import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend import auth
from backend.database import Base, get_db
from backend.main import app
from backend.models import Asset, Finding, FindingScore, User


@pytest.fixture
def client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(autocommit=False, autoflush=False, bind=engine)()
    admin = User(
        username="admin",
        hashed_password=auth.get_password_hash("password123"),
        role="admin",
    )
    asset = Asset(name="TEST-SRV", exposure="Internet", criticality=5)
    db.add_all([admin, asset])
    db.flush()
    finding = Finding(
        asset_id=asset.id,
        cve_id="CVE-2021-44228",
        cvss_score=9.8,
        in_kev=True,
        status="Open",
        date_found="2026-10-01",
    )
    db.add(finding)
    db.flush()
    db.add(FindingScore(
        finding_id=finding.id,
        provider_id=1,
        likelihood=0.95,
        priority_tier="Critical",
        provenance={},
        explanation="Test scoring explanation",
    ))
    db.commit()

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    db.close()


def get_auth_headers(client):
    res = client.post("/token", data={"username": "admin", "password": "password123"})
    assert res.status_code == 200
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def test_findings_list_and_counts(client):
    headers = get_auth_headers(client)
    res = client.get("/findings?page=1&page_size=10", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "items" in data and "total" in data and "counts" in data
    assert len(data["items"]) <= 10
    assert set(data["counts"].keys()) == {"Critical", "High", "Medium", "Low"}


def test_findings_filters_and_search(client):
    headers = get_auth_headers(client)
    res = client.get("/findings?priority=Critical", headers=headers)
    assert res.status_code == 200
    for item in res.json()["items"]:
        assert item["priority_tier"] == "Critical"

    res_q = client.get("/findings?q=CVE-2021-44228", headers=headers)
    assert res_q.status_code == 200
    for item in res_q.json()["items"]:
        assert "CVE-2021-44228" in item["cve_id"]


def test_finding_detail_and_404(client):
    headers = get_auth_headers(client)
    list_res = client.get("/findings?page=1&page_size=1", headers=headers)
    first_id = list_res.json()["items"][0]["id"]

    detail_res = client.get(f"/findings/{first_id}", headers=headers)
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == first_id
    assert "asset" in detail and "explanation" in detail and "score_history" in detail

    missing_res = client.get("/findings/999999", headers=headers)
    assert missing_res.status_code == 404


def test_status_update_records_audit(client):
    headers = get_auth_headers(client)
    list_res = client.get("/findings?page=1&page_size=1", headers=headers)
    finding = list_res.json()["items"][0]

    upd = client.put(f"/findings/{finding['id']}/status", json={"status": "In Progress"}, headers=headers)
    assert upd.status_code == 200
    assert upd.json()["status"] == "In Progress"

    client.put(f"/findings/{finding['id']}/status", json={"status": "Open"}, headers=headers)
