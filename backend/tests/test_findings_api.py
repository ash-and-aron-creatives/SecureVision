import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from backend import auth
from backend.database import Base, get_db
from backend.main import app
from backend.models import Asset, Finding, FindingScore, User
from backend.rules_config import RECOMMENDED_ACTION_TEMPLATES
from backend.tests.db_helpers import create_test_engine


@pytest.fixture
def db_session():
    engine = create_test_engine()
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
        final_priority="Critical",
        priority_source="rules",
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
    yield db
    db.close()


@pytest.fixture
def client(db_session):
    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


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
    assert data["items"][0]["recommended_action"] == RECOMMENDED_ACTION_TEMPLATES["Critical"]


def test_findings_over_twenty_are_reachable_across_pages(client, db_session):
    asset = db_session.query(Asset).first()
    for index in range(25):
        finding = Finding(
            asset_id=asset.id,
            cve_id=f"CVE-2026-{index + 1000}",
            cvss_score=5.0,
            final_priority="Medium",
            priority_source="rules",
            status="Open",
            date_found="2026-10-01",
        )
        db_session.add(finding)
        db_session.flush()
        db_session.add(FindingScore(
            finding_id=finding.id,
            provider_id=1,
            likelihood=0.2,
            priority_tier="Medium",
            provenance={},
            explanation="Pagination test finding",
        ))
    db_session.commit()

    headers = get_auth_headers(client)
    pages = [
        client.get(f"/findings?page={page}&page_size=20", headers=headers).json()
        for page in (1, 2)
    ]
    finding_ids = {item["id"] for page in pages for item in page["items"]}
    assert pages[0]["total"] == 26
    assert pages[0]["pages"] == 2
    assert len(finding_ids) == 26


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


@pytest.mark.parametrize("tier", ("Critical", "High", "Medium", "Low"))
def test_finding_detail_includes_rule_only_action_for_each_final_tier(
    client, db_session, tier
):
    asset = db_session.query(Asset).first()
    finding = Finding(
        asset_id=asset.id,
        cve_id=f"CVE-2026-{len(tier):04d}",
        cvss_score=5.0,
        final_priority=tier,
        priority_source="rules",
        status="Open",
        date_found="2026-10-01",
    )
    db_session.add(finding)
    db_session.commit()

    response = client.get(
        f"/findings/{finding.id}",
        headers=get_auth_headers(client),
    )
    assert response.status_code == 200
    assert response.json()["recommended_action"] == RECOMMENDED_ACTION_TEMPLATES[tier]
    assert response.json()["ml_recommended_action"] is None


def test_status_update_records_audit(client):
    headers = get_auth_headers(client)
    list_res = client.get("/findings?page=1&page_size=1", headers=headers)
    finding = list_res.json()["items"][0]

    upd = client.put(f"/findings/{finding['id']}/status", json={"status": "In Progress"}, headers=headers)
    assert upd.status_code == 200
    assert upd.json()["status"] == "In Progress"

    client.put(f"/findings/{finding['id']}/status", json={"status": "Open"}, headers=headers)
