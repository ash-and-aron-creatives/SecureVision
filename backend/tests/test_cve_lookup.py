import os

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
from sqlalchemy.engine import make_url

from backend import auth, main
from backend.database import Base, get_db
from backend.main import app
from backend.models import CVECatalog, User
from backend.tests.db_helpers import create_test_engine
from scripts.load_cve_catalog import CATALOG_COLUMNS, load_csv


@pytest.fixture
def cve_client(monkeypatch):
    engine = create_test_engine()
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(autocommit=False, autoflush=False, bind=engine)()
    db.add(User(username="cve-admin", hashed_password=auth.get_password_hash("password123"), role="admin"))
    db.commit()

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        token = client.post(
            "/token",
            data={"username": "cve-admin", "password": "password123"},
        ).json()["access_token"]
        yield client, db, {"Authorization": f"Bearer {token}"}, monkeypatch
    app.dependency_overrides.clear()
    db.close()
    engine.dispose()


def test_catalog_hit_and_search(cve_client):
    client, db, headers, _ = cve_client
    db.add(
        CVECatalog(
            cve_id="CVE-1999-0095",
            published_date="1999-04-26",
            description="Test catalog description.",
            cvss_score=10.0,
            cvss_vector="CVSS:2.0/AV:N",
            cwe="CWE-20",
            epss=0.01,
            percentile=0.4,
            in_kev=False,
        )
    )
    db.commit()

    lookup = client.get("/cves/CVE-1999-0095", headers=headers)
    assert lookup.status_code == 200
    assert lookup.json()["cve_id"] == "CVE-1999-0095"
    assert lookup.json()["source"] == "catalog"
    assert lookup.json()["description"] == "Test catalog description."

    search = client.get("/cves?search=Test%20catalog", headers=headers)
    assert search.status_code == 200
    assert search.headers["x-cve-lookup-source"] == "catalog"
    assert search.json()[0]["source"] == "catalog"
    assert client.get("/cves/not-a-cve", headers=headers).status_code == 422
    assert client.get("/cves?search=%20%20", headers=headers).status_code == 422
    assert client.get("/cves/CVE-1999-0095").status_code == 401


def test_catalog_miss_falls_back_to_live_provider_and_caches(cve_client):
    client, db, headers, monkeypatch = cve_client
    calls = []

    async def fetch(cve_id):
        calls.append(cve_id)
        return {
            "cve_id": cve_id,
            "available": True,
            "description": "Cached test description",
            "published_date": "2025-01-01",
            "cvss": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N",
            "cwe": "CWE-79",
            "epss": 0.3,
            "percentile": 0.7,
            "in_kev": False,
        }

    monkeypatch.setattr(main, "fetch_cve_data", fetch)
    first = client.get("/cves/CVE-2025-7878", headers=headers)
    second = client.get("/cves/CVE-2025-7878", headers=headers)
    assert first.status_code == second.status_code == 200
    assert first.json()["source"] == "live_provider"
    assert second.json()["source"] == "postgres_cache"
    assert first.json()["cvss_score"] == 7.5
    assert second.json()["description"] == "Cached test description"
    assert calls == ["CVE-2025-7878"]
    assert db.query(main.models.CVECache).count() == 1


def test_empty_catalog_and_unavailable_provider_are_explicit(cve_client, monkeypatch):
    client, db, headers, _ = cve_client

    async def unavailable(cve_id):
        return {"cve_id": cve_id, "available": False, "errors": ["provider unavailable"]}

    monkeypatch.setattr(main, "fetch_cve_data", unavailable)
    response = client.get("/cves/CVE-2025-7879", headers=headers)
    assert response.status_code == 503
    assert "CVE catalog" in response.json()["detail"]["message"]
    assert "live provider" in response.json()["detail"]["message"]
    assert db.query(CVECatalog).count() == 0
    assert db.query(main.models.CVECache).count() == 0


def test_loader_upserts_twenty_synthetic_rows_idempotently(cve_client, tmp_path):
    _, db, _, _ = cve_client
    csv_path = tmp_path / "synthetic-cves.csv"
    header = ",".join(CATALOG_COLUMNS)
    rows = [
        f"CVE-2025-{index:04d},2025-01-01,Description {index},7.5,CVSS:3.1/AV:N,"
        f"CWE-79,,0.2,0.7,{int(index % 2 == 0)}"
        for index in range(20)
    ]
    csv_path.write_text(header + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
    schema = getattr(db.get_bind(), "_securevision_test_schema")
    loader_url = make_url(os.environ["DATABASE_URL"]).set(
        query={"options": f"-csearch_path={schema}"}
    ).render_as_string(hide_password=False)

    assert load_csv(loader_url, csv_path, batch_size=7) == 20
    rows[0] = rows[0].replace("Description 0", "Updated description")
    csv_path.write_text(header + "\n" + "\n".join(rows) + "\n", encoding="utf-8")
    assert load_csv(loader_url, csv_path, batch_size=7) == 20
    assert db.query(CVECatalog).count() == 20
    assert db.query(CVECatalog).filter_by(cve_id="CVE-2025-0000").one().description == (
        "Updated description"
    )
