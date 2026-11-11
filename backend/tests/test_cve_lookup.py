import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from backend import auth, main
from backend.database import Base, get_db
from backend.main import app
from backend.models import User
from backend.tests.db_helpers import create_test_engine


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


def test_prepared_cve_dataset_lookup_and_search(cve_client):
    client, _, headers, _ = cve_client
    lookup = client.get("/cves/CVE-1999-0095", headers=headers)
    assert lookup.status_code == 200
    assert lookup.json()["cve_id"] == "CVE-1999-0095"
    assert lookup.json()["description"]
    assert lookup.json()["in_kev"] is False

    search = client.get("/cves?search=CVE-1999-0095", headers=headers)
    assert search.status_code == 200
    assert len(search.json()) == 1
    assert search.json()[0]["cve_id"] == "CVE-1999-0095"
    assert client.get("/cves/not-a-cve", headers=headers).status_code == 422
    assert client.get("/cves?search=%20%20", headers=headers).status_code == 422
    assert client.get("/cves/CVE-1999-0095").status_code == 401


def test_cve_lookup_uses_and_populates_cache_when_dataset_is_missing(cve_client):
    client, db, headers, monkeypatch = cve_client
    monkeypatch.setattr(main, "dataset_available", lambda: False)
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
    assert first.json()["cvss_score"] == 7.5
    assert second.json()["description"] == "Cached test description"
    assert calls == ["CVE-2025-7878"]
    assert db.query(main.models.CVECache).count() == 1

    search = client.get("/cves?search=Cached%20test%20description", headers=headers)
    assert search.status_code == 200
    assert search.json()[0]["cve_id"] == "CVE-2025-7878"


def test_cve_cache_does_not_hide_provider_failure(cve_client, monkeypatch):
    client, db, headers, _ = cve_client
    monkeypatch.setattr(main, "dataset_available", lambda: False)

    async def unavailable(cve_id):
        return {"cve_id": cve_id, "available": False, "errors": ["provider unavailable"]}

    monkeypatch.setattr(main, "fetch_cve_data", unavailable)
    response = client.get("/cves/CVE-2025-7879", headers=headers)
    assert response.status_code == 503
    assert db.query(main.models.CVECache).count() == 0
