import io

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend import auth, main
from backend.database import Base, get_db
from backend.models import Asset, AuditLog, Finding, User


@pytest.fixture
def role_api(tmp_path):
    database_path = tmp_path / "role-api.db"
    engine = create_engine(
        f"sqlite:///{database_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(bind=engine)
    session_factory = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = session_factory()

    users = {
        role: User(
            username=role,
            hashed_password="unused-by-token-auth",
            role=role,
        )
        for role in ("admin", "analyst", "viewer")
    }
    asset = Asset(name="RBAC-BASE", exposure="Internet", criticality=4)
    finding = Finding(
        asset=asset,
        cve_id="CVE-2025-1000",
        cvss_score=7.5,
        status="Open",
        date_found="2025-01-01",
    )
    db.add_all([*users.values(), finding])
    db.commit()
    user_ids = {role: user.id for role, user in users.items()}
    asset_id = asset.id
    finding_id = finding.id

    def override_get_db():
        yield db

    app = main.app
    app.dependency_overrides[get_db] = override_get_db

    def headers_for(role):
        token = auth.create_access_token({"sub": role})
        return {"Authorization": f"Bearer {token}"}

    try:
        with TestClient(app) as client:
            yield {
                "client": client,
                "db": db,
                "headers_for": headers_for,
                "user_ids": user_ids,
                "asset_id": asset_id,
                "finding_id": finding_id,
            }
    finally:
        app.dependency_overrides.pop(get_db, None)
        db.close()
        engine.dispose()


def _csv_file(cve_id):
    content = f"asset_name,cve_id,date_found\nRBAC-BASE,{cve_id},2025-01-02\n".encode()
    return {"file": ("rbac.csv", io.BytesIO(content), "text/csv")}


def _assert_audited_mutation(role_api, role, method, path, **kwargs):
    db = role_api["db"]
    before = db.query(AuditLog).count()
    response = getattr(role_api["client"], method)(
        path,
        headers=role_api["headers_for"](role),
        **kwargs,
    )
    assert response.status_code in (200, 201), response.text
    assert db.query(AuditLog).count() == before + 1
    audit = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    assert audit.user_id == role_api["user_ids"][role]
    return response


def test_viewer_is_forbidden_from_all_mutations_and_admin_views(role_api):
    client = role_api["client"]
    headers = role_api["headers_for"]("viewer")
    asset_id = role_api["asset_id"]
    finding_id = role_api["finding_id"]
    analyst_id = role_api["user_ids"]["analyst"]

    requests = [
        lambda: client.post(
            "/scan",
            json={
                "asset_id": asset_id,
                "cve_id": "CVE-2025-2000",
                "cvss_score": 8.0,
                "epss_percentile": 0.8,
            },
            headers=headers,
        ),
        lambda: client.post(
            "/assets",
            json={"name": "VIEWER-ASSET", "exposure": "Internal", "criticality": 2},
            headers=headers,
        ),
        lambda: client.put(
            f"/findings/{finding_id}/status",
            json={"status": "Resolved"},
            headers=headers,
        ),
        lambda: client.post(
            "/imports/commit",
            files=_csv_file("CVE-2021-44228"),
            headers=headers,
        ),
        lambda: client.post(
            "/users",
            json={"username": "viewer-created", "password": "password123", "role": "analyst"},
            headers=headers,
        ),
        lambda: client.patch(
            f"/users/{analyst_id}",
            json={"role": "viewer"},
            headers=headers,
        ),
        lambda: client.put(
            f"/users/{analyst_id}/role",
            json={"role": "viewer"},
            headers=headers,
        ),
        lambda: client.delete(f"/users/{analyst_id}", headers=headers),
    ]
    for request in requests:
        assert request().status_code == 403

    assert client.get("/users", headers=headers).status_code == 403
    assert client.get("/audit", headers=headers).status_code == 403
    assert role_api["db"].query(AuditLog).count() == 0


def test_analyst_can_mutate_operational_resources_but_not_admin_views(role_api):
    client = role_api["client"]
    headers = role_api["headers_for"]("analyst")
    asset_id = role_api["asset_id"]
    finding_id = role_api["finding_id"]

    _assert_audited_mutation(
        role_api,
        "analyst",
        "post",
        "/assets",
        json={"name": "ANALYST-ASSET", "exposure": "Internal", "criticality": 3},
    )
    _assert_audited_mutation(
        role_api,
        "analyst",
        "post",
        "/scan",
        json={
            "asset_id": asset_id,
            "cve_id": "CVE-2025-2001",
            "cvss_score": 8.0,
            "epss_percentile": 0.8,
        },
    )
    _assert_audited_mutation(
        role_api,
        "analyst",
        "put",
        f"/findings/{finding_id}/status",
        json={"status": "In Progress"},
    )
    imported = _assert_audited_mutation(
        role_api,
        "analyst",
        "post",
        "/imports/commit",
        files=_csv_file("CVE-2021-44228"),
    )
    assert imported.json()["imported"] == 1

    assert client.get("/users", headers=headers).status_code == 403
    assert client.get("/audit", headers=headers).status_code == 403


def test_admin_can_mutate_all_resources_and_each_mutation_is_audited(role_api):
    client = role_api["client"]
    headers = role_api["headers_for"]("admin")
    asset_id = role_api["asset_id"]
    finding_id = role_api["finding_id"]

    assert client.get("/users", headers=headers).status_code == 200
    assert client.get("/audit", headers=headers).status_code == 200

    _assert_audited_mutation(
        role_api,
        "admin",
        "post",
        "/assets",
        json={"name": "ADMIN-ASSET", "exposure": "Internal", "criticality": 3},
    )
    _assert_audited_mutation(
        role_api,
        "admin",
        "post",
        "/scan",
        json={
            "asset_id": asset_id,
            "cve_id": "CVE-2025-2002",
            "cvss_score": 8.0,
            "epss_percentile": 0.8,
        },
    )
    _assert_audited_mutation(
        role_api,
        "admin",
        "put",
        f"/findings/{finding_id}/status",
        json={"status": "Resolved"},
    )
    imported = _assert_audited_mutation(
        role_api,
        "admin",
        "post",
        "/imports/commit",
        files=_csv_file("CVE-2017-0144"),
    )
    assert imported.json()["imported"] == 1

    created = _assert_audited_mutation(
        role_api,
        "admin",
        "post",
        "/users",
        json={"username": "admin-created", "password": "password123", "role": "analyst"},
    )
    user_id = created.json()["id"]
    _assert_audited_mutation(
        role_api,
        "admin",
        "patch",
        f"/users/{user_id}",
        json={"role": "viewer"},
    )
    _assert_audited_mutation(
        role_api,
        "admin",
        "put",
        f"/users/{user_id}/role",
        json={"role": "analyst"},
    )
    _assert_audited_mutation(
        role_api,
        "admin",
        "delete",
        f"/users/{user_id}",
    )


def test_invalid_cves_return_422_on_intel_and_scan(role_api):
    headers = role_api["headers_for"]("admin")
    client = role_api["client"]

    intel = client.get("/intel/not-a-cve", headers=headers)
    assert intel.status_code == 422

    scan = client.post(
        "/scan",
        json={
            "asset_id": role_api["asset_id"],
            "cve_id": "not-a-cve",
            "cvss_score": 8.0,
            "epss_percentile": 0.8,
        },
        headers=headers,
    )
    assert scan.status_code == 422


def test_unavailable_intelligence_returns_explicit_error_without_zero_score(
    role_api, monkeypatch
):
    async def unavailable_intel(cve_id):
        return {
            "cve_id": cve_id,
            "epss": None,
            "cvss": None,
            "available": False,
            "errors": ["EPSS lookup failed.", "NVD lookup failed."],
        }

    monkeypatch.setattr(main, "fetch_cve_data", unavailable_intel)
    client = role_api["client"]
    headers = role_api["headers_for"]("analyst")
    cve_id = "CVE-2025-9876"

    intel = client.get(f"/intel/{cve_id}", headers=headers)
    assert intel.status_code == 200
    assert intel.json()["epss"] is None
    assert intel.json()["cvss"] is None
    assert intel.json()["available"] is False
    assert intel.json()["errors"] == ["EPSS lookup failed.", "NVD lookup failed."]
    assert "score" not in intel.json()

    scan = client.post(
        "/scan",
        json={"asset_id": role_api["asset_id"], "cve_id": cve_id},
        headers=headers,
    )
    assert scan.status_code == 503
    assert scan.json()["detail"]["message"] == (
        "Threat intelligence is unavailable; scan was not scored."
    )
    assert scan.json()["detail"]["errors"] == [
        "EPSS lookup failed.",
        "NVD lookup failed.",
    ]
    assert "score" not in scan.json()["detail"]
    assert (
        role_api["db"].query(Finding).filter(Finding.cve_id == cve_id).first()
        is None
    )
    assert role_api["db"].query(AuditLog).count() == 0
