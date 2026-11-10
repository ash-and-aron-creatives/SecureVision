import io

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend import auth, main
from backend.database import Base, get_db
from backend.models import Asset, AuditLog, Finding, User


def _has_auth_dependency(dependency):
    return dependency.call is auth.get_current_user or any(
        _has_auth_dependency(child) for child in dependency.dependencies
    )


def _protected_route_cases():
    cases = []
    for route in main.app.routes:
        if not isinstance(route, APIRoute) or not _has_auth_dependency(route.dependant):
            continue
        path = route.path
        for parameter, value in (
            ("{asset_id}", "1"),
            ("{finding_id}", "1"),
            ("{user_id}", "1"),
            ("{cve_id}", "CVE-2025-1234"),
        ):
            path = path.replace(parameter, value)
        if path == "/cves":
            path += "?search=CVE-2025-1234"
        for method in route.methods - {"HEAD", "OPTIONS"}:
            cases.append((method, path))
    return cases


PROTECTED_ROUTES = _protected_route_cases()


@pytest.fixture
def role_api(tmp_path, monkeypatch):
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
    async def nvd_and_epss(cve_id):
        return {
            "cve_id": cve_id,
            "epss": 0.4,
            "cvss": 8.0,
            "available": True,
            "errors": [],
            "description": "Mock vulnerability description.",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe": "CWE-79",
            "published_date": "2025-01-01T00:00Z",
        }
    monkeypatch.setattr(main, "fetch_cve_data", nvd_and_epss)
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


def _request_protected_route(client, method, path):
    if path.startswith("/imports/"):
        return client.request(
            method,
            path,
            files=_csv_file("CVE-2025-1234"),
        )
    body = None
    if path == "/assets" and method == "POST":
        body = {"name": "ROUTE-ASSET", "exposure": "Internal", "criticality": 3}
    elif path.startswith("/assets/") and method == "PUT":
        body = {"name": "ROUTE-ASSET", "exposure": "Internal", "criticality": 3}
    elif path == "/scan":
        body = {"asset_id": 1, "cve_id": "CVE-2025-1234", "cvss_score": 8, "epss_percentile": 0.3}
    elif path.endswith("/status"):
        body = {"status": "Resolved"}
    elif path == "/users" and method == "POST":
        body = {"username": "route-user", "password": "password123", "role": "analyst"}
    elif path.endswith("/role") or path.startswith("/users/") and method == "PATCH":
        body = {"role": "viewer"}
    elif path.startswith("/users/") and method == "PUT":
        body = {"role": "viewer"}
    return client.request(method, path, json=body)


@pytest.mark.parametrize(("method", "path"), PROTECTED_ROUTES)
def test_all_authenticated_api_routes_reject_missing_tokens(role_api, method, path):
    response = _request_protected_route(role_api["client"], method, path)
    assert response.status_code == 401, f"{method} {path}: {response.status_code} {response.text}"


@pytest.mark.parametrize(
    ("method", "path", "role", "body"),
    [
        ("POST", "/assets", "viewer", {"name": "ROLE-ASSET", "exposure": "Internal", "criticality": 3}),
        ("PUT", "/assets/1", "viewer", {"name": "ROLE-ASSET", "exposure": "Internal", "criticality": 3}),
        ("DELETE", "/assets/1", "viewer", None),
        ("POST", "/scan", "viewer", {"asset_id": 1, "cve_id": "CVE-2025-1234"}),
        ("PUT", "/findings/1/status", "viewer", {"status": "Resolved"}),
        ("POST", "/imports/preview", "viewer", None),
        ("POST", "/imports/commit", "viewer", None),
        ("GET", "/audit", "analyst", None),
        ("GET", "/users", "analyst", None),
        ("POST", "/users", "analyst", {"username": "role-user", "password": "password123"}),
        ("PATCH", "/users/2", "analyst", {"role": "viewer"}),
        ("PUT", "/users/2/role", "analyst", {"role": "viewer"}),
        ("DELETE", "/users/2", "analyst", None),
    ],
)
def test_role_restricted_routes_reject_the_wrong_role(role_api, method, path, role, body):
    client = role_api["client"]
    headers = role_api["headers_for"](role)
    if path.startswith("/imports/"):
        response = client.request(method, path, files=_csv_file("CVE-2025-1234"), headers=headers)
    else:
        response = client.request(method, path, json=body, headers=headers)
    assert response.status_code == 403, f"{method} {path}: {response.status_code} {response.text}"


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

    created = _assert_audited_mutation(
        role_api,
        "analyst",
        "post",
        "/assets",
        json={"name": "ANALYST-ASSET", "exposure": "Internal", "criticality": 3},
    )
    created_asset_id = created.json()["id"]
    _assert_audited_mutation(
        role_api,
        "analyst",
        "put",
        f"/assets/{created_asset_id}",
        json={"name": "ANALYST-ASSET-EDITED", "exposure": "Internal", "criticality": 3},
    )
    _assert_audited_mutation(role_api, "analyst", "delete", f"/assets/{created_asset_id}")
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
