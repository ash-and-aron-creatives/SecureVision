import io
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from backend.main import app
from backend.database import Base, get_db
from backend import auth, main, users
from backend.models import Asset, AuditLog, Finding, User
from backend.tests.db_helpers import create_test_engine


@pytest.fixture
def db_session():
    engine = create_test_engine()
    Base.metadata.create_all(bind=engine)
    TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = TestingSessionLocal()
    users = [
        User(username="admin", hashed_password=auth.get_password_hash("password123"), role="admin"),
        User(username="analyst1", hashed_password=auth.get_password_hash("password123"), role="analyst"),
        User(username="viewer1", hashed_password=auth.get_password_hash("password123"), role="viewer"),
    ]
    asset = Asset(name="RBAC-SRV", exposure="Internet", criticality=4)
    db.add_all(users + [asset])
    db.commit()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client(db_session, monkeypatch):
    def _override_get_db():
        yield db_session

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
    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def _headers(client, username, password="password123"):
    r = client.post("/token", data={"username": username, "password": password})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def test_admin_create_duplicate_and_validation(client, db_session):
    h_admin = _headers(client, "admin")

    r = client.post("/users", json={"username": "sec_ops", "password": "password123", "role": "analyst"}, headers=h_admin)
    assert r.status_code == 201
    assert r.json()["username"] == "sec_ops"
    assert r.json()["role"] == "analyst"

    log = db_session.query(AuditLog).filter(AuditLog.action == "USER_CREATED").first()
    assert log is not None and "sec_ops" in log.details

    dup = client.post("/users", json={"username": "SEC_OPS", "password": "password123", "role": "viewer"}, headers=h_admin)
    assert dup.status_code in (400, 409)

    short_pw = client.post("/users", json={"username": "newguy", "password": "123", "role": "viewer"}, headers=h_admin)
    assert short_pw.status_code == 400


def test_username_validation_and_parameterized_injection_text(client, db_session):
    headers = _headers(client, "admin")
    invalid_values = ("a" * 121, "secops\nadmin")
    for username in invalid_values:
        response = client.post(
            "/users",
            json={"username": username, "password": "password123", "role": "analyst"},
            headers=headers,
        )
        assert response.status_code == 400

    injected_text = "' OR 1=1 --"
    response = client.post(
        "/users",
        json={"username": injected_text, "password": "password123", "role": "analyst"},
        headers=headers,
    )
    assert response.status_code == 201
    assert db_session.query(User).filter_by(username=injected_text).one().username == injected_text


def test_self_demotion_and_self_deletion_blocked(client, db_session):
    h_admin = _headers(client, "admin")
    admin_user = db_session.query(User).filter(User.username == "admin").first()
    db_session.add(User(
        username="second_admin",
        hashed_password=auth.get_password_hash("password123"),
        role="admin",
    ))
    db_session.commit()

    demote = client.put(f"/users/{admin_user.id}/role", json={"role": "viewer"}, headers=h_admin)
    assert demote.status_code == 400
    assert demote.json()["detail"] == "Administrators cannot demote themselves."

    delete_self = client.delete(f"/users/{admin_user.id}", headers=h_admin)
    assert delete_self.status_code == 400
    assert delete_self.json()["detail"] == "Administrators cannot delete themselves."


def test_last_administrator_cannot_be_demoted_or_deleted(client, db_session):
    h_admin = _headers(client, "admin")
    admin = db_session.query(User).filter_by(username="admin").one()

    demote = client.put(f"/users/{admin.id}/role", json={"role": "analyst"}, headers=h_admin)
    assert demote.status_code == 400
    assert demote.json()["detail"] == "At least one administrator must remain."

    delete = client.delete(f"/users/{admin.id}", headers=h_admin)
    assert delete.status_code == 400
    assert delete.json()["detail"] == "At least one administrator must remain."


def test_update_role_and_delete_other_user_logs_audit(client, db_session):
    h_admin = _headers(client, "admin")
    viewer = db_session.query(User).filter(User.username == "viewer1").first()

    upd = client.patch(f"/users/{viewer.id}", json={"role": "analyst"}, headers=h_admin)
    assert upd.status_code == 200
    assert upd.json()["role"] == "analyst"
    assert db_session.query(AuditLog).filter(AuditLog.action == "USER_UPDATED").first() is not None

    reset = client.patch(
        f"/users/{viewer.id}",
        json={"password": "new-password-123"},
        headers=h_admin,
    )
    assert reset.status_code == 200
    update_logs = db_session.query(AuditLog).filter_by(action="USER_UPDATED").order_by(AuditLog.id).all()
    assert "password_reset" in update_logs[-1].details
    assert "new-password-123" not in update_logs[-1].details

    rem = client.delete(f"/users/{viewer.id}", headers=h_admin)
    assert rem.status_code == 200
    assert db_session.query(AuditLog).filter(AuditLog.action == "USER_DELETED").first() is not None


def test_rbac_matrix_across_endpoints(client, db_session):
    h_admin = _headers(client, "admin")
    h_analyst = _headers(client, "analyst1")
    h_viewer = _headers(client, "viewer1")
    asset = db_session.query(Asset).first()

    assert client.get("/users", headers=h_admin).status_code == 200
    assert client.get("/users", headers=h_analyst).status_code == 403
    assert client.get("/users", headers=h_viewer).status_code == 403

    assert client.get("/audit", headers=h_admin).status_code == 200
    assert client.get("/audit", headers=h_analyst).status_code == 403
    assert client.get("/audit", headers=h_viewer).status_code == 403

    scan_payload = {"asset_id": asset.id, "cve_id": "CVE-2024-1111", "cvss_score": 8.0, "in_kev": False, "epss_percentile": 0.4}
    assert client.post("/scan", json=scan_payload, headers=h_analyst).status_code == 200
    assert client.post("/scan", json=scan_payload, headers=h_viewer).status_code == 403

    csv_bytes = b"asset_name,cve_id,date_found\nRBAC-SRV,CVE-2024-2222,2026-10-01\n"
    assert client.post("/imports/preview", files={"file": ("t.csv", io.BytesIO(csv_bytes), "text/csv")}, headers=h_analyst).status_code == 200
    assert client.post("/imports/preview", files={"file": ("t.csv", io.BytesIO(csv_bytes), "text/csv")}, headers=h_viewer).status_code == 403

    assert client.get("/findings", headers=h_viewer).status_code == 200


def test_finding_detail_only_includes_audit_trail_for_admin(client, db_session):
    admin = db_session.query(User).filter(User.username == "admin").first()
    asset = db_session.query(Asset).first()
    finding = Finding(
        asset_id=asset.id,
        cve_id="CVE-2024-1234",
        cvss_score=7.5,
        status="Open",
    )
    db_session.add(finding)
    db_session.flush()
    db_session.add(
        AuditLog(
            user_id=admin.id,
            action="STATUS_UPDATE",
            details=f"finding_id={finding.id} CVE-2024-1234 status changed",
        )
    )
    db_session.commit()

    h_admin = _headers(client, "admin")
    h_analyst = _headers(client, "analyst1")
    h_viewer = _headers(client, "viewer1")

    admin_detail = client.get(f"/findings/{finding.id}", headers=h_admin)
    analyst_detail = client.get(f"/findings/{finding.id}", headers=h_analyst)
    viewer_detail = client.get(f"/findings/{finding.id}", headers=h_viewer)

    assert admin_detail.status_code == 200
    assert admin_detail.json()["audit_trail"]
    assert analyst_detail.status_code == 200
    assert analyst_detail.json()["audit_trail"] == []
    assert viewer_detail.status_code == 200
    assert viewer_detail.json()["audit_trail"] == []


def test_finding_detail_audit_trail_matches_exact_finding_ids(client, db_session):
    admin = db_session.query(User).filter(User.username == "admin").first()
    asset = db_session.query(Asset).first()
    findings = [
        Finding(id=finding_id, asset_id=asset.id, cve_id=f"CVE-2024-{finding_id:04d}", status="Open")
        for finding_id in (1, 10, 11, 100)
    ]
    db_session.add_all(findings)
    db_session.flush()
    db_session.add_all(
        [
            AuditLog(user_id=admin.id, action="STATUS_UPDATE", details="finding_id=1 status changed"),
            AuditLog(user_id=admin.id, action="SCAN_RUN", details="finding_id=10 Finding created"),
            AuditLog(user_id=admin.id, action="STATUS_UPDATE", details="finding_id=100 status changed"),
            AuditLog(user_id=admin.id, action="IMPORT", details="imported=2 skipped=0 finding_ids=10,11"),
        ]
    )
    db_session.commit()

    headers = _headers(client, "admin")
    trails = {
        finding_id: client.get(f"/findings/{finding_id}", headers=headers).json()["audit_trail"]
        for finding_id in (1, 10, 11, 100)
    }

    assert [entry["details"] for entry in trails[1]] == ["finding_id=1 status changed"]
    assert [entry["details"] for entry in trails[10]] == [
        "imported=2 skipped=0 finding_ids=10,11",
        "finding_id=10 Finding created",
    ]
    assert [entry["details"] for entry in trails[11]] == ["imported=2 skipped=0 finding_ids=10,11"]
    assert [entry["details"] for entry in trails[100]] == ["finding_id=100 status changed"]


def test_deactivate_user_with_audit_history_invalidates_login_and_tokens(client, db_session):
    target = db_session.query(User).filter_by(username="analyst1").one()
    target_headers = _headers(client, "analyst1")

    response = client.post(
        f"/users/{target.id}/deactivate",
        headers=_headers(client, "admin"),
    )

    assert response.status_code == 200
    assert response.json()["is_active"] is False
    assert (
        db_session.query(AuditLog)
        .filter_by(action="USER_DEACTIVATED")
        .one()
        .user_id
        is not None
    )
    assert client.get("/me", headers=target_headers).status_code == 401
    login = client.post(
        "/token",
        data={"username": "analyst1", "password": "password123"},
    )
    assert login.status_code == 401
    assert login.json()["detail"] == "Incorrect credentials"


def test_delete_user_with_audit_history_returns_409(client, db_session):
    target = db_session.query(User).filter_by(username="analyst1").one()
    _headers(client, "analyst1")

    response = client.delete(
        f"/users/{target.id}",
        headers=_headers(client, "admin"),
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "User has audit history; deactivate instead."


def test_admin_cannot_deactivate_self_or_last_active_admin(client, db_session):
    admin = db_session.query(User).filter_by(username="admin").one()
    headers = _headers(client, "admin")

    self_deactivation = client.post(
        f"/users/{admin.id}/deactivate",
        headers=headers,
    )
    assert self_deactivation.status_code == 409
    assert self_deactivation.json()["detail"] == "Administrators cannot deactivate themselves."

    app.dependency_overrides[users.require_admin] = lambda: User(
        id=-1,
        username="test-admin-override",
        hashed_password="",
        role="admin",
        is_active=True,
    )
    try:
        last_admin_deactivation = client.post(f"/users/{admin.id}/deactivate")
    finally:
        app.dependency_overrides.pop(users.require_admin, None)

    assert last_admin_deactivation.status_code == 409
    assert last_admin_deactivation.json()["detail"] == (
        "At least one active administrator must remain."
    )


def test_reactivate_restores_login(client, db_session):
    target = db_session.query(User).filter_by(username="analyst1").one()
    admin_headers = _headers(client, "admin")
    deactivated = client.post(
        f"/users/{target.id}/deactivate",
        headers=admin_headers,
    )
    assert deactivated.status_code == 200

    failed_login = client.post(
        "/token",
        data={"username": "analyst1", "password": "password123"},
    )
    assert failed_login.status_code == 401
    reactivated = client.post(
        f"/users/{target.id}/reactivate",
        headers=admin_headers,
    )

    assert reactivated.status_code == 200
    assert reactivated.json()["is_active"] is True
    assert (
        db_session.query(AuditLog)
        .filter_by(action="USER_REACTIVATED")
        .first()
        is not None
    )
    successful_login = client.post(
        "/token",
        data={"username": "analyst1", "password": "password123"},
    )
    assert successful_login.status_code == 200