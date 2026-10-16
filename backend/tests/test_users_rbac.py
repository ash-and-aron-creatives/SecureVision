import io
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.database import Base, get_db
from backend import auth
from backend.models import Asset, AuditLog, User


@pytest.fixture
def db_session():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
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
def client(db_session):
    def _override_get_db():
        yield db_session

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


def test_self_demotion_and_self_deletion_blocked(client, db_session):
    h_admin = _headers(client, "admin")
    admin_user = db_session.query(User).filter(User.username == "admin").first()

    demote = client.put(f"/users/{admin_user.id}/role", json={"role": "viewer"}, headers=h_admin)
    assert demote.status_code == 400

    delete_self = client.delete(f"/users/{admin_user.id}", headers=h_admin)
    assert delete_self.status_code == 400


def test_update_role_and_delete_other_user_logs_audit(client, db_session):
    h_admin = _headers(client, "admin")
    viewer = db_session.query(User).filter(User.username == "viewer1").first()

    upd = client.patch(f"/users/{viewer.id}", json={"role": "analyst"}, headers=h_admin)
    assert upd.status_code == 200
    assert upd.json()["role"] == "analyst"
    assert db_session.query(AuditLog).filter(AuditLog.action == "USER_UPDATED").first() is not None

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