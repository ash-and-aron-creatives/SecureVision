import os
import pytest
import subprocess
import sys
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker
import json
from pathlib import Path

from backend.main import app
from backend.database import Base, get_db
from backend import auth
from backend.models import User, AuditLog
from backend.tests.db_helpers import create_test_engine

@pytest.fixture
def db_session():
    engine = create_test_engine()
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    db.add(User(username='admin', hashed_password=auth.get_password_hash('password123'), role='admin'))
    db.commit()
    yield db
    db.close()

@pytest.fixture
def client(db_session):
    def _override():
        yield db_session
    app.dependency_overrides[get_db] = _override
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

def test_password_hashing():
    hashed = auth.get_password_hash('secret123')
    assert hashed != 'secret123'
    assert auth.verify_password('secret123', hashed) is True
    assert auth.verify_password('wrongpass', hashed) is False

def test_token_creation_requires_configured_secret(monkeypatch):
    monkeypatch.delenv("SECRET_KEY", raising=False)
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        auth.create_access_token({"sub": "admin"})

def test_sqlite_database_url_fails_without_traceback(tmp_path):
    env = os.environ.copy()
    env["DATABASE_URL"] = f"sqlite:///{(tmp_path / 'not-created.db').as_posix()}"
    env.pop("SECUREVISION_TESTING", None)
    env.pop("SECUREVISION_POSTGRES_TESTS", None)
    output_path = tmp_path / "uvicorn-startup.log"
    with output_path.open("w", encoding="utf-8") as output:
        result = subprocess.run(
            [sys.executable, "-m", "uvicorn", "backend.main:app", "--port", "0"],
            cwd=Path(__file__).resolve().parents[2],
            env=env,
            stdout=output,
            stderr=subprocess.STDOUT,
            check=False,
        )
    output = output_path.read_text(encoding="utf-8")

    assert result.returncode != 0
    assert "Traceback" not in output
    assert "SecureVision requires PostgreSQL" in output
    assert "run .\\setup_dev.ps1" in output
    assert not (tmp_path / "not-created.db").exists()

def test_cors_allows_only_configured_origins(client):
    allowed = client.options(
        "/token",
        headers={
            "Origin": "http://testserver",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert allowed.headers["access-control-allow-origin"] == "http://testserver"

    rejected = client.options(
        "/token",
        headers={
            "Origin": "https://unconfigured.example",
            "Access-Control-Request-Method": "POST",
        },
    )
    assert "access-control-allow-origin" not in rejected.headers

def test_login_success_and_failure(client, db_session):
    ok = client.post('/token', data={'username': 'admin', 'password': 'password123'})
    assert ok.status_code == 200
    assert 'access_token' in ok.json()
    success = db_session.query(AuditLog).filter_by(action="LOGIN_SUCCESS").one()
    assert success.timestamp is not None
    assert json.loads(success.details) == {"username": "admin"}

    bad = client.post('/token', data={'username': 'admin', 'password': 'wrongpassword'})
    assert bad.status_code == 401
    unknown = client.post('/token', data={'username': 'not-a-user', 'password': 'wrongpassword'})
    assert unknown.status_code == bad.status_code
    assert unknown.json() == bad.json()

    failures = db_session.query(AuditLog).filter_by(action="LOGIN_FAILED").order_by(AuditLog.id).all()
    assert [json.loads(row.details) for row in failures] == [
        {"username_attempted": "admin"},
        {"username_attempted": "not-a-user"},
    ]
    assert all(row.user_id is None and row.timestamp is not None for row in failures)
    assert all("wrongpassword" not in row.details for row in failures)


def test_login_rate_limit_is_per_username_and_ip_and_audited(client, db_session):
    for attempt in range(5):
        response = client.post(
            "/token",
            data={"username": "admin", "password": f"bad-password-{attempt}"},
        )
        assert response.status_code == 401

    limited = client.post(
        "/token",
        data={"username": "admin", "password": "password123"},
    )
    assert limited.status_code == 429
    assert db_session.query(AuditLog).filter_by(action="LOGIN_FAILED").count() == 6

    other_username = client.post(
        "/token",
        data={"username": "another-user", "password": "wrong-password"},
    )
    assert other_username.status_code == 401

    auth.reset_login_failures()
    success = client.post(
        "/token",
        data={"username": "admin", "password": "password123"},
    )
    assert success.status_code == 200


def test_me_returns_the_authenticated_user(client):
    token = client.post(
        "/token",
        data={"username": "admin", "password": "password123"},
    ).json()["access_token"]
    response = client.get("/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    assert response.json() == {"id": 1, "username": "admin", "role": "admin"}


def test_protected_routes_reject_missing_or_invalid_jwt(client):
    no_tok = client.get('/findings')
    assert no_tok.status_code == 401

    bad_tok = client.get('/findings', headers={'Authorization': 'Bearer invalid.jwt.token'})
    assert bad_tok.status_code == 401
