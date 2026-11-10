import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
import json

from backend.main import app
from backend.database import Base, get_db
from backend import auth
from backend.models import User, AuditLog

@pytest.fixture
def db_session():
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
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

def test_protected_routes_reject_missing_or_invalid_jwt(client):
    no_tok = client.get('/findings')
    assert no_tok.status_code == 401

    bad_tok = client.get('/findings', headers={'Authorization': 'Bearer invalid.jwt.token'})
    assert bad_tok.status_code == 401
