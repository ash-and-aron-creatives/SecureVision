import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.database import Base, get_db
from backend import auth
from backend.models import User, AuditLog

@pytest.fixture
def client():
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
    db.add(User(username='admin', hashed_password=auth.get_password_hash('password123'), role='admin'))
    db.commit()
    def _override():
        yield db
    app.dependency_overrides[get_db] = _override
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    db.close()

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

def test_login_success_and_failure(client):
    ok = client.post('/token', data={'username': 'admin', 'password': 'password123'})
    assert ok.status_code == 200
    assert 'access_token' in ok.json()

    bad = client.post('/token', data={'username': 'admin', 'password': 'wrongpassword'})
    assert bad.status_code == 401

def test_protected_routes_reject_missing_or_invalid_jwt(client):
    no_tok = client.get('/findings')
    assert no_tok.status_code == 401

    bad_tok = client.get('/findings', headers={'Authorization': 'Bearer invalid.jwt.token'})
    assert bad_tok.status_code == 401
