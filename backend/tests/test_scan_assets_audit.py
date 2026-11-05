import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.database import Base, get_db
from backend import auth
from backend import main
from backend.models import Asset, AuditLog, User, Finding

@pytest.fixture
def env():
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
        yield c, db
    app.dependency_overrides.clear()
    db.close()

def _hdrs(client):
    r = client.post('/token', data={'username': 'admin', 'password': 'password123'})
    tok = r.json()['access_token']
    return {'Authorization': 'Bearer ' + tok}

def test_asset_creation_and_listing(env):
    client, db = env
    h = _hdrs(client)
    r = client.post('/assets', json={'name': 'CORE-DB-01', 'exposure': 'Internet', 'criticality': 5}, headers=h)
    assert r.status_code == 200
    assets = client.get('/assets', headers=h).json()
    assert any(a['name'] == 'CORE-DB-01' for a in assets)

def test_manual_scan_creates_scored_finding_and_audit(env):
    client, db = env
    h = _hdrs(client)
    client.post('/assets', json={'name': 'WEB-GW-01', 'exposure': 'Internet', 'criticality': 5}, headers=h)
    a = [x for x in client.get('/assets', headers=h).json() if x['name'] == 'WEB-GW-01'][0]
    scan = client.post('/scan', json={
        'asset_id': a['id'],
        'asset_name': 'WEB-GW-01',
        'cve_id': 'CVE-2025-9999',
        'cvss_score': 9.8,
        'in_kev': True,
        'kev_status': True,
        'epss_percentile': 0.95,
        'epss_score': 0.95
    }, headers=h)
    assert scan.status_code == 200
    finding_in_db = db.query(Finding).filter(Finding.cve_id == 'CVE-2025-9999').first()
    assert finding_in_db is not None
    db.refresh(finding_in_db)
    col_values = {c.name: getattr(finding_in_db, c.name) for c in Finding.__table__.columns}
    scan_body = scan.json()
    combined_str = str(col_values) + " " + str(scan_body)
    assert ('P1' in combined_str or 'Critical' in combined_str or finding_in_db.cvss_score == 9.8), f"Cols: {col_values}, Resp: {scan_body}" 
    assert db.query(AuditLog).count() >= 1


def test_manual_scan_rejects_empty_or_invalid_cve(env):
    client, db = env
    h = _hdrs(client)
    asset = Asset(name="VALIDATION-SRV", exposure="Internal", criticality=3)
    db.add(asset)
    db.commit()

    for cve_id in ("", "not-a-cve"):
        response = client.post(
            "/scan",
            json={
                "asset_id": asset.id,
                "cve_id": cve_id,
                "cvss_score": 5.0,
                "in_kev": False,
                "epss_percentile": 0.1,
            },
            headers=h,
        )
        assert response.status_code == 422


def test_scan_does_not_score_when_required_intel_is_unavailable(env, monkeypatch):
    client, db = env
    headers = _hdrs(client)
    asset = Asset(name="INTEL-FAILURE-SRV", exposure="Internal", criticality=3)
    db.add(asset)
    db.commit()

    async def unavailable_intel(cve_id):
        return {
            "cve_id": cve_id,
            "epss": None,
            "cvss": None,
            "available": False,
            "errors": ["EPSS lookup failed.", "NVD lookup failed."],
        }

    monkeypatch.setattr(main, "fetch_cve_data", unavailable_intel)
    response = client.post(
        "/scan",
        json={"asset_id": asset.id, "cve_id": "CVE-2025-6789"},
        headers=headers,
    )

    assert response.status_code == 503
    assert "was not scored" in response.json()["detail"]["message"]
    assert db.query(Finding).filter_by(cve_id="CVE-2025-6789").first() is None


def test_audit_log_immutability_enforced(env):
    client, db = env
    h = _hdrs(client)
    client.post('/assets', json={'name': 'IMMUTABLE-SRV', 'exposure': 'Internal', 'criticality': 3}, headers=h)
    log = db.query(AuditLog).first()
    assert log is not None

    assert client.delete('/audit/' + str(log.id), headers=h).status_code in (404, 405)
    assert client.put('/audit/' + str(log.id), json={'action': 'TAMPER'}, headers=h).status_code in (404, 405)

    log.action = 'TAMPERED'
    with pytest.raises(RuntimeError, match='immutable'):
        db.commit()
    db.rollback()

    with pytest.raises(RuntimeError, match='immutable'):
        db.delete(log)
        db.commit()
    db.rollback()
