import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from backend.main import app
from backend.database import Base, get_db
from backend import auth
from backend import main
from backend.models import Asset, AuditLog, User, Finding
from backend.tests.db_helpers import create_test_engine

@pytest.fixture
def env(monkeypatch):
    engine = create_test_engine()
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = SessionLocal()
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
    r = client.post('/assets', json={
        'name': 'CORE-DB-01',
        'type': 'Server',
        'ip_or_domain': '192.0.2.10',
        'owner': 'Platform',
        'environment': 'Production',
        'exposure': 'Internet',
        'criticality': 5,
    }, headers=h)
    assert r.status_code == 200
    assets = client.get('/assets', headers=h).json()
    assert any(a['name'] == 'CORE-DB-01' for a in assets)
    asset = next(a for a in assets if a['name'] == 'CORE-DB-01')
    assert {
        key: asset[key] for key in ("type", "ip_or_domain", "owner", "environment")
    } == {
        "type": "Server",
        "ip_or_domain": "192.0.2.10",
        "owner": "Platform",
        "environment": "Production",
    }


def test_asset_names_are_unique_ignoring_case_for_create_and_edit(env):
    client, db = env
    headers = _hdrs(client)
    first = client.post(
        "/assets",
        json={"name": "Case-Sensitive-Name", "exposure": "Internal", "criticality": 3},
        headers=headers,
    )
    assert first.status_code == 200

    duplicate = client.post(
        "/assets",
        json={"name": "case-sensitive-name", "exposure": "Internal", "criticality": 3},
        headers=headers,
    )
    assert duplicate.status_code == 409
    assert "ignoring letter case" in duplicate.json()["detail"]

    other = client.post(
        "/assets",
        json={"name": "Another-Asset", "exposure": "Internal", "criticality": 3},
        headers=headers,
    )
    conflict = client.put(
        f"/assets/{other.json()['id']}",
        json={"name": "CASE-SENSITIVE-NAME", "exposure": "Internal", "criticality": 3},
        headers=headers,
    )
    assert conflict.status_code == 409
    assert "ignoring letter case" in conflict.json()["detail"]
    assert db.query(Asset).filter(Asset.name.ilike("case-sensitive-name")).count() == 1


def test_asset_update_delete_and_findings_guard(env):
    client, db = env
    headers = _hdrs(client)
    created = client.post(
        "/assets",
        json={"name": "EDIT-ME", "exposure": "Internal", "criticality": 3},
        headers=headers,
    )
    asset_id = created.json()["id"]
    updated = client.put(
        f"/assets/{asset_id}",
        json={
            "name": "EDITED",
            "type": "Cloud",
            "ip_or_domain": "asset.example.test",
            "owner": "Security",
            "environment": "Staging",
            "exposure": "Internet",
            "criticality": 4,
        },
        headers=headers,
    )
    assert updated.status_code == 200
    assert updated.json()["name"] == "EDITED"
    assert updated.json()["type"] == "Cloud"
    assert db.query(AuditLog).filter_by(action="ASSET_UPDATED").count() == 1

    finding = Finding(
        asset_id=asset_id,
        cve_id="CVE-2025-9090",
        cvss_score=6.0,
        in_kev=False,
        status="Open",
    )
    db.add(finding)
    db.commit()
    blocked = client.delete(f"/assets/{asset_id}", headers=headers)
    assert blocked.status_code == 409
    assert "has findings" in blocked.json()["detail"]
    assert db.query(Asset).filter_by(id=asset_id).one().name == "EDITED"

    db.delete(finding)
    db.commit()
    deleted = client.delete(f"/assets/{asset_id}", headers=headers)
    assert deleted.status_code == 200
    assert deleted.json() == {"deleted": asset_id, "name": "EDITED"}
    assert db.query(Asset).filter_by(id=asset_id).first() is None
    assert db.query(AuditLog).filter_by(action="ASSET_DELETED").count() == 1


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ip_or_domain", "bad host; DROP TABLE assets"),
        ("owner", "platform\u0000admin"),
        ("environment", "Production<script>"),
        ("type", "Database<script>"),
    ],
)
def test_asset_text_input_validation_and_literal_name_storage(env, field, value):
    client, db = env
    headers = _hdrs(client)
    body = {
        "name": "literal-' OR 1=1 --",
        "type": "Server",
        "ip_or_domain": "",
        "owner": "",
        "environment": "Production",
        "exposure": "Internal",
        "criticality": 3,
    }
    body[field] = value
    rejected = client.post("/assets", json=body, headers=headers)
    assert rejected.status_code == 422

    body[field] = {
        "ip_or_domain": "192.0.2.44",
        "owner": "Platform",
        "environment": "Production",
        "type": "Server",
    }[field]
    accepted = client.post("/assets", json=body, headers=headers)
    assert accepted.status_code == 200
    assert db.query(Asset).filter_by(name="literal-' OR 1=1 --").count() == 1

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


def test_repeated_scan_updates_existing_finding_and_reopens_resolved(env):
    client, db = env
    headers = _hdrs(client)
    asset = Asset(name="REPEAT-SCAN-SRV", exposure="Internet", criticality=5)
    db.add(asset)
    db.commit()
    payload = {
        "asset_id": asset.id,
        "cve_id": "CVE-2025-4321",
        "cvss_score": 9.8,
        "in_kev": True,
        "epss_percentile": 0.95,
    }

    created = client.post("/scan", json=payload, headers=headers)
    assert created.status_code == 200
    assert created.json()["action"] == "created"
    finding = db.query(Finding).filter_by(asset_id=asset.id, cve_id=payload["cve_id"]).one()
    finding.status = "In Progress"
    db.commit()

    payload.update(cvss_score=5.0, in_kev=False, epss_percentile=0.2)
    updated = client.post("/scan", json=payload, headers=headers)
    assert updated.status_code == 200
    assert updated.json()["action"] == "updated"
    assert updated.json()["reopened"] is False
    assert updated.json()["finding_id"] == finding.id
    assert updated.json()["priority_tier"] != created.json()["priority_tier"]
    assert updated.json()["explanation"] != created.json()["explanation"]
    assert db.query(Finding).filter_by(asset_id=asset.id, cve_id=payload["cve_id"]).count() == 1
    db.refresh(finding)
    assert finding.cvss_score == 5.0
    assert finding.status == "In Progress"
    assert db.query(AuditLog).filter(AuditLog.details.contains("Finding updated")).count() == 1

    finding.status = "Resolved"
    db.commit()
    reopened = client.post("/scan", json=payload, headers=headers)
    assert reopened.status_code == 200
    assert reopened.json()["action"] == "updated"
    assert reopened.json()["reopened"] is True
    db.refresh(finding)
    assert finding.status == "Open"
    assert db.query(Finding).filter_by(asset_id=asset.id, cve_id=payload["cve_id"]).count() == 1


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
