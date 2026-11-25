import io

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.orm import sessionmaker

from backend import auth, main
from backend.database import Base, get_db
from backend.main import app
from backend.models import Asset, AuditLog, Finding, FindingScore, User
from backend.tests.db_helpers import create_test_engine


@pytest.fixture
def api(monkeypatch):
    engine = create_test_engine()
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(autocommit=False, autoflush=False, bind=engine)()
    admin = User(
        username="test-admin",
        hashed_password=auth.get_password_hash("test-password"),
        role="admin",
    )
    viewer = User(
        username="test-viewer",
        hashed_password=auth.get_password_hash("test-password"),
        role="viewer",
    )
    asset = Asset(name="TEST-ASSET", exposure="Internet", criticality=5)
    db.add_all([admin, viewer, asset])
    db.flush()
    finding = Finding(
        asset_id=asset.id,
        cve_id="CVE-2025-1234",
        cvss_score=8.5,
        in_kev=True,
        final_priority="Critical",
        priority_source="rules",
        status="Open",
        date_found="2026-10-01",
    )
    db.add(finding)
    db.flush()
    db.add(FindingScore(
        finding_id=finding.id,
        provider_id=1,
        likelihood=0.8,
        priority_tier="Critical",
        provenance={"source": "test"},
        explanation="Test explanation",
    ))
    db.commit()

    async def nvd_and_epss(cve_id):
        return {
            "cve_id": cve_id,
            "epss": 0.4,
            "epss_percentile": 0.4,
            "cvss": 8.0,
            "available": True,
            "errors": [],
            "description": "Mock vulnerability description.",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe": "CWE-79",
            "published_date": "2025-01-01T00:00Z",
        }

    monkeypatch.setattr(main, "fetch_cve_data", nvd_and_epss)

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as client:
        yield client, db
    app.dependency_overrides.clear()
    db.close()


def _headers(client, username="test-admin"):
    response = client.post(
        "/token",
        data={"username": username, "password": "test-password"},
    )
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def _reject_audit_insert(mapper, connection, target):
    raise RuntimeError("audit insert failed")


def _assert_audit_failure_rolls_back(db, request, assertion):
    event.listen(AuditLog, "before_insert", _reject_audit_insert)
    try:
        with pytest.raises(RuntimeError, match="audit insert failed"):
            request()
    finally:
        event.remove(AuditLog, "before_insert", _reject_audit_insert)
    assert assertion()
    db.rollback()


def test_response_models_have_consistent_shapes(api, monkeypatch):
    client, db = api
    headers = _headers(client)

    token_response = client.post(
        "/token",
        data={"username": "test-admin", "password": "test-password"},
    )
    assert set(token_response.json()) == {"access_token", "token_type", "role", "username"}

    async def unavailable_intel(cve_id):
        return {
            "cve_id": cve_id,
            "epss": None,
            "epss_percentile": None,
            "cvss": None,
            "available": False,
            "errors": ["EPSS lookup failed.", "NVD lookup failed."],
            "description": None,
            "cvss_vector": None,
            "cwe": None,
            "published_date": None,
        }

    monkeypatch.setattr(main, "fetch_cve_data", unavailable_intel)
    invalid_intel = client.get("/intel/not-a-cve", headers=headers)
    assert invalid_intel.status_code == 422
    unavailable_response = client.get("/intel/CVE-2025-1111", headers=headers)
    assert unavailable_response.status_code == 200
    assert unavailable_response.json() == {
        "cve_id": "CVE-2025-1111",
        "epss": None,
        "epss_percentile": None,
        "cvss": None,
        "available": False,
        "errors": ["EPSS lookup failed.", "NVD lookup failed."],
        "description": None,
        "cvss_vector": None,
        "cwe": None,
        "published_date": None,
    }

    asset_response = client.post(
        "/assets",
        json={"name": "SCHEMA-ASSET", "exposure": "Internal", "criticality": 3},
        headers=headers,
    )
    assert asset_response.status_code == 200
    assert set(asset_response.json()) == {
        "id", "name", "type", "ip_or_domain", "owner", "environment",
        "exposure", "criticality", "needs_review",
    }
    assert set(client.get("/assets", headers=headers).json()[0]) == {
        "id", "name", "type", "ip_or_domain", "owner", "environment",
        "exposure", "criticality", "needs_review",
    }

    scan_response = client.post(
        "/scan",
        json={
            "asset_id": 1,
            "cve_id": "CVE-2025-5678",
            "cvss_score": 8.0,
            "epss_percentile": 0.0,
        },
        headers=headers,
    )
    assert scan_response.status_code == 200
    scan_body = scan_response.json()
    assert set(scan_body) == {
        "finding_id", "action", "reopened", "priority_tier", "final_priority",
        "recommended_action", "priority_source", "rule_priority_tier", "score", "explanation",
        "ml_likelihood", "ml_risk", "ml_priority", "ml_top_reasons", "ml_model_version",
        "ml_recommended_action", "ml_unavailable_reason",
    }
    assert scan_body["action"] == "created"
    assert scan_body["score"] == 2
    assert set(scan_body["explanation"]) == {"summary", "inputs", "rationale"}
    assert set(scan_body["explanation"]["inputs"]) == {
        "in_kev", "internet_facing", "criticality", "epss_percentile", "cvss_score",
    }

    finding = client.get("/findings", headers=headers).json()["items"][0]
    assert {"exposure", "criticality", "score", "explanation"} <= set(finding)
    assert "asset_exposure" not in finding and "asset_criticality" not in finding
    detail = client.get(f"/findings/{finding['id']}", headers=headers).json()
    assert set(detail["asset"]) == {
        "id", "name", "type", "ip_or_domain", "owner", "environment",
        "exposure", "criticality",
    }
    assert {"score", "explanation", "score_history", "audit_trail"} <= set(detail)

    user_response = client.post(
        "/users",
        json={"username": "schema-user", "password": "test-password", "role": "analyst"},
        headers=headers,
    )
    assert user_response.status_code == 201
    assert set(user_response.json()) == {"id", "username", "role", "is_active"}
    assert set(client.get("/users", headers=headers).json()[0]) == {
        "id", "username", "role", "is_active",
    }
    audit = client.get("/audit", headers=headers).json()[0]
    assert set(audit) == {"id", "user", "action", "details", "timestamp"}

    csv_data = b"asset_name,cve_id,date_found\nTEST-ASSET,CVE-2025-9876,2026-10-01\n"
    preview = client.post(
        "/imports/preview",
        files={"file": ("findings.csv", io.BytesIO(csv_data), "text/csv")},
        headers=headers,
    )
    assert preview.status_code == 200
    assert set(preview.json()) == {"detected_format", "summary", "rows", "ambiguous_date_rows"}
    assert set(preview.json()["summary"]) == {"total", "ok", "error", "duplicate"}
    assert set(preview.json()["rows"][0]) == {
        "line", "asset_name", "cve_id", "date_found", "status", "reason", "asset_id",
        "cvss_score",
    }

    async def fetch_cve_data(cve_id):
        return {
            "cve_id": cve_id,
            "in_kev": False,
            "cvss": 7.0,
            "epss": 0.4,
            "epss_percentile": 0.4,
            "available": True,
            "errors": [],
            "description": "Mock vulnerability description.",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe": "CWE-79",
            "published_date": "2025-01-01T00:00Z",
        }

    monkeypatch.setattr(main, "fetch_cve_data", fetch_cve_data)
    committed = client.post(
        "/imports/commit",
        files={"file": ("findings.csv", io.BytesIO(csv_data), "text/csv")},
        headers=headers,
    )
    assert committed.status_code == 200
    assert set(committed.json()) == {"imported", "skipped", "problems_csv", "ambiguous_date_rows"}
    assert committed.json()["imported"] == 1


def test_csv_import_skips_findings_when_intel_is_unavailable(api, monkeypatch):
    client, db = api
    headers = _headers(client)

    async def unavailable_intel(cve_id):
        return {
            "cve_id": cve_id,
            "epss": 0.2,
            "epss_percentile": 0.2,
            "cvss": None,
            "available": False,
            "errors": ["NVD CVSS score is unavailable."],
        }

    monkeypatch.setattr(main, "fetch_cve_data", unavailable_intel)
    csv_data = b"asset_name,cve_id,date_found\nTEST-ASSET,CVE-2025-9876,2026-10-01\n"
    response = client.post(
        "/imports/commit",
        files={"file": ("findings.csv", io.BytesIO(csv_data), "text/csv")},
        headers=headers,
    )

    assert response.status_code == 200
    assert response.json()["imported"] == 0
    assert response.json()["skipped"] == 1
    assert "NVD CVSS score is unavailable." in response.json()["problems_csv"]
    assert db.query(Finding).filter_by(cve_id="CVE-2025-9876").first() is None


def test_csv_import_skips_repeated_asset_cve_rows_in_one_file(api, monkeypatch):
    client, db = api
    headers = _headers(client)

    async def available_intel(cve_id):
        return {
            "cve_id": cve_id,
            "in_kev": False,
            "cvss": 7.0,
            "epss": 0.4,
            "epss_percentile": 0.4,
            "available": True,
            "errors": [],
            "description": "Repeated-row test description.",
            "cvss_vector": "CVSS:3.1/AV:N",
            "cwe": "CWE-79",
            "published_date": "2025-01-01T00:00Z",
        }

    monkeypatch.setattr(main, "fetch_cve_data", available_intel)
    csv_data = (
        b"asset_name,cve_id,date_found\n"
        b"TEST-ASSET,CVE-2025-9876,2026-10-01\n"
        b"TEST-ASSET,CVE-2025-9876,2026-10-02\n"
    )
    preview = client.post(
        "/imports/preview",
        files={"file": ("repeated.csv", io.BytesIO(csv_data), "text/csv")},
        headers=headers,
    )
    assert preview.status_code == 200
    assert preview.json()["summary"]["duplicate"] == 1

    committed = client.post(
        "/imports/commit",
        files={"file": ("repeated.csv", io.BytesIO(csv_data), "text/csv")},
        headers=headers,
    )
    assert committed.status_code == 200
    assert committed.json()["imported"] == 1
    assert committed.json()["skipped"] == 1
    assert "Repeated in this file." in committed.json()["problems_csv"]
    asset_id = db.query(Asset.id).filter_by(name="TEST-ASSET").scalar()
    assert db.query(Finding).filter_by(asset_id=asset_id, cve_id="CVE-2025-9876").count() == 1


def test_csv_import_creates_missing_asset_with_review_flag_and_file_cvss(api, monkeypatch):
    client, db = api
    headers = _headers(client)

    async def available_epSS_only(cve_id):
        return {
            "cve_id": cve_id,
            "epss": 0.4,
            "epss_percentile": 0.4,
            "cvss": None,
            "available": True,
            "errors": ["NVD CVSS score is unavailable."],
        }

    monkeypatch.setattr(main, "fetch_cve_data", available_epSS_only)
    csv_data = (
        b"Hostname,CVE,First Discovered,CVSS v3.1 Base Score\n"
        b"new-db,CVE-2025-9877,2026-10-01,8.2\n"
    )
    preview = client.post(
        "/imports/preview",
        data={"create_missing_assets": "true"},
        files={"file": ("findings.csv", io.BytesIO(csv_data), "text/csv")},
        headers=headers,
    )
    assert preview.status_code == 200
    assert preview.json()["detected_format"] == "Generic"
    assert preview.json()["summary"]["ok"] == 1

    response = client.post(
        "/imports/commit",
        data={"create_missing_assets": "true"},
        files={"file": ("findings.csv", io.BytesIO(csv_data), "text/csv")},
        headers=headers,
    )
    assert response.status_code == 200
    assert response.json()["imported"] == 1
    asset = db.query(Asset).filter_by(name="new-db").one()
    assert asset.exposure == "Internal"
    assert asset.criticality == 3
    assert asset.needs_review is True
    listed_asset = next(
        item for item in client.get("/assets", headers=headers).json()
        if item["id"] == asset.id
    )
    assert listed_asset["needs_review"] is True
    finding = db.query(Finding).filter_by(cve_id="CVE-2025-9877").one()
    assert finding.asset_id == asset.id
    assert finding.cvss_score == 8.2
    audit = db.query(AuditLog).filter_by(action="IMPORT").one()
    assert "created_assets=new-db" in audit.details


def test_viewer_is_read_only_and_admin_only_routes_remain_restricted(api):
    client, db = api
    headers = _headers(client, "test-viewer")
    asset = db.query(Asset).first()
    finding = db.query(Finding).first()
    csv_data = b"asset_name,cve_id,date_found\nTEST-ASSET,CVE-2025-9876,2026-10-01\n"

    assert client.get("/assets", headers=headers).status_code == 200
    assert client.get("/findings", headers=headers).status_code == 200
    assert client.post(
        "/assets",
        json={"name": "DENIED-ASSET", "exposure": "Internal", "criticality": 2},
        headers=headers,
    ).status_code == 403
    assert client.post(
        "/scan",
        json={"asset_id": asset.id, "cve_id": "CVE-2025-5678"},
        headers=headers,
    ).status_code == 403
    assert client.put(
        f"/findings/{finding.id}/status",
        json={"status": "Resolved"},
        headers=headers,
    ).status_code == 403
    assert client.post(
        "/users",
        json={"username": "viewer-created", "password": "test-password"},
        headers=headers,
    ).status_code == 403
    assert client.get("/users", headers=headers).status_code == 403
    assert client.get("/audit", headers=headers).status_code == 403
    for path in ("/imports/preview", "/imports/commit"):
        assert client.post(
            path,
            files={"file": ("findings.csv", io.BytesIO(csv_data), "text/csv")},
            headers=headers,
        ).status_code == 403


def test_asset_creation_rolls_back_when_audit_insert_fails(api):
    client, db = api
    headers = _headers(client)

    _assert_audit_failure_rolls_back(
        db,
        lambda: client.post(
            "/assets",
            json={"name": "ROLLBACK-ASSET", "exposure": "Internal", "criticality": 2},
            headers=headers,
        ),
        lambda: db.query(Asset).filter_by(name="ROLLBACK-ASSET").first() is None,
    )


def test_asset_update_and_delete_roll_back_when_audit_insert_fails(api):
    client, db = api
    headers = _headers(client)
    asset = Asset(name="ROLLBACK-ASSET", exposure="Internal", criticality=3)
    db.add(asset)
    db.commit()
    before_name = asset.name
    body = {
        "name": "UPDATED-ASSET",
        "type": "Server",
        "ip_or_domain": "asset.example.test",
        "owner": "Operations",
        "environment": "Production",
        "exposure": "Internet",
        "criticality": 4,
    }
    _assert_audit_failure_rolls_back(
        db,
        lambda: client.put(f"/assets/{asset.id}", json=body, headers=headers),
        lambda: db.query(Asset).filter_by(id=asset.id).one().name == before_name,
    )
    deletable = Asset(name="ROLLBACK-DELETE-ASSET", exposure="Internal", criticality=3)
    db.add(deletable)
    db.commit()
    _assert_audit_failure_rolls_back(
        db,
        lambda: client.delete(f"/assets/{deletable.id}", headers=headers),
        lambda: db.query(Asset).filter_by(id=deletable.id).one().name == deletable.name,
    )


def test_scan_rolls_back_when_audit_insert_fails(api):
    client, db = api
    headers = _headers(client)

    _assert_audit_failure_rolls_back(
        db,
        lambda: client.post(
            "/scan",
            json={
                "asset_id": 1,
                "cve_id": "CVE-2025-6789",
                "cvss_score": 7.0,
                "epss_percentile": 0.0,
            },
            headers=headers,
        ),
        lambda: db.query(Finding).filter_by(cve_id="CVE-2025-6789").first() is None,
    )
    assert db.query(FindingScore).count() == 1


def test_status_update_rolls_back_when_audit_insert_fails(api):
    client, db = api
    headers = _headers(client)
    finding = db.query(Finding).first()

    _assert_audit_failure_rolls_back(
        db,
        lambda: client.put(
            f"/findings/{finding.id}/status",
            json={"status": "Resolved"},
            headers=headers,
        ),
        lambda: db.query(Finding).filter_by(id=finding.id).first().status == "Open",
    )


def test_user_create_update_delete_roll_back_when_audit_insert_fails(api):
    client, db = api
    headers = _headers(client)

    _assert_audit_failure_rolls_back(
        db,
        lambda: client.post(
            "/users",
            json={"username": "ROLLBACK-USER", "password": "test-password"},
            headers=headers,
        ),
        lambda: db.query(User).filter_by(username="ROLLBACK-USER").first() is None,
    )
    viewer = db.query(User).filter_by(username="test-viewer").first()
    _assert_audit_failure_rolls_back(
        db,
        lambda: client.patch(
            f"/users/{viewer.id}",
            json={"role": "analyst"},
            headers=headers,
        ),
        lambda: db.query(User).filter_by(username="test-viewer").first().role == "viewer",
    )
    viewer = db.query(User).filter_by(username="test-viewer").first()
    _assert_audit_failure_rolls_back(
        db,
        lambda: client.delete(f"/users/{viewer.id}", headers=headers),
        lambda: db.query(User).filter_by(username="test-viewer").first() is not None,
    )


def test_import_commit_rolls_back_when_audit_insert_fails(api, monkeypatch):
    client, db = api
    headers = _headers(client)
    csv_data = b"asset_name,cve_id,date_found\nTEST-ASSET,CVE-2025-9876,2026-10-01\n"

    async def fetch_cve_data(cve_id):
        return {
            "cve_id": cve_id,
            "in_kev": False,
            "cvss": 7.0,
            "epss": 0.4,
            "epss_percentile": 0.4,
            "available": True,
            "errors": [],
        }

    monkeypatch.setattr(main, "fetch_cve_data", fetch_cve_data)
    _assert_audit_failure_rolls_back(
        db,
        lambda: client.post(
            "/imports/commit",
            files={"file": ("findings.csv", io.BytesIO(csv_data), "text/csv")},
            headers=headers,
        ),
        lambda: db.query(Finding).filter_by(cve_id="CVE-2025-9876").first() is None,
    )
    assert db.query(FindingScore).count() == 1
