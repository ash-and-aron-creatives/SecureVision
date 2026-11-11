from datetime import date, datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

import backend.main as main
from backend import auth
from backend.database import Base, get_db
from backend.main import app
from backend.models import Asset, AuditLog, Finding, FindingScore, User
from backend.tests.db_helpers import create_test_engine


@pytest.fixture
def analytics_client():
    engine = create_test_engine()
    Base.metadata.create_all(bind=engine)
    session_local = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    db = session_local()
    db.add(User(username="analytics-admin", hashed_password=auth.get_password_hash("password123"), role="admin"))
    db.commit()

    def override_db():
        yield db

    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as client:
        token_response = client.post(
            "/token",
            data={"username": "analytics-admin", "password": "password123"},
        )
        headers = {"Authorization": f"Bearer {token_response.json()['access_token']}"}
        yield client, db, headers
    app.dependency_overrides.clear()
    db.close()
    engine.dispose()


def _add_finding(db, asset, cve_id, tier, status, found_date):
    finding = Finding(
        asset_id=asset.id,
        cve_id=cve_id,
        status=status,
        date_found=found_date,
        cvss_score=8.0,
        in_kev=False,
    )
    db.add(finding)
    db.flush()
    db.add(
        FindingScore(
            finding_id=finding.id,
            provider_id=1,
            likelihood=0.5,
            priority_tier=tier,
            provenance={},
            explanation="test",
        )
    )
    return finding


def test_dashboard_analytics_uses_findings_and_audit_history(analytics_client):
    client, db, headers = analytics_client
    now = datetime.now(timezone.utc)
    today = date.today()
    asset = Asset(name="analytics-server", exposure="Internal", criticality=3)
    db.add(asset)
    db.flush()

    critical = _add_finding(db, asset, "CVE-2025-1001", "Critical", "Resolved", today.isoformat())
    high = _add_finding(
        db, asset, "CVE-2025-1002", "High", "Resolved", (today - timedelta(days=4)).isoformat()
    )
    medium = _add_finding(
        db, asset, "CVE-2025-1004", "Medium", "Resolved", (today - timedelta(days=10)).isoformat()
    )
    low = _add_finding(
        db, asset, "CVE-2025-1005", "Low", "Resolved", (today - timedelta(days=31)).isoformat()
    )
    _add_finding(db, asset, "CVE-2025-1003", "Medium", "Open", today.isoformat())
    db.add_all(
        [
            AuditLog(
                action="STATUS_UPDATE",
                details=f"finding_id={critical.id} {critical.cve_id} status changed from Open to Resolved",
                timestamp=now,
            ),
            AuditLog(
                action="STATUS_UPDATE",
                details=f"finding_id={high.id} {high.cve_id} status changed from Open to In Progress",
                timestamp=now - timedelta(days=1),
            ),
            AuditLog(
                action="STATUS_UPDATE",
                details=f"finding_id={high.id} {high.cve_id} status changed from In Progress to Resolved",
                timestamp=now,
            ),
            AuditLog(
                action="STATUS_UPDATE",
                details=f"finding_id={medium.id} {medium.cve_id} status changed from Open to In Progress",
                timestamp=now - timedelta(days=2),
            ),
            AuditLog(
                action="STATUS_UPDATE",
                details=f"finding_id={medium.id} {medium.cve_id} status changed from In Progress to Resolved",
                timestamp=now,
            ),
            AuditLog(
                action="STATUS_UPDATE",
                details=f"finding_id={low.id} {low.cve_id} status changed from Open to In Progress",
                timestamp=now - timedelta(days=30),
            ),
            AuditLog(
                action="STATUS_UPDATE",
                details=f"finding_id={low.id} {low.cve_id} status changed from In Progress to Resolved",
                timestamp=now,
            ),
            AuditLog(
                action="SCAN_RUN",
                details=f"finding_id={critical.id} scanned",
                timestamp=now - timedelta(hours=12),
            ),
            AuditLog(
                action="SCAN_RUN",
                details=f"finding_id={high.id} scanned",
                timestamp=now - timedelta(days=5),
            ),
            AuditLog(
                action="SCAN_RUN",
                details=f"finding_id={medium.id} scanned",
                timestamp=now - timedelta(days=10),
            ),
            AuditLog(
                action="SCAN_RUN",
                details=f"finding_id={low.id} scanned",
                timestamp=now - timedelta(days=31),
            ),
            AuditLog(
                action="FINDING_IMPORTED",
                details="finding_id=999 imported from CSV",
                timestamp=now - timedelta(days=2),
            ),
            AuditLog(
                action="IMPORT",
                details="file=weekly.csv imported=3 skipped=0",
                timestamp=now - timedelta(days=3),
            ),
        ]
    )
    db.commit()

    response = client.get("/dashboard/analytics", headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert data["total_findings"] == 5
    assert data["total_assets"] == 1
    assert data["open_vulnerabilities"] == 1
    assert data["fixed_this_month"] == 4
    assert data["resolved_findings"] == 4
    assert data["mitigation_pct"] == 80.0
    assert data["critical_count"] == 1
    assert data["open_medium_count"] == 1
    assert data["open_critical_count"] == 0
    assert data["mean_time_to_triage_hours"] == 81.0
    assert data["sla_compliance_pct"] == 50.0
    assert data["ingestion_has_history"] is True
    assert len(data["weekly_activity"]) == 7
    assert sum(day["ingested_count"] for day in data["weekly_activity"]) == 5
    assert sum(day["resolved_count"] for day in data["weekly_activity"]) == 4


def test_dashboard_analytics_returns_empty_metrics_without_history(analytics_client):
    client, _, headers = analytics_client

    response = client.get("/dashboard/analytics", headers=headers)

    assert response.status_code == 200
    data = response.json()
    assert data["total_findings"] == 0
    assert data["total_assets"] == 0
    assert data["open_vulnerabilities"] == 0
    assert data["fixed_this_month"] == 0
    assert data["mitigation_pct"] is None
    assert data["mean_time_to_triage_hours"] is None
    assert data["sla_compliance_pct"] is None
    assert data["ingestion_has_history"] is False
    assert len(data["weekly_activity"]) == 7
    assert all(day["ingested_count"] == 0 and day["resolved_count"] == 0 for day in data["weekly_activity"])


def test_csv_import_records_per_finding_creation_time(analytics_client, monkeypatch):
    client, db, headers = analytics_client

    async def available_intel(cve_id):
        return {
            "cve_id": cve_id,
            "epss": 0.2,
            "cvss": 5.0,
            "available": True,
            "errors": [],
            "in_kev": False,
        }

    monkeypatch.setattr(main, "fetch_cve_data", available_intel)
    asset_response = client.post(
        "/assets",
        json={"name": "import-analytics-server", "exposure": "Internal", "criticality": 3},
        headers=headers,
    )
    assert asset_response.status_code == 200
    csv_content = (
        "asset_name,cve_id,date_found\n"
        f"import-analytics-server,CVE-2025-1111,{date.today().isoformat()}\n"
    )

    import_response = client.post(
        "/imports/commit",
        files={"file": ("findings.csv", csv_content.encode(), "text/csv")},
        headers=headers,
    )

    assert import_response.status_code == 200
    finding = db.query(Finding).filter_by(cve_id="CVE-2025-1111").one()
    import_event = db.query(AuditLog).filter_by(action="IMPORT").one()
    assert f"finding_ids={finding.id}" in import_event.details
    details_response = client.get(f"/findings/{finding.id}", headers=headers)
    assert details_response.status_code == 200
    assert any(log["action"] == "IMPORT" for log in details_response.json()["audit_trail"])

    status_response = client.put(
        f"/findings/{finding.id}/status",
        json={"status": "In Progress"},
        headers=headers,
    )
    assert status_response.status_code == 200
    analytics_response = client.get("/dashboard/analytics", headers=headers)
    assert analytics_response.json()["mean_time_to_triage_hours"] is not None


def test_dashboard_analytics_requires_authentication(analytics_client):
    client, _, _ = analytics_client

    response = client.get("/dashboard/analytics")

    assert response.status_code == 401
