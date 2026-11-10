import hashlib
import json
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from backend.main import app
from backend.database import Base, get_db
from backend import auth
from backend.models import Asset, AuditLog, Finding, FindingScore, User


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
    admin = User(
        username="admin",
        hashed_password=auth.get_password_hash("password123"),
        role="admin",
    )
    db.add(admin)
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


@pytest.fixture
def auth_headers(client):
    res = client.post("/token", data={"username": "admin", "password": "password123"})
    assert res.status_code == 200
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


@pytest.fixture
def seeded(db_session):
    a1 = Asset(name="RPT-WEB", exposure="Internet", criticality=5)
    a2 = Asset(name='=HYPERLINK("http://evil")', exposure="Internal", criticality=1)
    db_session.add_all([a1, a2])
    db_session.flush()
    specs = [
        (a1, "CVE-2099-0001", 9.8, True, "Open", "Critical"),
        (a1, "CVE-2099-0002", 7.5, False, "Open", "High"),
        (a2, "CVE-2099-0003", 4.0, False, "Resolved", "Low"),
    ]
    for asset, cve, cvss, kev, status, tier in specs:
        f = Finding(
            asset_id=asset.id,
            cve_id=cve,
            cvss_score=cvss,
            in_kev=kev,
            status=status,
            date_found="2026-10-14",
        )
        db_session.add(f)
        db_session.flush()
        db_session.add(
            FindingScore(
                finding_id=f.id,
                provider_id=1,
                likelihood=0.5,
                priority_tier=tier,
                provenance={"source": "test"},
                explanation="test",
            )
        )
    db_session.commit()
    return a1, a2


def _last_export(db_session):
    row = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == "EXPORT")
        .order_by(AuditLog.id.desc())
        .first()
    )
    return row, json.loads(row.details)


def test_csv_export_basic(client, auth_headers, seeded):
    r = client.get("/reports/findings.csv", headers=auth_headers)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "attachment" in r.headers["content-disposition"]
    lines = r.text.strip().splitlines()
    assert lines[0].startswith("finding_id,cve_id,asset")
    assert len(lines) == 1 + 3


def test_csv_filters_applied(client, auth_headers, seeded):
    r = client.get("/reports/findings.csv?priority=Critical", headers=auth_headers)
    assert "CVE-2099-0001" in r.text
    assert "CVE-2099-0002" not in r.text and "CVE-2099-0003" not in r.text

    r = client.get("/reports/findings.csv?status=Resolved", headers=auth_headers)
    assert "CVE-2099-0003" in r.text and "CVE-2099-0001" not in r.text

    a1, _ = seeded
    r = client.get(f"/reports/findings.csv?asset_id={a1.id}&q=0002", headers=auth_headers)
    assert r.text.count("CVE-2099-") == 1 and "CVE-2099-0002" in r.text


def test_csv_search_matches_explanation_summary(client, auth_headers, seeded, db_session):
    score = db_session.query(FindingScore).filter(FindingScore.finding_id.isnot(None)).first()
    score.explanation = "queue-search-token"
    db_session.commit()

    response = client.get("/reports/findings.csv?q=queue-search-token", headers=auth_headers)
    assert response.status_code == 200
    assert "CVE-2099-0001" in response.text
    assert "CVE-2099-0002" not in response.text
    assert response.headers["x-row-count"] == "1"


def test_csv_formula_injection_guard(client, auth_headers, seeded):
    r = client.get("/reports/findings.csv", headers=auth_headers)
    assert "'=HYPERLINK" in r.text
    assert ",=HYPERLINK" not in r.text and ',"=HYPERLINK' not in r.text


def test_csv_export_audit_log(client, auth_headers, seeded, db_session):
    r = client.get("/reports/findings.csv?priority=High&sort=cvss", headers=auth_headers)
    _, d = _last_export(db_session)
    assert d["format"] == "csv"
    assert d["filters"]["priority"] == "High" and d["filters"]["sort"] == "cvss"
    assert d["rows"] == 1
    assert d["sha256"] == hashlib.sha256(r.content).hexdigest()
    assert r.headers["x-content-sha256"] == d["sha256"]


def test_pdf_export_header_and_audit(client, auth_headers, seeded, db_session):
    r = client.get("/reports/executive.pdf", headers=auth_headers)
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert r.content.startswith(b"%PDF-")
    row, d = _last_export(db_session)
    assert d["format"] == "pdf"
    assert d["sha256"] == hashlib.sha256(r.content).hexdigest()


def test_reports_require_auth(client):
    assert client.get("/reports/findings.csv").status_code in (401, 403)
    assert client.get("/reports/executive.pdf").status_code in (401, 403)