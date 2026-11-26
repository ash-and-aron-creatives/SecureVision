import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from backend import auth, main
from backend.database import Base, get_db
from backend.main import app
from backend.models import Asset, Finding, FindingScore, User
from backend.rules_config import RECOMMENDED_ACTION_TEMPLATES
from backend.tests.db_helpers import create_test_engine


@pytest.fixture
def db_session():
    engine = create_test_engine()
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(autocommit=False, autoflush=False, bind=engine)()
    admin = User(
        username="admin",
        hashed_password=auth.get_password_hash("password123"),
        role="admin",
    )
    asset = Asset(name="TEST-SRV", exposure="Internet", criticality=5)
    db.add_all([admin, asset])
    db.flush()
    finding = Finding(
        asset_id=asset.id,
        cve_id="CVE-2021-44228",
        cvss_score=9.8,
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
        likelihood=0.95,
        priority_tier="Critical",
        provenance={},
        explanation="Test scoring explanation",
    ))
    db.commit()
    yield db
    db.close()


@pytest.fixture
def client(db_session):
    def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def get_auth_headers(client):
    res = client.post("/token", data={"username": "admin", "password": "password123"})
    assert res.status_code == 200
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


def _reference_findings_page(db_session, params):
    rows = []
    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for finding in db_session.query(Finding).all():
        latest = (
            db_session.query(FindingScore)
            .filter(FindingScore.finding_id == finding.id)
            .order_by(FindingScore.id.desc())
            .first()
        )
        rule_tier = latest.priority_tier if latest and latest.priority_tier else "Low"
        tier = finding.final_priority or rule_tier
        explanation = main._stored_explanation(latest, finding, finding.asset)
        if finding.status == "Open" and tier in counts:
            counts[tier] += 1
        rows.append({
            "id": finding.id,
            "cve_id": str(finding.cve_id or "UNKNOWN"),
            "asset_id": finding.asset_id or 0,
            "asset_name": finding.asset.name if finding.asset else "Unknown",
            "priority_tier": tier,
            "status": str(finding.status or "Open"),
            "cvss_score": float(finding.cvss_score) if finding.cvss_score is not None else 0.0,
            "epss": float(latest.likelihood) if latest and latest.likelihood is not None else 0.0,
            "explanation": explanation,
        })

    priority = params.get("priority")
    status = params.get("status")
    asset_id = params.get("asset_id")
    needle = params.get("q", "").strip().lower()
    if priority:
        rows = [row for row in rows if row["priority_tier"].lower() == priority.strip().lower()]
    if status:
        rows = [row for row in rows if row["status"].lower() == status.strip().lower()]
    if asset_id is not None:
        rows = [row for row in rows if row["asset_id"] == int(asset_id)]
    if params.get("q"):
        rows = [
            row for row in rows
            if needle in row["cve_id"].lower()
            or needle in row["asset_name"].lower()
            or needle in str(row["explanation"].get("summary", "")).lower()
        ]

    sort = params.get("sort", "priority")
    if sort == "cvss":
        rows.sort(key=lambda row: (row["cvss_score"], row["id"]), reverse=True)
    elif sort == "epss":
        rows.sort(key=lambda row: (row["epss"], row["id"]), reverse=True)
    elif sort == "newest":
        rows.sort(key=lambda row: row["id"], reverse=True)
    else:
        rows.sort(
            key=lambda row: (
                main.TIER_RANK.get(row["priority_tier"], 0),
                row["cvss_score"],
                row["epss"],
                row["id"],
            ),
            reverse=True,
        )

    page = int(params.get("page", 1))
    page_size = int(params.get("page_size", 7))
    start = (page - 1) * page_size
    return {
        "ids": [row["id"] for row in rows[start : start + page_size]],
        "total": len(rows),
        "pages": max(1, (len(rows) + page_size - 1) // page_size),
        "counts": counts,
    }


def _add_findings_reference_dataset(db_session):
    assets = [
        Asset(name="percent%_app", exposure="Internet", criticality=4),
        Asset(name="gateway_2", exposure="Internal", criticality=2),
        Asset(name="search-node", exposure="Internet", criticality=3),
    ]
    db_session.add_all(assets)
    db_session.flush()
    tiers = ("Critical", "High", "Medium", "Low")
    statuses = ("Open", "In Progress", "Resolved", None)
    findings = []
    for index in range(32):
        finding = Finding(
            asset_id=assets[index % len(assets)].id,
            cve_id="CVE-2025-10%_special" if index == 4 else f"CVE-2025-{2000 + index}",
            cvss_score=None if index % 6 == 0 else float((index * 7) % 101) / 10,
            final_priority="" if index % 9 == 0 else tiers[index % len(tiers)],
            status=statuses[index % len(statuses)],
            date_found=f"2025-01-{index % 28 + 1:02d}",
        )
        db_session.add(finding)
        db_session.flush()
        findings.append(finding)
        if index % 6 != 0:
            db_session.add(FindingScore(
                finding_id=finding.id,
                provider_id=1,
                likelihood=None if index % 5 == 0 else float(index % 10) / 10,
                priority_tier=tiers[(index + 1) % len(tiers)],
                provenance={},
                explanation=f"Explanation {index} searchable",
            ))
            if index == 2:
                db_session.add(FindingScore(
                    finding_id=finding.id,
                    provider_id=1,
                    likelihood=0.99,
                    priority_tier="High",
                    provenance={},
                    explanation="Latest explanation with final_marker",
                ))
    db_session.commit()
    return assets


def test_findings_sql_pagination_matches_reference(client, db_session):
    assets = _add_findings_reference_dataset(db_session)
    headers = get_auth_headers(client)
    cases = [{"sort": sort} for sort in ("priority", "cvss", "epss", "newest")]
    cases.extend([
        {"priority": "hIgH"},
        {"status": "rEsOlVeD"},
        {"asset_id": assets[1].id},
        {"q": "CVE-2025-20"},
        {"q": "%"},
        {"q": "_"},
        {"priority": "Critical", "status": "Open", "asset_id": assets[0].id, "q": "CVE"},
    ])
    cases.extend(
        {"sort": sort, "page": page}
        for sort in ("priority", "cvss", "epss", "newest")
        for page in (1, 3, 5)
    )

    for params in cases:
        request_params = {"page_size": 7, **params}
        response = client.get("/findings", params=request_params, headers=headers)
        assert response.status_code == 200
        actual = response.json()
        expected = _reference_findings_page(db_session, request_params)
        assert [item["id"] for item in actual["items"]] == expected["ids"]
        assert actual["total"] == expected["total"]
        assert actual["pages"] == expected["pages"]
        assert actual["counts"] == expected["counts"]


def test_findings_list_and_counts(client):
    headers = get_auth_headers(client)
    res = client.get("/findings?page=1&page_size=10", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "items" in data and "total" in data and "counts" in data
    assert len(data["items"]) <= 10
    assert set(data["counts"].keys()) == {"Critical", "High", "Medium", "Low"}
    assert data["items"][0]["recommended_action"] == RECOMMENDED_ACTION_TEMPLATES["Critical"]


def test_findings_over_twenty_are_reachable_across_pages(client, db_session):
    asset = db_session.query(Asset).first()
    for index in range(25):
        finding = Finding(
            asset_id=asset.id,
            cve_id=f"CVE-2026-{index + 1000}",
            cvss_score=5.0,
            final_priority="Medium",
            priority_source="rules",
            status="Open",
            date_found="2026-10-01",
        )
        db_session.add(finding)
        db_session.flush()
        db_session.add(FindingScore(
            finding_id=finding.id,
            provider_id=1,
            likelihood=0.2,
            priority_tier="Medium",
            provenance={},
            explanation="Pagination test finding",
        ))
    db_session.commit()

    headers = get_auth_headers(client)
    pages = [
        client.get(f"/findings?page={page}&page_size=20", headers=headers).json()
        for page in (1, 2)
    ]
    finding_ids = {item["id"] for page in pages for item in page["items"]}
    assert pages[0]["total"] == 26
    assert pages[0]["pages"] == 2
    assert len(finding_ids) == 26


def test_findings_filters_and_search(client):
    headers = get_auth_headers(client)
    res = client.get("/findings?priority=Critical", headers=headers)
    assert res.status_code == 200
    for item in res.json()["items"]:
        assert item["priority_tier"] == "Critical"

    res_q = client.get("/findings?q=CVE-2021-44228", headers=headers)
    assert res_q.status_code == 200
    for item in res_q.json()["items"]:
        assert "CVE-2021-44228" in item["cve_id"]


def test_finding_detail_and_404(client):
    headers = get_auth_headers(client)
    list_res = client.get("/findings?page=1&page_size=1", headers=headers)
    first_id = list_res.json()["items"][0]["id"]

    detail_res = client.get(f"/findings/{first_id}", headers=headers)
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == first_id
    assert "asset" in detail and "explanation" in detail and "score_history" in detail

    missing_res = client.get("/findings/999999", headers=headers)
    assert missing_res.status_code == 404


@pytest.mark.parametrize("tier", ("Critical", "High", "Medium", "Low"))
def test_finding_detail_includes_rule_only_action_for_each_final_tier(
    client, db_session, tier
):
    asset = db_session.query(Asset).first()
    finding = Finding(
        asset_id=asset.id,
        cve_id=f"CVE-2026-{len(tier):04d}",
        cvss_score=5.0,
        final_priority=tier,
        priority_source="rules",
        status="Open",
        date_found="2026-10-01",
    )
    db_session.add(finding)
    db_session.commit()

    response = client.get(
        f"/findings/{finding.id}",
        headers=get_auth_headers(client),
    )
    assert response.status_code == 200
    assert response.json()["recommended_action"] == RECOMMENDED_ACTION_TEMPLATES[tier]
    assert response.json()["ml_recommended_action"] is None


def test_status_update_records_audit(client):
    headers = get_auth_headers(client)
    list_res = client.get("/findings?page=1&page_size=1", headers=headers)
    finding = list_res.json()["items"][0]

    upd = client.put(f"/findings/{finding['id']}/status", json={"status": "In Progress"}, headers=headers)
    assert upd.status_code == 200
    assert upd.json()["status"] == "In Progress"

    client.put(f"/findings/{finding['id']}/status", json={"status": "Open"}, headers=headers)
