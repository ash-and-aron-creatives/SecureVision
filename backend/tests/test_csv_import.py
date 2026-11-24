import datetime as dt
import csv
import io
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from backend import auth, main
from backend.database import Base, get_db
from backend.main import app
from backend.models import Asset, CVECatalog, Finding, FindingScore, User
from backend.tests.db_helpers import create_test_engine

from backend.csv_import import (
    ImportFileError,
    MAX_BYTES,
    MAX_ROWS,
    detect_format,
    parse_and_validate,
    problems_to_csv,
    safe_cell,
)

ASSETS = {"Payment-DB": 1, "Public Website": 2}
TODAY = dt.date(2026, 10, 12)

def run(text, existing=None):
    return parse_and_validate(text.encode("utf-8"), ASSETS, existing or set(), TODAY)

def test_valid_rows_and_normalisation():
    rows, s = run("asset_name,cve_id,date_found\npayment-db, cve-2021-44228 ,2026-10-01\n")
    assert s == {"total": 1, "ok": 1, "error": 0, "duplicate": 0}
    assert rows[0].asset_id == 1 and rows[0].cve_id == "CVE-2021-44228"


def test_host_or_ip_candidate_matches_the_asset_identifier_map():
    rows, summary = parse_and_validate(
        b"hostname,cve_id,date_found\n192.0.2.10,CVE-2021-44228,2026-10-01\n",
        {"Payment-DB": 1, "192.0.2.10": 1},
        set(),
        TODAY,
    )
    assert summary["ok"] == 1
    assert rows[0].asset_id == 1


def test_csv_asset_name_text_validation():
    long_name = "a" * 201
    controls = "bad\u0000host"
    rows, summary = parse_and_validate(
        (
            "hostname,cve_id,date_found\n"
            f"{long_name},CVE-2021-44228,2026-10-01\n"
            f"{controls},CVE-2021-44228,2026-10-01\n"
        ).encode(),
        {},
        set(),
        TODAY,
        allow_missing_assets=True,
    )
    assert summary["error"] == 2
    assert "at most 200 characters" in rows[0].reason
    assert "control characters" in rows[1].reason

def test_bom_extra_columns_and_header_case():
    rows, s = run("\ufeffAsset_Name,CVE_ID,Date_Found,notes\nPublic Website,CVE-2017-0144,2026-09-01,x\n")
    assert s["ok"] == 1

def test_missing_column_is_file_error():
    with pytest.raises(ImportFileError, match="date_found"): run("asset_name,cve_id\nPayment-DB,CVE-2021-44228\n")

def test_unknown_asset_bad_cve_bad_date_future_date():
    rows, s = run("asset_name,cve_id,date_found\nNope,CVE-2021-44228,2026-10-01\nPayment-DB,CVE-21-1,2026-10-01\nPayment-DB,CVE-2021-44228,not-a-date\nPayment-DB,CVE-2021-44228,2026-10-13\n")
    assert [r.status for r in rows] == ["error"] * 4
    assert "Unknown asset" in rows[0].reason and "CVE-" in rows[1].reason
    assert "date_found" in rows[2].reason


@pytest.mark.parametrize(
    ("header", "format_name"),
    [
        ("asset_name,cve_id,date_found,cvss_score", "Generic"),
        ("Plugin ID,Host,CVE,First Discovered,CVSS v3.1 Base Score", "Nessus"),
        ("QID,IP,DNS,CVE ID,First Detected,CVSS Base Score", "Qualys"),
        ("IP,Hostname,NVT Name,CVEs,Creation Time,CVSS Base Score", "OpenVAS/Greenbone"),
    ],
)
def test_scanner_format_detection(header, format_name):
    assert detect_format(header.split(",")) == format_name


def test_scanner_adapters_map_identifiers_dates_and_cvss():
    cases = [
        (
            "Plugin ID,Hostname,IP Address,CVE,First Discovered,CVSS v3.1 Base Score\n"
            "123, payment-db ,192.0.2.1,CVE-2021-44228,2026-10-01T10:20:30Z,8.4\n",
            "Payment-DB",
            "2026-10-01",
            8.4,
        ),
        (
            "QID,IP,DNS,CVE ID,First Detected,CVSS Base Score\n"
            "123,192.0.2.1,payment-db,CVE-2021-44228,13/04/2026,7.2\n",
            "Payment-DB",
            "2026-04-13",
            7.2,
        ),
        (
            "IP,Hostname,NVT Name,CVEs,Creation Time,CVSS Base Score\n"
            "payment-db,db.example.test,OpenSSH CVE,CVE-2021-44228,04/13/2026,6.5\n",
            "db.example.test",
            "2026-04-13",
            6.5,
        ),
    ]
    for content, expected_asset, expected_date, expected_cvss in cases:
        rows, summary = parse_and_validate(content.encode(), ASSETS, set(), TODAY)
        assert summary["ok"] == 1
        assert rows[0].asset_name.casefold() == expected_asset.casefold()
        assert rows[0].date_found == expected_date
        assert rows[0].cvss_score == expected_cvss


def test_multi_cve_rows_and_multiple_validation_errors():
    rows, summary = run(
        "asset_name,cve_id,date_found\n"
        "Payment-DB,CVE-2021-44228; CVE-2022-12345,2026-10-01\n"
        "Unknown Host,not-a-cve,not-a-date\n"
    )
    assert [row.cve_id for row in rows] == ["CVE-2021-44228", "CVE-2022-12345", "NOT-A-CVE"]
    assert [row.status for row in rows] == ["ok", "ok", "error"]
    assert "Unknown asset" in rows[2].reason
    assert "cve_id" in rows[2].reason
    assert "date_found" in rows[2].reason
    assert summary == {"total": 3, "ok": 2, "error": 1, "duplicate": 0}


def test_no_cve_is_reported_clearly_and_missing_asset_can_be_previewed():
    rows, summary = parse_and_validate(
        b"hostname,cve,date_found\nnew-db,,2026-10-01\n",
        ASSETS,
        set(),
        TODAY,
        allow_missing_assets=True,
    )
    assert summary["error"] == 1
    assert "No CVE" in rows[0].reason
    rows, summary = parse_and_validate(
        b"hostname,cve,date_found\nnew-db,CVE-2021-44228,2026-10-01\n",
        ASSETS,
        set(),
        TODAY,
        allow_missing_assets=True,
    )
    assert summary["ok"] == 1 and rows[0].asset_id is None


@pytest.mark.parametrize(
    ("date_text", "expected"),
    [
        ("2026-10-01", "2026-10-01"),
        ("13/04/2026", "2026-04-13"),
        ("04/13/2026", "2026-04-13"),
        ("2026-10-01T13:45:00Z", "2026-10-01"),
    ],
)
def test_flexible_dates(date_text, expected):
    rows, _ = run(f"asset_name,cve_id,date_found\nPayment-DB,CVE-2021-44228,{date_text}\n")
    assert rows[0].date_found == expected


def test_utf8_bom_and_quoted_fields():
    data = b'\xef\xbb\xbf"Asset Name","CVE ID","Date Found"\n"Payment, DB",CVE-2021-44228,2026-10-01\n'
    rows, summary = parse_and_validate(data, {"Payment, DB": 3}, set(), TODAY)
    assert summary["ok"] == 1
    assert rows[0].asset_name == "Payment, DB"


@pytest.mark.parametrize(
    ("filename", "expected_format"),
    [
        ("generic.csv", "Generic"),
        ("nessus.csv", "Nessus"),
        ("qualys.csv", "Qualys"),
        ("openvas.csv", "OpenVAS/Greenbone"),
    ],
)
def test_sample_data_imports(filename, expected_format):
    sample_path = Path(__file__).parents[2] / "sample_data" / filename
    data = sample_path.read_bytes()
    headers = next(csv.reader(data.decode("utf-8-sig").splitlines()))
    assert detect_format(headers) == expected_format
    rows, summary = parse_and_validate(
        data,
        {"Payment-DB": 1, "payment-db": 1, "192.0.2.10": 1},
        set(),
        TODAY,
    )
    assert summary["ok"] == 1
    assert rows[0].asset_id == 1

def test_duplicates_in_file_and_existing():
    rows, s = run("asset_name,cve_id,date_found\nPayment-DB,CVE-2021-44228,2026-10-01\nPayment-DB,CVE-2021-44228,2026-10-02\nPublic Website,CVE-2017-0144,2026-10-02\n", existing={(2, "CVE-2017-0144")})
    assert [r.status for r in rows] == ["ok", "duplicate", "duplicate"]
    assert "this file" in rows[1].reason and "already exists" in rows[2].reason

def test_same_cve_on_different_assets_is_not_duplicate():
    rows, s = run("asset_name,cve_id,date_found\nPayment-DB,CVE-2021-44228,2026-10-01\nPublic Website,CVE-2021-44228,2026-10-01\n")
    assert s["ok"] == 2

def test_limits_and_encoding():
    with pytest.raises(ImportFileError, match="5 MB"): parse_and_validate(b"x" * (MAX_BYTES + 1), ASSETS, set(), TODAY)
    with pytest.raises(ImportFileError, match="UTF-8"): parse_and_validate("asset_name,cve_id,date_found\n\xe9".encode("latin-1"), ASSETS, set(), TODAY)
    with pytest.raises(ImportFileError, match="5,000"): run("asset_name,cve_id,date_found\n" + "Payment-DB,CVE-2021-44228,2026-10-01\n" * 5001)
    with pytest.raises(ImportFileError, match="empty"): run("")

def test_accepts_csv_at_exact_byte_and_row_limits():
    header = b"asset_name,cve_id,date_found,notes\n"
    row_prefix = b"Payment-DB,CVE-2021-44228,2026-10-01,"
    padding = MAX_BYTES - len(header) - MAX_ROWS * (len(row_prefix) + 1)
    padding_per_row, extra_padding = divmod(padding, MAX_ROWS)
    data_rows = (
        row_prefix + b"x" * (padding_per_row + (index < extra_padding)) + b"\n"
        for index in range(MAX_ROWS)
    )
    data = header + b"".join(data_rows)

    assert len(data) == MAX_BYTES
    rows, summary = parse_and_validate(data, ASSETS, set(), TODAY)

    assert len(rows) == MAX_ROWS
    assert summary == {
        "total": MAX_ROWS,
        "ok": 1,
        "error": 0,
        "duplicate": MAX_ROWS - 1,
    }


def test_csv_import_uses_catalog_kev_without_live_provider(monkeypatch):
    engine = create_test_engine()
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(autocommit=False, autoflush=False, bind=engine)()
    db.add_all([
        User(
            username="csv-catalog-admin",
            hashed_password=auth.get_password_hash("test-password"),
            role="admin",
        ),
        Asset(name="CATALOG-CSV-SRV", exposure="Internal", criticality=3),
        CVECatalog(
            cve_id="CVE-2025-9881",
            published_date="2025-01-01",
            description="Catalog CSV KEV test.",
            cvss_score=0.1,
            cvss_vector="CVSS:3.1/AV:L",
            cwe="CWE-79",
            kev_date_added="2025-01-02",
            epss=0.30,
            percentile=0.01,
            in_kev=True,
        ),
    ])
    db.commit()

    async def live_provider(_cve_id):
        pytest.fail("Catalog-complete CVE unexpectedly called the live provider.")

    monkeypatch.setattr(main, "fetch_cve_data", live_provider)

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    try:
        with TestClient(app) as client:
            token = client.post(
                "/token",
                data={"username": "csv-catalog-admin", "password": "test-password"},
            ).json()["access_token"]
            response = client.post(
                "/imports/commit",
                files={
                    "file": (
                        "catalog-kev.csv",
                        io.BytesIO(
                            b"asset_name,cve_id,date_found\n"
                            b"CATALOG-CSV-SRV,CVE-2025-9881,2026-10-01\n"
                        ),
                        "text/csv",
                    ),
                },
                headers={"Authorization": f"Bearer {token}"},
            )
    finally:
        app.dependency_overrides.clear()
        db.close()

    assert response.status_code == 200
    assert response.json()["imported"] == 1
    finding = db.query(Finding).filter_by(cve_id="CVE-2025-9881").one()
    score = db.query(FindingScore).filter_by(finding_id=finding.id).one()
    assert finding.in_kev is True
    assert finding.final_priority in ("High", "Critical")
    assert score.priority_tier == "High"
    assert score.likelihood == 0.01


def test_error_report_blocks_formula_injection():
    rows, _ = run("asset_name,cve_id,date_found\n=HYPERLINK(\"http://x\"),CVE-2021-44228,2026-10-01\n")
    out = problems_to_csv(rows)
    assert "'=HYPERLINK" in out and safe_cell("+1") == "'+1" and safe_cell("ok") == "ok" and safe_cell(None) == ""
