import datetime as dt
import pytest
from backend.csv_import import (ImportFileError, MAX_BYTES, parse_and_validate, problems_to_csv, safe_cell)

ASSETS = {"Payment-DB": 1, "Public Website": 2}
TODAY = dt.date(2026, 10, 12)

def run(text, existing=None):
    return parse_and_validate(text.encode("utf-8"), ASSETS, existing or set(), TODAY)

def test_valid_rows_and_normalisation():
    rows, s = run("asset_name,cve_id,date_found\npayment-db, cve-2021-44228 ,2026-10-01\n")
    assert s == {"total": 1, "ok": 1, "error": 0, "duplicate": 0}
    assert rows[0].asset_id == 1 and rows[0].cve_id == "CVE-2021-44228"

def test_bom_extra_columns_and_header_case():
    rows, s = run("\ufeffAsset_Name,CVE_ID,Date_Found,notes\nPublic Website,CVE-2017-0144,2026-09-01,x\n")
    assert s["ok"] == 1

def test_missing_column_is_file_error():
    with pytest.raises(ImportFileError, match="date_found"): run("asset_name,cve_id\nPayment-DB,CVE-2021-44228\n")

def test_unknown_asset_bad_cve_bad_date_future_date():
    rows, s = run("asset_name,cve_id,date_found\nNope,CVE-2021-44228,2026-10-01\nPayment-DB,CVE-21-1,2026-10-01\nPayment-DB,CVE-2021-44228,01/10/2026\nPayment-DB,CVE-2021-44228,2026-10-13\n")
    assert [r.status for r in rows] == ["error"] * 4
    assert "Unknown asset" in rows[0].reason and "CVE-" in rows[1].reason

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

def test_error_report_blocks_formula_injection():
    rows, _ = run("asset_name,cve_id,date_found\n=HYPERLINK(\"http://x\"),CVE-2021-44228,2026-10-01\n")
    out = problems_to_csv(rows)
    assert "'=HYPERLINK" in out and safe_cell("+1") == "'+1" and safe_cell("ok") == "ok" and safe_cell(None) == ""
