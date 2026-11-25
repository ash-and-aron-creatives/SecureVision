import pytest

from backend import cve_dataset


def catalog_record(**overrides):
    record = {
        "cve_id": "CVE-2025-1234",
        "published_date": "2025-01-01",
        "description": "Catalog description",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N",
        "cwe": "CWE-79",
        "kev_date_added": "2025-01-02",
        "epss": 0.3,
        "percentile": 0.9,
        "in_kev": True,
    }
    record.update(overrides)
    return record


@pytest.mark.anyio
async def test_lookup_without_catalog_returns_scoring_keys_as_none(monkeypatch):
    async def live_lookup(_cve_id):
        return {"cvss": None, "epss": None}

    monkeypatch.setattr(cve_dataset, "lookup_catalog", lambda _db, _cve_id: None)

    result = await cve_dataset.lookup_cve_intel(None, "CVE-2025-1234", live_lookup)

    assert result["cvss"] is None
    assert result["epss"] is None
    assert result["epss_percentile"] is None
    assert result["available"] is False


@pytest.mark.anyio
async def test_catalog_gaps_preserve_live_values(monkeypatch):
    async def live_lookup(_cve_id):
        return {
            "cvss": 7.5,
            "epss": 0.3,
            "epss_percentile": 0.82,
            "cwe": "CWE-79",
        }

    monkeypatch.setattr(
        cve_dataset,
        "lookup_catalog",
        lambda _db, _cve_id: catalog_record(percentile=None, cwe=None),
    )

    result = await cve_dataset.lookup_cve_intel(None, "CVE-2025-1234", live_lookup)

    assert result["epss_percentile"] == 0.82
    assert result["cwe"] == "CWE-79"


@pytest.mark.anyio
async def test_complete_catalog_false_kev_does_not_call_live(monkeypatch):
    async def live_lookup(_cve_id):
        pytest.fail("Complete catalog unexpectedly called the live provider.")

    monkeypatch.setattr(
        cve_dataset,
        "lookup_catalog",
        lambda _db, _cve_id: catalog_record(in_kev=False),
    )

    result = await cve_dataset.lookup_cve_intel(None, "CVE-2025-1234", live_lookup)

    assert result["in_kev"] is False
    assert result["source"] == "catalog"


@pytest.mark.anyio
async def test_optional_catalog_gaps_do_not_call_live(monkeypatch):
    async def live_lookup(_cve_id):
        pytest.fail("Optional catalog gap unexpectedly called the live provider.")

    monkeypatch.setattr(
        cve_dataset,
        "lookup_catalog",
        lambda _db, _cve_id: catalog_record(kev_date_added=None),
    )

    result = await cve_dataset.lookup_cve_intel(None, "CVE-2025-1234", live_lookup)

    assert result["source"] == "catalog"
    assert result["kev_date_added"] is None
