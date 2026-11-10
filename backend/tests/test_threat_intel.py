import httpx
import pytest

from backend import threat_intel


class FailedResponse:
    def raise_for_status(self):
        raise httpx.ConnectError("service unavailable")


class FailedClient:
    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    async def get(self, url, timeout):
        return FailedResponse()


@pytest.mark.anyio
async def test_lookup_failures_are_explicit_and_never_zero_scores(monkeypatch):
    monkeypatch.setattr(threat_intel.httpx, "AsyncClient", FailedClient)

    result = await threat_intel.fetch_cve_data("CVE-2025-1234")

    assert result == {
        "cve_id": "CVE-2025-1234",
        "epss": None,
        "cvss": None,
        "available": False,
        "errors": ["EPSS lookup failed.", "NVD lookup failed."],
        "description": None,
        "cvss_vector": None,
        "cwe": None,
        "published_date": None,
    }


@pytest.mark.anyio
async def test_one_provider_failure_preserves_available_score_as_partial(monkeypatch):
    class MixedClient(FailedClient):
        async def get(self, url, timeout):
            if "epss" in url:
                return FailedResponse()

            class Response:
                def raise_for_status(self):
                    return None

                def json(self):
                    return {
                        "vulnerabilities": [{
                            "cve": {
                                "metrics": {
                                    "cvssMetricV31": [{
                                        "cvssData": {
                                            "baseScore": 8.2,
                                            "vectorString": "CVSS:3.1/AV:N",
                                        },
                                    }],
                                },
                                "descriptions": [{"lang": "en", "value": "Test description"}],
                                "weaknesses": [{
                                    "description": [{"lang": "en", "value": "CWE-79"}],
                                }],
                                "published": "2025-01-01T00:00Z",
                            },
                        }],
                    }

            return Response()

    monkeypatch.setattr(threat_intel.httpx, "AsyncClient", MixedClient)

    result = await threat_intel.fetch_cve_data("CVE-2025-1234")

    assert result["epss"] is None
    assert result["cvss"] == 8.2
    assert result["available"] is False
    assert result["errors"] == ["EPSS lookup failed."]
    assert result["description"] == "Test description"
    assert result["cvss_vector"] == "CVSS:3.1/AV:N"
    assert result["cwe"] == "CWE-79"
    assert result["published_date"] == "2025-01-01T00:00Z"
