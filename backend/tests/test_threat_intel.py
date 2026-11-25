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
        "epss_percentile": None,
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
    assert result["epss_percentile"] is None
    assert result["cvss"] == 8.2
    assert result["available"] is False
    assert result["errors"] == ["EPSS lookup failed."]
    assert result["description"] == "Test description"
    assert result["cvss_vector"] == "CVSS:3.1/AV:N"
    assert result["cwe"] == "CWE-79"
    assert result["published_date"] == "2025-01-01T00:00Z"


@pytest.mark.anyio
async def test_lookup_returns_first_probability_and_percentile(monkeypatch):
    class Response:
        def __init__(self, payload):
            self.payload = payload

        def raise_for_status(self):
            return None

        def json(self):
            return self.payload

    class Client(FailedClient):
        async def get(self, url, timeout):
            if "epss" in url:
                return Response({"data": [{"epss": "0.30", "percentile": "0.97"}]})
            return Response({"vulnerabilities": [{
                "cve": {
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 0.0}}]},
                },
            }]})

    monkeypatch.setattr(threat_intel.httpx, "AsyncClient", Client)

    result = await threat_intel.fetch_cve_data("CVE-2025-1234")

    assert result["epss"] == 0.30
    assert result["epss_percentile"] == 0.97
    assert result["cvss"] == 0.0
    assert result["available"] is True


@pytest.mark.anyio
@pytest.mark.parametrize("api_key", ("test-nvd-key", None))
async def test_nvd_api_key_is_sent_only_when_configured(monkeypatch, api_key):
    class Response:
        status_code = 200

        def raise_for_status(self):
            return None

        def json(self):
            return {"vulnerabilities": [{
                "cve": {
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.2}}]},
                },
            }]}

    calls = []

    class Client(FailedClient):
        async def get(self, url, **kwargs):
            if "epss" in url:
                return FailedResponse()
            calls.append(kwargs)
            return Response()

    if api_key:
        monkeypatch.setenv("NVD_API_KEY", api_key)
    else:
        monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setattr(threat_intel.httpx, "AsyncClient", Client)

    result = await threat_intel.fetch_cve_data("CVE-2025-1234")

    assert result["cvss"] == 8.2
    if api_key:
        assert calls == [{"timeout": 3.0, "headers": {"apiKey": api_key}}]
    else:
        assert calls == [{"timeout": 3.0}]


@pytest.mark.anyio
async def test_nvd_retries_once_after_rate_limit(monkeypatch):
    class Response:
        def __init__(self, status_code):
            self.status_code = status_code

        def raise_for_status(self):
            if self.status_code >= 400:
                response = httpx.Response(
                    self.status_code,
                    request=httpx.Request("GET", "https://services.nvd.nist.gov/"),
                )
                raise httpx.HTTPStatusError("rate limited", request=response.request, response=response)

        def json(self):
            return {"vulnerabilities": [{
                "cve": {
                    "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.2}}]},
                },
            }]}

    nvd_responses = [Response(429), Response(200)]
    calls = []
    sleeps = []

    class Client(FailedClient):
        async def get(self, url, **kwargs):
            if "epss" in url:
                return FailedResponse()
            calls.append(url)
            return nvd_responses.pop(0)

    async def record_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setattr(threat_intel.httpx, "AsyncClient", Client)
    monkeypatch.setattr(threat_intel.asyncio, "sleep", record_sleep)

    result = await threat_intel.fetch_cve_data("CVE-2025-1234")

    assert len(calls) == 2
    assert sleeps == [2]
    assert result["cvss"] == 8.2
    assert "NVD lookup failed." not in result["errors"]


@pytest.mark.anyio
async def test_nvd_rate_limit_twice_returns_unavailable_result(monkeypatch):
    class Response:
        status_code = 429

        def raise_for_status(self):
            response = httpx.Response(
                self.status_code,
                request=httpx.Request("GET", "https://services.nvd.nist.gov/"),
            )
            raise httpx.HTTPStatusError("rate limited", request=response.request, response=response)

    calls = []

    class Client(FailedClient):
        async def get(self, url, **kwargs):
            if "epss" in url:
                return FailedResponse()
            calls.append(url)
            return Response()

    async def no_wait(seconds):
        return None

    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.setattr(threat_intel.httpx, "AsyncClient", Client)
    monkeypatch.setattr(threat_intel.asyncio, "sleep", no_wait)

    result = await threat_intel.fetch_cve_data("CVE-2025-1234")

    assert len(calls) == 2
    assert result["cvss"] is None
    assert result["available"] is False
    assert result["errors"] == ["EPSS lookup failed.", "NVD lookup failed."]
