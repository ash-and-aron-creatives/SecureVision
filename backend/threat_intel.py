import math

import httpx

DEMO_CACHE = {
    "CVE-2021-44228": {"cve_id": "CVE-2021-44228", "epss": 0.995, "cvss": 10.0},
    "CVE-2017-0144": {"cve_id": "CVE-2017-0144", "epss": 0.952, "cvss": 8.1},
    "CVE-2021-26855": {"cve_id": "CVE-2021-26855", "epss": 0.971, "cvss": 9.8},
}


def _result(cve_id: str, epss: float | None, cvss: float | None, errors: list[str]) -> dict:
    return {
        "cve_id": cve_id,
        "epss": epss,
        "cvss": cvss,
        "available": epss is not None and cvss is not None,
        "errors": errors,
    }


async def fetch_cve_data(cve_id: str) -> dict:
    cve_upper = cve_id.upper()
    if cve_upper in DEMO_CACHE:
        cached = DEMO_CACHE[cve_upper]
        return _result(cve_upper, cached["epss"], cached["cvss"], [])

    epss_score = None
    cvss_score = None
    errors = []

    async with httpx.AsyncClient() as client:
        try:
            epss_resp = await client.get(
                f"https://api.first.org/data/v1/epss?cve={cve_upper}",
                timeout=3.0,
            )
            epss_resp.raise_for_status()
            epss_data = epss_resp.json()
        except (httpx.HTTPError, ValueError):
            errors.append("EPSS lookup failed.")
        else:
            results = epss_data.get("data") if isinstance(epss_data, dict) else None
            raw_epss = results[0].get("epss") if (
                isinstance(results, list) and results and isinstance(results[0], dict)
            ) else None
            try:
                parsed_epss = float(raw_epss)
                if not math.isfinite(parsed_epss) or not 0 <= parsed_epss <= 1:
                    raise ValueError
                epss_score = parsed_epss
            except (TypeError, ValueError):
                errors.append("EPSS score is unavailable.")

        try:
            nvd_resp = await client.get(
                f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_upper}",
                timeout=3.0,
            )
            nvd_resp.raise_for_status()
            nvd_data = nvd_resp.json()
        except (httpx.HTTPError, ValueError):
            errors.append("NVD lookup failed.")
        else:
            vulnerabilities = nvd_data.get("vulnerabilities") if isinstance(nvd_data, dict) else None
            metrics = (
                vulnerabilities[0].get("cve", {}).get("metrics", {})
                if isinstance(vulnerabilities, list)
                and vulnerabilities
                and isinstance(vulnerabilities[0], dict)
                and isinstance(vulnerabilities[0].get("cve"), dict)
                else {}
            )
            for metric_name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(metric_name) if isinstance(metrics, dict) else None
                if not isinstance(metric_list, list) or not metric_list or not isinstance(metric_list[0], dict):
                    continue
                cvss_data = metric_list[0].get("cvssData")
                raw_cvss = cvss_data.get("baseScore") if isinstance(cvss_data, dict) else None
                try:
                    parsed_cvss = float(raw_cvss)
                    if not math.isfinite(parsed_cvss) or not 0 <= parsed_cvss <= 10:
                        continue
                    cvss_score = parsed_cvss
                except (TypeError, ValueError):
                    continue
                break
            if cvss_score is None:
                errors.append("NVD CVSS score is unavailable.")

    return _result(cve_upper, epss_score, cvss_score, errors)
