import asyncio
import math
import os

import httpx

DEMO_CACHE = {
    "CVE-2021-44228": {
        "cve_id": "CVE-2021-44228",
        "epss": 0.99999,
        "epss_percentile": 1.0,
        "cvss": 10.0,
    },
    "CVE-2017-0144": {
        "cve_id": "CVE-2017-0144",
        "epss": 0.9923,
        "epss_percentile": 0.99935,
        "cvss": 8.1,
    },
    "CVE-2021-26855": {
        "cve_id": "CVE-2021-26855",
        "epss": 0.99996,
        "epss_percentile": 0.99988,
        "cvss": 9.8,
    },
}


def _result(
    cve_id: str,
    epss: float | None,
    epss_percentile: float | None,
    cvss: float | None,
    errors: list[str],
    description: str | None = None,
    cvss_vector: str | None = None,
    cwe: str | None = None,
    published_date: str | None = None,
) -> dict:
    return {
        "cve_id": cve_id,
        "epss": epss,
        "epss_percentile": epss_percentile,
        "cvss": cvss,
        "available": (
            epss is not None
            and epss_percentile is not None
            and cvss is not None
        ),
        "errors": errors,
        "description": description,
        "cvss_vector": cvss_vector,
        "cwe": cwe,
        "published_date": published_date,
    }


async def _fetch_nvd_response(client: httpx.AsyncClient, cve_id: str) -> httpx.Response:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    api_key = os.getenv("NVD_API_KEY")
    if api_key:
        response = await client.get(url, timeout=3.0, headers={"apiKey": api_key})
    else:
        response = await client.get(url, timeout=3.0)
    if getattr(response, "status_code", None) in (429, 503):
        await asyncio.sleep(2)
        if api_key:
            response = await client.get(url, timeout=3.0, headers={"apiKey": api_key})
        else:
            response = await client.get(url, timeout=3.0)
    return response


async def fetch_cve_data(cve_id: str) -> dict:
    cve_upper = cve_id.upper()
    if cve_upper in DEMO_CACHE:
        cached = DEMO_CACHE[cve_upper]
        return _result(
            cve_upper,
            cached["epss"],
            cached.get("epss_percentile"),
            cached["cvss"],
            [],
        )

    epss_score = None
    epss_percentile = None
    cvss_score = None
    errors = []
    description = None
    cvss_vector = None
    cwe = None
    published_date = None

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
            epss_record = results[0] if (
                isinstance(results, list) and results and isinstance(results[0], dict)
            ) else {}
            raw_epss = epss_record.get("epss")
            try:
                parsed_epss = float(raw_epss)
                if not math.isfinite(parsed_epss) or not 0 <= parsed_epss <= 1:
                    raise ValueError
                epss_score = parsed_epss
            except (TypeError, ValueError):
                errors.append("EPSS score is unavailable.")
            raw_percentile = epss_record.get("percentile")
            try:
                parsed_percentile = float(raw_percentile)
                if not math.isfinite(parsed_percentile) or not 0 <= parsed_percentile <= 1:
                    raise ValueError
                epss_percentile = parsed_percentile
            except (TypeError, ValueError):
                errors.append("EPSS percentile is unavailable.")

        try:
            nvd_resp = await _fetch_nvd_response(client, cve_upper)
            nvd_resp.raise_for_status()
            nvd_data = nvd_resp.json()
        except (httpx.HTTPError, ValueError):
            errors.append("NVD lookup failed.")
        else:
            vulnerabilities = nvd_data.get("vulnerabilities") if isinstance(nvd_data, dict) else None
            cve_record = (
                vulnerabilities[0].get("cve")
                if isinstance(vulnerabilities, list)
                and vulnerabilities
                and isinstance(vulnerabilities[0], dict)
                and isinstance(vulnerabilities[0].get("cve"), dict)
                else {}
            )
            published = cve_record.get("published")
            published_date = published if isinstance(published, str) else None
            descriptions = cve_record.get("descriptions")
            if isinstance(descriptions, list):
                description = next(
                    (
                        item["value"]
                        for item in descriptions
                        if isinstance(item, dict)
                        and item.get("lang") == "en"
                        and isinstance(item.get("value"), str)
                        and item["value"].strip()
                    ),
                    None,
                )
            weaknesses = cve_record.get("weaknesses")
            if isinstance(weaknesses, list):
                for weakness in weaknesses:
                    weakness_descriptions = weakness.get("description") if isinstance(weakness, dict) else None
                    if not isinstance(weakness_descriptions, list):
                        continue
                    cwe = next(
                        (
                            item["value"]
                            for item in weakness_descriptions
                            if isinstance(item, dict)
                            and isinstance(item.get("value"), str)
                            and item["value"].startswith(("CWE-", "NVD-CWE-"))
                        ),
                        None,
                    )
                    if cwe:
                        break
            metrics = (
                cve_record.get("metrics", {})
            )
            for metric_name in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metric_list = metrics.get(metric_name) if isinstance(metrics, dict) else None
                if not isinstance(metric_list, list) or not metric_list or not isinstance(metric_list[0], dict):
                    continue
                cvss_data = metric_list[0].get("cvssData")
                raw_cvss = cvss_data.get("baseScore") if isinstance(cvss_data, dict) else None
                raw_vector = cvss_data.get("vectorString") if isinstance(cvss_data, dict) else None
                try:
                    parsed_cvss = float(raw_cvss)
                    if not math.isfinite(parsed_cvss) or not 0 <= parsed_cvss <= 10:
                        continue
                    cvss_score = parsed_cvss
                    cvss_vector = raw_vector if isinstance(raw_vector, str) else None
                except (TypeError, ValueError):
                    continue
                break
            if cvss_score is None:
                errors.append("NVD CVSS score is unavailable.")

    return _result(
        cve_upper,
        epss_score,
        epss_percentile,
        cvss_score,
        errors,
        description,
        cvss_vector,
        cwe,
        published_date,
    )
