import httpx

# OFFLINE DEMO CACHE: Guarantees lightning-fast, network-independent results during presentation
DEMO_CACHE = {
    "CVE-2021-44228": {"cve_id": "CVE-2021-44228", "epss": 0.995, "cvss": 10.0}, # Log4j
    "CVE-2017-0144": {"cve_id": "CVE-2017-0144", "epss": 0.952, "cvss": 8.1},    # EternalBlue
    "CVE-2021-26855": {"cve_id": "CVE-2021-26855", "epss": 0.971, "cvss": 9.8}   # ProxyLogon
}

async def fetch_cve_data(cve_id: str):
    cve_upper = cve_id.upper()
    
    # 1. Check local cache first for demo safety
    if cve_upper in DEMO_CACHE:
        return DEMO_CACHE[cve_upper]

    epss_score = 0.0
    cvss_score = 0.0

    # 2. Fetch Predictive AI Data from FIRST.org (with short timeout)
    try:
        async with httpx.AsyncClient() as client:
            epss_resp = await client.get(f"https://api.first.org/data/v1/epss?cve={cve_id}", timeout=3.0)
            if epss_resp.status_code == 200:
                data = epss_resp.json()
                if "data" in data and len(data["data"]) > 0:
                    epss_score = float(data["data"][0].get("epss", 0.0))
    except Exception:
        pass

    # 3. Fetch Base CVSS from US Government NVD Database (with short timeout)
    try:
        async with httpx.AsyncClient() as client:
            nvd_resp = await client.get(f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}", timeout=3.0)
            if nvd_resp.status_code == 200:
                data = nvd_resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    metrics = vulns[0].get("cve", {}).get("metrics", {})
                    if "cvssMetricV31" in metrics:
                        cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV30" in metrics:
                        cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                    elif "cvssMetricV2" in metrics:
                        cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]
    except Exception:
        pass

    return {"cve_id": cve_id, "epss": epss_score, "cvss": cvss_score}
