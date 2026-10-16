"""
P2 Deep Audit Script — SecureVision
Addresses reviewer items:
  1. KEV-before-publication: 10 printed examples with raw strings, source field names,
     timezone/format check, plus a note to hand-check 5 against the CISA KEV catalog.
  2. 2026 volume: NVD API chunked queries (≤120 days each, resultsPerPage=1) for
     monthly totalResults Jan–Sep 2026 vs. local raw file counts.
  3. EPSS provenance: file names, dates, join method, 5 example rows labelled
     "hindsight (today's file)".

Run:  .\venv\Scripts\python.exe ml/audit_p2_strict.py
"""

import json
import os
import sys
import gzip
import time
from datetime import datetime, date, timedelta

import pandas as pd
import requests

# ── paths ──────────────────────────────────────────────────────────────────
RAW_DIR = os.path.join("data", "raw")
PROCESSED_DIR = os.path.join("data", "processed")
TODAY = "2026-10-08"
MASTER_FILE = os.path.join(PROCESSED_DIR, f"master_cves_{TODAY}.csv")
NVD_FILE = os.path.join(RAW_DIR, f"nvd_cves_{TODAY}.json")
KEV_FILE = os.path.join(RAW_DIR, f"kev_catalog_{TODAY}.json")
EPSS_FILE_GZ = os.path.join(RAW_DIR, f"epss_scores_{TODAY}.csv.gz")
EPSS_FILE_CSV = os.path.join(RAW_DIR, f"epss_scores_{TODAY}.csv")

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
NVD_API_KEY = os.environ.get("NVD_API_KEY", "")  # optional; improves rate limits

# ── helpers ────────────────────────────────────────────────────────────────
SEPARATOR = "=" * 80


def load_master():
    if not os.path.exists(MASTER_FILE):
        print(f"ERROR: Master file not found: {MASTER_FILE}", file=sys.stderr)
        sys.exit(1)
    df = pd.read_csv(MASTER_FILE, low_memory=False)
    df["published_date"] = pd.to_datetime(df["published_date"], errors="coerce")
    df["kev_date_added"] = pd.to_datetime(df["kev_date_added"], errors="coerce")
    return df


def nvd_api_total(start_date: str, end_date: str) -> int | None:
    """
    Query NVD API for totalResults in a date range.
    NVD enforces max 120-day windows.  We use resultsPerPage=1 to minimize payload.
    """
    params = {
        "pubStartDate": f"{start_date}T00:00:00.000",
        "pubEndDate": f"{end_date}T23:59:59.999",
        "resultsPerPage": 1,
    }
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    for attempt in range(3):
        try:
            resp = requests.get(NVD_API_BASE, params=params, headers=headers, timeout=30)
            if resp.status_code == 200:
                return resp.json().get("totalResults")
            elif resp.status_code == 403:
                wait = 6 * (attempt + 1)
                print(f"  [rate-limited, retrying in {wait}s]")
                time.sleep(wait)
            else:
                print(f"  [HTTP {resp.status_code}] {resp.text[:200]}")
                return None
        except requests.RequestException as e:
            print(f"  [network error: {e}]")
            time.sleep(5)
    return None


# ══════════════════════════════════════════════════════════════════════════
#  ITEM 1 — KEV Before Publication: 10 examples, raw strings, TZ check
# ══════════════════════════════════════════════════════════════════════════
def audit_kev_anomalies(df: pd.DataFrame):
    print(SEPARATOR)
    print("P2 ITEM 1: KEV-before-publication anomalies")
    print(SEPARATOR)

    # ── Source field names ──
    print("\nSource field names in raw files:")
    print(f"  NVD JSON:  cve -> published            (file: {NVD_FILE})")
    print(f"  KEV JSON:  vulnerabilities -> dateAdded (file: {KEV_FILE})")
    print(f"  Master CSV columns: published_date, kev_date_added")

    # ── Timezone / format check on raw files ──
    print("\n--- Timezone & format check (raw NVD) ---")
    try:
        import ijson
        sample_ts = []
        with open(NVD_FILE, "rb") as f:
            for i, item in enumerate(ijson.items(f, "item")):
                pub = item.get("cve", {}).get("published", "")
                if pub:
                    sample_ts.append(pub)
                if len(sample_ts) >= 5:
                    break
        for ts in sample_ts:
            print(f"  raw NVD 'published' string: {ts!r}")
    except Exception as e:
        print(f"  (could not stream NVD JSON: {e})")

    print("\n--- Timezone & format check (raw KEV) ---")
    try:
        with open(KEV_FILE, "r", encoding="utf-8") as f:
            kev_data = json.load(f)
        kev_vulns = kev_data.get("vulnerabilities", [])
        for v in kev_vulns[:5]:
            print(f"  raw KEV 'dateAdded' string: {v.get('dateAdded')!r}  (cveID: {v.get('cveID')})")
    except Exception as e:
        print(f"  (could not load KEV JSON: {e})")

    # ── Identify anomalies in master ──
    positives = df[df["in_kev"] == 1].copy()
    anomalies = positives[positives["kev_date_added"] < positives["published_date"]].copy()
    anomalies["gap_days"] = (anomalies["published_date"] - anomalies["kev_date_added"]).dt.days

    print(f"\nTotal in_kev=1 positives:              {len(positives)}")
    print(f"Positives where KEV date < published:  {len(anomalies)}")

    print("\n--- 10 examples (cve_id, published, kev_date_added, raw strings) ---")
    sample = anomalies.head(10)
    # Re-read raw strings from KEV JSON for these CVEs
    kev_raw_map = {}
    try:
        with open(KEV_FILE, "r", encoding="utf-8") as f:
            kev_data = json.load(f)
        for v in kev_data.get("vulnerabilities", []):
            kev_raw_map[v["cveID"]] = v.get("dateAdded", "")
    except Exception:
        pass

    # Re-read raw NVD published strings for these CVEs
    nvd_raw_map = {}
    try:
        import ijson
        target_cves = set(sample["cve_id"].tolist())
        with open(NVD_FILE, "rb") as f:
            for item in ijson.items(f, "item"):
                cve_obj = item.get("cve", {})
                cid = cve_obj.get("id", "")
                if cid in target_cves:
                    nvd_raw_map[cid] = cve_obj.get("published", "")
                    if len(nvd_raw_map) == len(target_cves):
                        break
    except Exception:
        pass

    for _, row in sample.iterrows():
        cid = row["cve_id"]
        raw_pub = nvd_raw_map.get(cid, "(not found)")
        raw_kev = kev_raw_map.get(cid, "(not found)")
        print(
            f"  {cid:20s} | published (parsed): {row['published_date']} | "
            f"kev_date_added (parsed): {row['kev_date_added']} | "
            f"gap: {row['gap_days']:.0f}d"
        )
        print(
            f"  {'':20s} | raw NVD published: {raw_pub!r} | "
            f"raw KEV dateAdded: {raw_kev!r}"
        )

    print(
        "\n>>> HAND-CHECK: Verify the first 5 CVEs above against "
        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
    )
    for _, row in sample.head(5).iterrows():
        print(f"    {row['cve_id']} — expected dateAdded: {kev_raw_map.get(row['cve_id'], '?')}")


# ══════════════════════════════════════════════════════════════════════════
#  ITEM 2 — 2026 volume: NVD API monthly counts vs. local raw file
# ══════════════════════════════════════════════════════════════════════════
def audit_2026_volume(df: pd.DataFrame):
    print(f"\n{SEPARATOR}")
    print("P2 ITEM 2: 2026 monthly volume — NVD API vs. local raw file")
    print(SEPARATOR)

    # ── Local counts from master ──
    df2026 = df[df["published_date"].dt.year == 2026].copy()
    df2026["month"] = df2026["published_date"].dt.month
    local_counts = df2026.groupby("month").size()

    print(f"\nLocal file: {MASTER_FILE}")
    print(f"Total 2026 rows in master: {len(df2026)}")

    # ── NVD API counts, chunked ≤120 days per request ──
    # For monthly queries each chunk is ≤31 days, well within the 120-day limit.
    print("\nQuerying NVD API (resultsPerPage=1, reading totalResults) ...")
    print(f"{'Month':>7s}  {'API totalResults':>17s}  {'Local count':>13s}  {'Delta':>7s}")
    print("-" * 52)

    api_counts = {}
    # Query Jan through Sep 2026 (we have data up to censoring date 2026-09-08)
    for m in range(1, 10):
        start = date(2026, m, 1)
        if m == 9:
            end = date(2026, 9, 8)  # censoring date
        elif m < 12:
            end = date(2026, m + 1, 1) - timedelta(days=1)
        else:
            end = date(2026, 12, 31)

        api_total = nvd_api_total(start.isoformat(), end.isoformat())
        api_counts[m] = api_total
        local_val = int(local_counts.get(m, 0))
        delta = f"{api_total - local_val:+d}" if api_total is not None else "N/A"
        api_str = str(api_total) if api_total is not None else "ERROR"
        print(f"  2026-{m:02d}  {api_str:>17s}  {local_val:>13d}  {delta:>7s}")

        # Respect NVD rate limit (6 req/min without key, 50/30s with key)
        if not NVD_API_KEY:
            time.sleep(6)
        else:
            time.sleep(0.6)

    api_grand = sum(v for v in api_counts.values() if v is not None)
    local_grand = int(local_counts.sum())
    print("-" * 52)
    print(f"  {'TOTAL':>7s}  {api_grand:>17d}  {local_grand:>13d}  {api_grand - local_grand:>+7d}")

    print(
        "\nNote: local counts may differ from API if (a) Rejected CVEs are excluded "
        "in our pipeline, or (b) NVD published new CVEs after our download date."
    )


# ══════════════════════════════════════════════════════════════════════════
#  ITEM 3 — EPSS: file names, dates, join method, 5 examples
# ══════════════════════════════════════════════════════════════════════════
def audit_epss():
    print(f"\n{SEPARATOR}")
    print("P2 ITEM 3: EPSS provenance — files, join method, 5 example rows")
    print(SEPARATOR)

    # ── Identify which file exists ──
    if os.path.exists(EPSS_FILE_GZ):
        epss_path = EPSS_FILE_GZ
    elif os.path.exists(EPSS_FILE_CSV):
        epss_path = EPSS_FILE_CSV
    else:
        print(f"ERROR: No EPSS file found at {EPSS_FILE_GZ} or {EPSS_FILE_CSV}")
        return

    file_size = os.path.getsize(epss_path)
    file_mtime = datetime.fromtimestamp(os.path.getmtime(epss_path)).isoformat()

    print(f"\nEPSS file used:    {epss_path}")
    print(f"File size:         {file_size:,} bytes")
    print(f"Last modified:     {file_mtime}")

    # ── Show header / comment lines ──
    print("\n--- Raw file header (first 5 lines) ---")
    if epss_path.endswith(".gz"):
        opener = gzip.open
    else:
        opener = open
    with opener(epss_path, "rt", encoding="utf-8") as fh:
        for i, line in enumerate(fh):
            if i >= 5:
                break
            print(f"  line {i}: {line.rstrip()!r}")

    # ── Load and show join method ──
    df_epss = pd.read_csv(epss_path, comment="#")
    print(f"\nEPSS DataFrame shape: {df_epss.shape}")
    print(f"EPSS columns:         {list(df_epss.columns)}")

    # Determine the CVE column name
    cve_col = "cve" if "cve" in df_epss.columns else df_epss.columns[0]
    print(f"CVE column used for join: '{cve_col}' -> renamed to 'cve_id'")
    df_epss = df_epss.rename(columns={cve_col: "cve_id"})

    print("\nJoin method: LEFT JOIN on cve_id (master LEFT JOIN epss)")
    print("  - This means CVEs without an EPSS score get NaN.")

    # ── 5 example rows ──
    print("\n--- 5 example EPSS rows (labelled: hindsight, today's file) ---")
    epss_col = "epss" if "epss" in df_epss.columns else df_epss.columns[1]
    pctl_col = "percentile" if "percentile" in df_epss.columns else (
        df_epss.columns[2] if len(df_epss.columns) > 2 else None
    )

    sample = df_epss.head(5)
    print(f"  {'cve_id':20s}  {'epss (hindsight)':>20s}  {'percentile (hindsight)':>24s}")
    for _, row in sample.iterrows():
        ep = f"{row[epss_col]:.5f}" if pd.notna(row.get(epss_col)) else "NaN"
        pc = f"{row[pctl_col]:.5f}" if pctl_col and pd.notna(row.get(pctl_col)) else "NaN"
        print(f"  {row['cve_id']:20s}  {ep:>20s}  {pc:>24s}")

    print(
        "\n>>> ALL EPSS numbers in this project are HINDSIGHT values from "
        f"the file downloaded on {TODAY}. They reflect EPSS model scores "
        "as of that date, not as of each CVE's publication date."
    )


# ══════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════
def main():
    print(f"P2 STRICT AUDIT — {datetime.now().isoformat()}")
    print(f"Working directory: {os.getcwd()}")
    print(f"Master file:       {MASTER_FILE}")
    print()

    df = load_master()
    audit_kev_anomalies(df)
    audit_2026_volume(df)
    audit_epss()

    print(f"\n{SEPARATOR}")
    print("P2 STRICT AUDIT COMPLETE")
    print(SEPARATOR)


if __name__ == "__main__":
    main()

