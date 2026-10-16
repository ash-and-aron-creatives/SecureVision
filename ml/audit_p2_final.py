import pandas as pd
import requests
import time
import os
import glob
import json
from datetime import datetime

PROCESSED_DIR = os.path.join('data', 'processed')
RAW_DIR = os.path.join('data', 'raw')

def run_p2():
    print(f"[{datetime.now().isoformat()}] Starting P2 Final Audit")
    master_files = sorted(glob.glob(os.path.join(PROCESSED_DIR, 'master_cves_*.csv')))
    df = pd.read_csv(master_files[-1], low_memory=False)
    
    # 1. FIXING THE KEV DATE BUG (Calendar Dates Only)
    df['pub_date'] = pd.to_datetime(df['published_date'], utc=True).dt.date
    df['kev_date'] = pd.to_datetime(df['kev_date_added'], utc=True).dt.date
    
    pos = df[df['in_kev'] == 1].copy()
    pos['gap_days'] = (pos['kev_date'] - pos['pub_date']).apply(lambda x: x.days if pd.notnull(x) else np.nan)
    
    strict_before = pos[pos['gap_days'] < 0]
    same_day = pos[pos['gap_days'] == 0]
    after_1_30 = pos[(pos['gap_days'] > 0) & (pos['gap_days'] <= 30)]
    
    print("\n--- B. KEV Before Publication (Calendar Date Fix) ---")
    print(f"Total Positives: {len(pos)}")
    print(f"Strictly BEFORE publication (< 0 days): {len(strict_before)}")
    print(f"Same day as publication   (= 0 days): {len(same_day)}")
    print(f"1 to 30 days AFTER pub    (1-30 days): {len(after_1_30)}")
    
    print("\nGap Distribution (Days):")
    print(pos['gap_days'].describe(percentiles=[0.5, 0.9]))
    
    print("\nVerify CVE-2026-87491:")
    print(pos[pos['cve_id'] == 'CVE-2026-87491'][['cve_id', 'published_date', 'kev_date_added', 'gap_days']])

    # 2. OFFLINE MISSING KEV CHECK
    print("\n--- A. Offline KEV Missing Check ---")
    kev_files = sorted(glob.glob(os.path.join(RAW_DIR, 'kev_catalog_*.json')))
    with open(kev_files[-1], 'r', encoding='utf-8') as f:
        kev_data = json.load(f)
    
    kev_cves = set(item['cveID'] for item in kev_data.get('vulnerabilities', []))
    master_cves = set(df['cve_id'])
    
    missing_from_master = kev_cves - master_cves
    # Filter missing to our 2022-2026 window for fairness
    missing_relevant = [c for c in missing_from_master if c.startswith('CVE-2022-') or c.startswith('CVE-2023-') or c.startswith('CVE-2024-') or c.startswith('CVE-2025-') or c.startswith('CVE-2026-')]
    print(f"Total KEV CVEs missing from Master (2022-2026 window): {len(missing_relevant)}")
    if missing_relevant:
        print("Sample missing:", missing_relevant[:5])

    # 3. NVD API ROBUST VOLUME CHECK (Jan 2026)
    print("\n--- A. NVD API Volume Check (Robust) ---")
    headers = {"User-Agent": "SecureVision-Audit/1.0"}
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate=2026-01-01T00:00:00.000&pubEndDate=2026-01-31T23:59:59.999&resultsPerPage=1"
    
    try:
        res = requests.get(url, headers=headers, timeout=20)
        print(f"HTTP Status: {res.status_code}")
        print(f"Body (first 200 chars): {res.text[:200]}")
        if res.status_code == 200:
            print(f"API totalResults (January): {res.json().get('totalResults')}")
    except Exception as e:
        print(f"API Request Failed: {e}")

if __name__ == '__main__':
    run_p2()
