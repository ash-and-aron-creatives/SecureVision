import pandas as pd
import numpy as np
import requests
import time
import os
import glob
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

def run():
    print("=== P2 KEV TIMING & MISSING DATAPOINTS ===")
    df = pd.read_csv(r'data\processed\master_cves_2026-10-08.csv', low_memory=False)
    df['pub_date'] = pd.to_datetime(df['published_date'], utc=True).dt.date
    df['kev_date'] = pd.to_datetime(df['kev_date_added'], utc=True).dt.date
    
    pos = df[df['in_kev'] == 1].copy()
    pos['gap_days'] = (pos['kev_date'] - pos['pub_date']).apply(lambda x: x.days if pd.notnull(x) else np.nan)
    
    strict_before = pos[pos['gap_days'] < 0]
    same_day = pos[pos['gap_days'] == 0]
    after_1_30 = pos[(pos['gap_days'] > 0) & (pos['gap_days'] <= 30)]
    missing_dates = pos[pos['gap_days'].isna()]
    
    print(f"Total Positives: {len(pos)}")
    print(f"Strictly BEFORE (< 0 days): {len(strict_before)}")
    print(f"Same day (= 0 days): {len(same_day)}")
    print(f"1 to 30 days AFTER (1-30 days): {len(after_1_30)}")
    print(f"Missing/NaT Gap: {len(missing_dates)}")
    print(f"Sum matches total: {len(strict_before) + len(same_day) + len(after_1_30) + len(missing_dates) == len(pos)}")
    
    print("\nGap Histogram (10 bins):")
    print(np.histogram(pos['gap_days'].dropna(), bins=10))

    print("\n=== P2 NVD CHANGE HISTORY (30 Pos / 30 Neg) ===")
    pos_cves = pos.sample(n=30, random_state=42)['cve_id'].tolist()
    neg_cves = df[df['in_kev'] == 0].sample(n=30, random_state=42)['cve_id'].tolist()
    
    headers = {"User-Agent": "SecureVision-Audit/1.0 (Contact: admin@localhost)"}
    
    def check_changes(cve_list, name):
        changed, added_exploit = 0, 0
        exploit_words = ['aware', 'report', 'reports', 'attacks', 'attackers', 'observed', 'wild', 'exploit']
        for cve in cve_list:
            url = f"https://services.nvd.nist.gov/rest/json/cvehistory/2.0?cveId={cve}"
            try:
                time.sleep(2.5) # NVD rate limit
                res = requests.get(url, headers=headers, timeout=10)
                if res.status_code == 200:
                    history = res.json().get('cveChanges', [])
                    for h in history:
                        details = h.get('change', {}).get('details', []) if 'change' in h else h.get('details', [])
                        for detail in details:
                            if 'description' in str(detail.get('action', '')).lower() or 'description' in str(detail.get('type', '')).lower():
                                changed += 1
                                new_val = str(detail.get('newValue', '')).lower()
                                if any(w in new_val for w in exploit_words):
                                    added_exploit += 1
                                break
            except Exception:
                pass
        print(f"{name} -> Checked: {len(cve_list)} | Descriptions Changed: {changed} | Added Exploit Wording: {added_exploit}")
        
    check_changes(pos_cves, "Positives")
    check_changes(neg_cves, "Negatives")
    
    print("\n=== P2 2026 API VOLUME CHECK ===")
    print("Month | API All | API noRejected | Difference")
    for m in range(1, 10):
        ed = 31 if m in [1,3,5,7,8] else (28 if m==2 else 30)
        ed = 8 if m==9 else ed
        base = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate=2026-{m:02d}-01T00:00:00.000&pubEndDate=2026-{m:02d}-{ed:02d}T23:59:59.999&resultsPerPage=1"
        try:
            time.sleep(2.5)
            r_all = requests.get(base, headers=headers, timeout=10).json().get('totalResults', 'Err')
            time.sleep(2.5)
            r_norej = requests.get(base + "&noRejected=true", headers=headers, timeout=10).json().get('totalResults', 'Err')
            print(f"2026-{m:02d} | {r_all:<7} | {r_norej:<12} | {int(r_all) - int(r_norej) if isinstance(r_all, int) and isinstance(r_norej, int) else 'Err'}")
        except Exception as e:
            print(f"2026-{m:02d} | Failed: {e}")

if __name__ == '__main__':
    run()
