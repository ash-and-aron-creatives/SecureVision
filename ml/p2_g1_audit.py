import pandas as pd
import numpy as np
import requests
import time
import os
import glob
from datetime import datetime
from sklearn.metrics import average_precision_score

os.makedirs(os.path.join('docs', 'logs'), exist_ok=True)
PROCESSED_DIR = os.path.join('data', 'processed')

# Dynamically locate the latest processed files
master_files = sorted(glob.glob(os.path.join(PROCESSED_DIR, 'master_cves_*.csv')))
val_files = sorted(glob.glob(os.path.join(PROCESSED_DIR, 'val_*.csv')))

if not master_files or not val_files:
    raise FileNotFoundError("Master or Val CSV files not found in data/processed/")

MASTER_FILE = master_files[-1]
VAL_FILE = val_files[-1]
print(f"Loading Master: {MASTER_FILE}")
print(f"Loading Val   : {VAL_FILE}")

def run_p2_g1():
    print(f"[{datetime.now().isoformat()}] Starting P2 & G1 Audit")
    df = pd.read_csv(MASTER_FILE, low_memory=False)
    df['dt_published'] = pd.to_datetime(df['published_date'], errors='coerce', utc=True)
    df['dt_kev'] = pd.to_datetime(df['kev_date_added'], errors='coerce', utc=True)
    
    positives = df[df['in_kev'] == 1].copy()
    positives['gap_days'] = (positives['dt_kev'] - positives['dt_published']).dt.days
    
    print("\n--- P2.1a: 10 Random KEV-before-pub Anomalies (Seed 42) ---")
    anomalies = positives[positives['gap_days'] < 0]
    sample = anomalies.sample(n=10, random_state=42)
    for _, r in sample.iterrows():
        print(f"{r['cve_id']} | gap: {r['gap_days']}d | pub: {r['published_date']} | kev: {r['kev_date_added']}")
        
    print("\n--- P2.1b: Anomalies by Year & Gap Distribution ---")
    anomalies['pub_year'] = anomalies['dt_published'].dt.year
    print(anomalies['pub_year'].value_counts().sort_index())
    gaps = anomalies['gap_days'].abs()
    print(f"Gap (days) - Min: {gaps.min()}, Median: {gaps.median()}, 90th: {gaps.quantile(0.9):.1f}, Max: {gaps.max()}")
    
    val_df = pd.read_csv(VAL_FILE, low_memory=False)
    val_df['dt_published'] = pd.to_datetime(val_df['published_date'], errors='coerce', utc=True)
    val_df['dt_kev'] = pd.to_datetime(val_df['kev_date_added'], errors='coerce', utc=True)
    val_cvss = val_df['cvss_score'].fillna(val_df['cvss_score'].median()) / 10.0
    
    mask_genuine = (val_df['dt_kev'] >= val_df['dt_published']) | val_df['dt_kev'].isna()
    mask_leaked = (val_df['dt_kev'] < val_df['dt_published']) | val_df['dt_kev'].isna()
    
    print("\n--- P2.1d: Sensitivity Analysis (CVSS PR-AUC) ---")
    pr_genuine = average_precision_score(val_df.loc[mask_genuine, 'in_kev'], val_cvss[mask_genuine])
    pr_leaked = average_precision_score(val_df.loc[mask_leaked, 'in_kev'], val_cvss[mask_leaked])
    print(f"Genuine Positives (KEV >= Pub): PR-AUC = {pr_genuine:.4f}")
    print(f"Leaked Positives  (KEV < Pub) : PR-AUC = {pr_leaked:.4f}")

    print("\n--- P2.2: 2026 Volume Reconciliation ---")
    print(f"{'Month':<10} | {'API Total':<10} | {'API noReject':<12} | {'Local Kept':<10} | {'Local Reject':<12}")
    
    df_2026 = df[df['dt_published'].dt.year == 2026]
    for m in range(1, 10):
        end_day = 31 if m in [1,3,5,7,8] else (28 if m==2 else 30)
        end_day = 8 if m==9 else end_day
        base_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate=2026-{m:02d}-01T00:00:00.000&pubEndDate=2026-{m:02d}-{end_day:02d}T23:59:59.999&resultsPerPage=1"
        try:
            time.sleep(6)
            res_total = requests.get(base_url, timeout=15).json().get('totalResults', 0)
            time.sleep(6)
            res_norej = requests.get(base_url + "&noRejected=true", timeout=15).json().get('totalResults', 0)
            loc_kept = len(df_2026[df_2026['dt_published'].dt.month == m])
            loc_rej = res_total - res_norej 
            print(f"2026-{m:02d} | {res_total:<10} | {res_norej:<12} | {loc_kept:<10} | {loc_rej:<12}")
        except Exception as e:
            print(f"2026-{m:02d} | API Call Failed: {e}")

    print("\n--- G1: CVSS Baseline Drop Diagnosis ---")
    val_y = val_df['in_kev'].values
    cvss_raw = val_df['cvss_score'].values / 10.0
    cvss_zeroed = val_df['cvss_score'].fillna(0).values / 10.0
    cvss_median = val_df['cvss_score'].fillna(6.7).values / 10.0
    
    print(f"Score with missing=NaN dropped     : {average_precision_score(val_y[~np.isnan(cvss_raw)], cvss_raw[~np.isnan(cvss_raw)]):.4f}")
    print(f"Score with missing=0 imputed       : {average_precision_score(val_y, cvss_zeroed):.4f}")
    print(f"Score with missing=median imputed  : {average_precision_score(val_y, cvss_median):.4f}")

if __name__ == '__main__':
    run_p2_g1()
