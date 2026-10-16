import pandas as pd
import os
import requests
from datetime import datetime

PROCESSED_DIR = os.path.join('data', 'processed')
RAW_DIR = os.path.join('data', 'raw')
TODAY = datetime.now().strftime('%Y-%m-%d')
MASTER_FILE = os.path.join(PROCESSED_DIR, f'master_cves_{TODAY}.csv')

def run_p2_audit():
    if not os.path.exists(MASTER_FILE):
        print(f"Master file not found at {MASTER_FILE}. Please check your dated filenames.")
        return

    df = pd.read_csv(MASTER_FILE)
    df['published_date'] = pd.to_datetime(df['published_date'], errors='coerce')
    df['kev_date_added'] = pd.to_datetime(df['kev_date_added'], errors='coerce')

    print("=== P2 AUDIT ITEM 1: KEV Before Publication ===")
    # Find records where kev_date_added < published_date
    kev_subset = df[df['in_kev'] == 1].copy()
    anomalies = kev_subset[kev_subset['kev_date_added'] < kev_subset['published_date']]
    print(f"Total Positives: {len(kev_subset)}")
    print(f"Positives with KEV date BEFORE publication date: {len(anomalies)} ({len(anomalies)/len(kev_subset):.1%})")
    
    print("\nPrinting 10 examples of anomalies:")
    for idx, row in anomalies.head(10).iterrows():
        print(f"CVE: {row['cve_id']} | Published: {row['published_date']} | KEV Added: {row['kev_date_added']}")

    print("\n=== P2 AUDIT ITEM 2: Reconciliation Table by Year ===")
    kev_subset['pub_year'] = kev_subset['published_date'].dt.year
    year_counts = kev_subset['pub_year'].value_counts().sort_index()
    print("Positives per publication year in master dataset:")
    print(year_counts)

    print("\n=== P2 AUDIT ITEM 3: Direct NVD API Range Check for 2026 ===")
    # Test NVD API totalResults for 2026
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate=2026-01-01T00:00:00.000&pubEndDate=2026-01-31T23:59:59.999"
    try:
        response = requests.get(url, timeout=15)
        if response.status_code == 200:
            data = response.json()
            print(f"NVD API Direct Check (Jan 2026 totalResults): {data.get('totalResults', 'Unknown')}")
        else:
            print(f"NVD API returned status code {response.status_code}")
    except Exception as e:
        print(f"API check failed due to network: {e}")

if __name__ == '__main__':
    run_p2_audit()
