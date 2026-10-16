import json
import os
import pandas as pd
import ijson

PROCESSED_DIR = os.path.join('data', 'processed')
RAW_DIR = os.path.join('data', 'raw')
TODAY = '2026-10-08'
os.makedirs(PROCESSED_DIR, exist_ok=True)

def build_master():
    print("Extracting valid CVEs from NVD (Filtering 'Rejected')...")
    records = []
    with open(os.path.join(RAW_DIR, f'nvd_cves_{TODAY}.json'), 'rb') as f:
        for item in ijson.items(f, 'item'):
            cve = item.get('cve', {})
            
            # CLAUDE FIX: Drop Rejected
            if cve.get('vulnStatus', '').lower() == 'rejected':
                continue
                
            cve_id = cve.get('id')
            pub_date = cve.get('published')
            
            descriptions = cve.get('descriptions', [])
            desc_text = next((d.get('value', '') for d in descriptions if d.get('lang') == 'en'), "")
                    
            cvss_score, cvss_vector = None, None
            metrics = cve.get('metrics', {})
            if 'cvssMetricV31' in metrics:
                base = metrics['cvssMetricV31'][0].get('cvssData', {})
                cvss_score, cvss_vector = base.get('baseScore'), base.get('vectorString')
            elif 'cvssMetricV30' in metrics:
                base = metrics['cvssMetricV30'][0].get('cvssData', {})
                cvss_score, cvss_vector = base.get('baseScore'), base.get('vectorString')

            cwe = "UNKNOWN"
            weaknesses = cve.get('weaknesses', [])
            if weaknesses and weaknesses[0].get('description'):
                cwe = weaknesses[0]['description'][0].get('value', 'UNKNOWN')

            records.append({
                'cve_id': cve_id, 'published_date': pub_date, 'description': desc_text,
                'cvss_score': cvss_score, 'cvss_vector': cvss_vector, 'cwe': cwe
            })

    df = pd.DataFrame(records)
    df['published_date'] = pd.to_datetime(df['published_date'], utc=True).dt.tz_localize(None)

    print("Loading KEV & EPSS...")
    with open(os.path.join(RAW_DIR, f'kev_catalog_{TODAY}.json'), 'r', encoding='utf-8') as f:
        kev = json.load(f)
    df_kev = pd.DataFrame(kev.get('vulnerabilities', []))[['cveID', 'dateAdded']].rename(columns={'cveID': 'cve_id', 'dateAdded': 'kev_date_added'})
    df_kev['kev_date_added'] = pd.to_datetime(df_kev['kev_date_added'], utc=True).dt.tz_localize(None)
    
    # FIX: Point to the compressed .csv.gz file
    epss_path = os.path.join(RAW_DIR, f'epss_scores_{TODAY}.csv')
    if not os.path.exists(epss_path):
        epss_path += '.gz'
        
    df_epss = pd.read_csv(epss_path, comment='#').rename(columns={'cve': 'cve_id'})

    print("Merging datasets...")
    merged = pd.merge(df, df_kev, on='cve_id', how='left')
    merged = pd.merge(merged, df_epss, on='cve_id', how='left')

    # CLAUDE FIX: Labeling Rule (<= 30 days, including KEV additions before NVD publication)
    merged['days_to_kev'] = (merged['kev_date_added'] - merged['published_date']).dt.days
    merged['in_kev'] = ((merged['days_to_kev'] <= 30) & (merged['kev_date_added'].notna())).astype(int)

    out_path = os.path.join(PROCESSED_DIR, f'master_cves_{TODAY}.csv')
    merged.to_csv(out_path, index=False)
    print(f"Master dataset created with {len(merged)} valid records. Total positives: {merged['in_kev'].sum()}")

if __name__ == '__main__':
    build_master()
