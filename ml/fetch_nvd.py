import requests
import json
import time
import os
from datetime import datetime

RAW_DIR = os.path.join('data', 'raw')
CHK_DIR = os.path.join(RAW_DIR, 'nvd_chunks')
os.makedirs(CHK_DIR, exist_ok=True)
TODAY = datetime.now().strftime('%Y-%m-%d')
FINAL_FILE = os.path.join(RAW_DIR, f'nvd_cves_{TODAY}.json')

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def fetch_full_nvd():
    print("Resuming full NVD historical download...")
    results_per_page = 2000
    start_index = 0
    total_results = 1 
    
    while start_index < total_results:
        chunk_file = os.path.join(CHK_DIR, f'chunk_{start_index}.json')
        
        if os.path.exists(chunk_file):
            print(f"Index {start_index} already downloaded. Skipping...")
            with open(chunk_file, 'r') as f:
                total_results = json.load(f).get('totalResults', total_results)
            start_index += results_per_page
            continue
            
        url = f"{BASE_URL}?resultsPerPage={results_per_page}&startIndex={start_index}"
        print(f"Fetching index {start_index}...")
        
        retries = 3
        while retries > 0:
            try:
                # ADDED TIMEOUT: Forces a retry if the server hangs
                response = requests.get(url, timeout=30)
                if response.status_code == 403:
                    print("Rate limited. Backing off for 15 seconds...")
                    time.sleep(15)
                    retries -= 1
                    continue
                
                response.raise_for_status()
                data = response.json()
                
                with open(chunk_file, 'w') as f:
                    json.dump(data, f)
                
                total_results = data.get('totalResults', 0)
                break 
                
            except requests.exceptions.RequestException as e:
                print(f"Network error: {e}. Retries left: {retries-1}")
                time.sleep(10)
                retries -= 1
        
        start_index += results_per_page
        time.sleep(6.1)

    print("Consolidating chunks...")
    all_cves = []
    for f_name in os.listdir(CHK_DIR):
        if f_name.endswith('.json'):
            with open(os.path.join(CHK_DIR, f_name), 'r') as f:
                data = json.load(f)
                all_cves.extend(data.get('vulnerabilities', []))
                
    with open(FINAL_FILE, 'w', encoding='utf-8') as f:
        json.dump(all_cves, f)
    print(f"Saved {len(all_cves)} total CVEs to {FINAL_FILE}")

if __name__ == '__main__':
    fetch_full_nvd()
