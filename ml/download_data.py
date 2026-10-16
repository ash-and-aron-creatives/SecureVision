import requests
import os
from datetime import datetime

RAW_DIR = os.path.join("data", "raw")
os.makedirs(RAW_DIR, exist_ok=True)
TODAY = datetime.now().strftime("%Y-%m-%d")

# URLs
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"

def download_file(url, filename):
    print(f"Downloading {filename}...")
    response = requests.get(url, stream=True)
    response.raise_for_status()
    filepath = os.path.join(RAW_DIR, filename)
    with open(filepath, "wb") as f:
        for chunk in response.iter_content(chunk_size=8192):
            f.write(chunk)
    print(f"Saved to {filepath}")

if __name__ == "__main__":
    print("Starting data collection...")
    download_file(KEV_URL, f"kev_catalog_{TODAY}.json")
    download_file(EPSS_URL, f"epss_scores_{TODAY}.csv.gz")
    print("Draft collection complete!")
