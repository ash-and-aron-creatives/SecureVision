import datetime, json, os, urllib.request
os.makedirs('data/raw/holdout', exist_ok=True)
ts = datetime.datetime.now(datetime.UTC)
start = (ts - datetime.timedelta(days=1)).strftime('%Y-%m-%dT%H:%M:%S.000Z')
end = ts.strftime('%Y-%m-%dT%H:%M:%S.000Z')
url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate={start}&pubEndDate={end}'
filepath = f'data/raw/holdout/snapshot_{ts.strftime("%Y%m%d")}.json'

try:
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req) as response: data = json.loads(response.read().decode())
    with open(filepath, 'w') as f: json.dump(data, f)
    print(f'Snapshot {filepath} created. Total Results: {data.get("totalResults", 0)}')
except Exception as e:
    print(f'NVD API Error: {e}')
