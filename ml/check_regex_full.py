import re, json, pandas as pd

with open('frozen_config.json', 'r') as f: config = json.load(f)
print(f"Config Features: {len(config['features'])} | n_features_in: {config.get('n_features_in')}")

p = r'\b(exploit\w*|attack\w*|actively|zero.?day|ransomware|campaign|threat\sactor|cisa|kev|known|aware|observed|wild|reports?|reportedly)\b'
pat_b = re.compile(p, re.IGNORECASE)

vocab = config['features'][52:] # TF-IDF terms
matches = [w for w in vocab if pat_b.search(w)]
print(f"Full regex matches remaining in config vocabulary: {matches}")

d = pd.read_csv(r'data\processed\train_2026-10-08.csv', low_memory=False)
desc_col = 'description' if 'description' in d.columns else d.columns[1]
masked_text = d[desc_col].fillna('').apply(lambda x: pat_b.sub('', str(x).lower()))

print('\nMatches remaining in masked training text per pattern (Expect 0):')
patterns = p.replace('\b', '').replace('(', '').replace(')', '').split('|')
for pat in patterns:
    c = masked_text.str.contains(re.compile(r'\b'+pat+r'\b', re.IGNORECASE)).sum()
    print(f"  {pat}: {c}")
