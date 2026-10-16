import json, re, pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer

print('\n--- REGEX MASK MEASUREMENT ---')
d = pd.read_csv(r'data\processed\train_2026-10-08.csv', low_memory=False)
p = r'\b(exploit\w*|attack\w*|actively|zero.?day|ransomware|campaign|threat\sactor|cisa|kev|known|aware|observed|wild|reports?|reportedly)\b'
txt = d['description'].fillna('')

cs = txt.str.contains(re.compile(p)).sum()
ci = txt.str.contains(re.compile(p, re.I)).sum()
print(f'case-sensitive: {cs} | case-insensitive: {ci} | missed by case-sensitive mask: {ci - cs}')

print('\n--- VECTORIZER VOCABULARY TEST ---')
pat_b = re.compile(p, re.IGNORECASE)
tfidf_b = TfidfVectorizer(max_features=100, preprocessor=lambda x: pat_b.sub('', str(x).lower()), stop_words='english', ngram_range=(1,2), min_df=2)
tfidf_b.fit(txt)
vocab = list(tfidf_b.get_feature_names_out())

print(f'Length of TF-IDF vocab: {len(vocab)}')
attack_words = [w for w in vocab if 'attack' in w]
print(f'Attack words remaining in real vectorizer vocab: {attack_words}')

with open('frozen_config.json', 'r') as f:
    c = json.load(f)
print(f"Features in config: {len(c['features'])} | n_features_in: {c.get('n_features_in')}")
print(f"Attack words in config: {[f for f in c['features'] if 'attack' in f]}")
