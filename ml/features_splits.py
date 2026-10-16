import pandas as pd
import numpy as np
import os
import joblib
import warnings
from sklearn.feature_extraction.text import TfidfVectorizer, ENGLISH_STOP_WORDS

# Suppress Pandas fragmentation warnings
warnings.simplefilter(action='ignore', category=pd.errors.PerformanceWarning)

PROCESSED_DIR = os.path.join('data', 'processed')
MODEL_DIR = os.path.join('ml', 'models')
TODAY = '2026-10-08'
MASTER_FILE = os.path.join(PROCESSED_DIR, f'master_cves_{TODAY}.csv')

def process_features_and_split():
    df = pd.read_csv(MASTER_FILE, low_memory=False)
    df['published_date'] = pd.to_datetime(df['published_date'])
    df['year'] = df['published_date'].dt.year
    
    # CLAUDE FIX: Right-Censoring
    censor_date = pd.to_datetime('2026-09-08')
    df = df[df['published_date'] <= censor_date].copy()
    
    df = df[df['published_date'] >= '2022-01-01'].copy()
    
    print("\n--- CVSS Missing Rate by Year ---")
    for yr in sorted(df['year'].unique()):
        missing_rate = df[df['year'] == yr]['cvss_score'].isna().mean()
        print(f"  {yr}: {missing_rate:.1%}")

    train_mask = df['year'].isin([2022, 2023, 2024])
    val_mask = df['year'] == 2025
    test_mask = df['year'] == 2026
    
    train_df, val_df, test_df = df[train_mask].copy(), df[val_mask].copy(), df[test_mask].copy()
    
    print("\n--- Split Demographics (After Censoring) ---")
    print(f"Train Set: {len(train_df)} rows | Positives: {train_df['in_kev'].sum()}")
    print(f"Val Set  : {len(val_df)} rows | Positives: {val_df['in_kev'].sum()}")
    print(f"Test Set : {len(test_df)} rows | Positives: {test_df['in_kev'].sum()}")

    train_median = train_df['cvss_score'].median()
    for dataset in [train_df, val_df, test_df]:
        dataset['cvss_missing'] = dataset['cvss_score'].isna().astype(int)
        dataset['cvss_score'] = dataset['cvss_score'].fillna(train_median)
        dataset['description'] = dataset['description'].fillna("")

    print("\nFitting TF-IDF (2000 features)...")
    # CLAUDE FIX: Block leakage words
    custom_stops = list(ENGLISH_STOP_WORDS) + ['exploited', 'actively', 'wild', 'cisa', 'kev', 'known']
    tfidf = TfidfVectorizer(max_features=2000, stop_words=custom_stops)
    
    # Fit and calculate top words
    X_tfidf_train = tfidf.fit_transform(train_df['description'])
    weights = np.asarray(X_tfidf_train.sum(axis=0)).flatten()
    top_indices = weights.argsort()[::-1][:30]
    top_words = [tfidf.get_feature_names_out()[i] for i in top_indices]
    
    print("\n--- Top 30 TF-IDF Terms by Weight ---")
    print(", ".join(top_words))

    def parse_cvss_vector(d):
        d['AV'] = d['cvss_vector'].str.extract(r'AV:([NALP])', expand=False).fillna('MISSING')
        d['AC'] = d['cvss_vector'].str.extract(r'AC:([LH])', expand=False).fillna('MISSING')
        d['PR'] = d['cvss_vector'].str.extract(r'PR:([NLH])', expand=False).fillna('MISSING')
        d['UI'] = d['cvss_vector'].str.extract(r'UI:([NR])', expand=False).fillna('MISSING')
        return pd.get_dummies(d, columns=['AV', 'AC', 'PR', 'UI', 'cwe'], dummy_na=False)

    train_df = parse_cvss_vector(train_df)
    val_df, test_df = parse_cvss_vector(val_df), parse_cvss_vector(test_df)
    
    meta_cols = ['cve_id', 'published_date', 'description', 'cvss_vector', 'kev_date_added', 'days_to_kev', 'in_kev', 'epss', 'percentile', 'year']
    model_features = [c for c in train_df.columns if c not in meta_cols]
    for dataset in [val_df, test_df]:
        dataset[model_features] = dataset.reindex(columns=model_features, fill_value=0)

    # Save to disk
    joblib.dump({'tfidf': tfidf, 'median_cvss': train_median}, os.path.join(MODEL_DIR, f'feature_transformers_{TODAY}.joblib'))
    train_df.to_csv(os.path.join(PROCESSED_DIR, f'train_{TODAY}.csv'), index=False)
    val_df.to_csv(os.path.join(PROCESSED_DIR, f'val_{TODAY}.csv'), index=False)
    test_df.to_csv(os.path.join(PROCESSED_DIR, f'test_{TODAY}.csv'), index=False)
    print("\nSaved artifacts and CSVs.")

if __name__ == '__main__':
    process_features_and_split()
