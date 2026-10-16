import pandas as pd
import numpy as np
import xgboost as xgb
import scipy.sparse as sp
import json
import hashlib
import os
import glob
from datetime import datetime
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import average_precision_score
from sklearn.calibration import CalibratedClassifierCV
import warnings
warnings.filterwarnings('ignore')

PROCESSED_DIR = os.path.join('data', 'processed')
LOG_DIR = os.path.join('docs', 'logs')

train_files = sorted(glob.glob(os.path.join(PROCESSED_DIR, 'train_*.csv')))
val_files = sorted(glob.glob(os.path.join(PROCESSED_DIR, 'val_*.csv')))

if not train_files or not val_files:
    raise FileNotFoundError("Train or Val CSV files missing from data/processed/")

TRAIN_FILE = train_files[-1]
VAL_FILE = val_files[-1]
print(f"Using Train: {TRAIN_FILE}")
print(f"Using Val  : {VAL_FILE}")

def run_g2_g9():
    print(f"[{datetime.now().isoformat()}] Starting G2-G9 Pipeline")
    train_df = pd.read_csv(TRAIN_FILE, low_memory=False)
    val_df = pd.read_csv(VAL_FILE, low_memory=False)
    y_train, y_val = train_df['in_kev'].values, val_df['in_kev'].values
    
    desc_col = 'description' if 'description' in train_df.columns else train_df.columns[1]
    
    print("\n--- G2b: Text Hindsight Leakage Audit ---")
    leak_words = ['aware', 'report', 'reports', 'attacks', 'attackers', 'observed', 'wild', 'exploit', 'exploited']
    pos_desc = train_df[train_df['in_kev'] == 1][desc_col].fillna('').str.lower()
    leaks = pos_desc.apply(lambda x: any(w in x for w in leak_words))
    print(f"Positives containing exploitation leak words: {leaks.sum()} out of {len(pos_desc)} ({leaks.mean():.1%})")
    
    blacklist = list(TfidfVectorizer(stop_words='english').get_stop_words() or []) + leak_words
    
    print("\n--- G2c: Vendor/Product Signal Check ---")
    vendors = ['microsoft', 'apple', 'google', 'oracle', 'cisco', 'adobe', 'linux']
    all_desc = train_df[desc_col].fillna('').str.lower()
    for v in vendors:
        p_pct = pos_desc.str.contains(v).mean()
        a_pct = all_desc.str.contains(v).mean()
        if p_pct > 0.05:
            print(f"  {v:<10}: Positives {p_pct:.1%} | All {a_pct:.1%}")
            blacklist.append(v)

    X1_train = train_df[['cvss_score']].fillna(6.7).values
    X1_val = val_df[['cvss_score']].fillna(6.7).values
    
    tfidf = TfidfVectorizer(max_features=500, stop_words=blacklist)
    X_text_train = tfidf.fit_transform(train_df[desc_col].fillna(''))
    X_text_val = tfidf.transform(val_df[desc_col].fillna(''))
    
    X_full_train = sp.hstack([X1_train, X_text_train])
    X_full_val = sp.hstack([X1_val, X_text_val])

    print("\n--- G3: Tuning with Early Stopping ---")
    scale_pos = (len(y_train) - y_train.sum()) / y_train.sum()
    clf = xgb.XGBClassifier(
        max_depth=4, 
        learning_rate=0.03, 
        min_child_weight=5, 
        subsample=0.8, 
        colsample_bytree=0.8,
        scale_pos_weight=scale_pos/3, 
        random_state=42, 
        n_estimators=500,
        eval_metric='aucpr',
        early_stopping_rounds=20
    )
    clf.fit(X_full_train, y_train, eval_set=[(X_full_val, y_val)], verbose=False)
    print(f"Best Iteration: {clf.best_iteration}")
    train_pr = average_precision_score(y_train, clf.predict_proba(X_full_train)[:, 1])
    val_pr = average_precision_score(y_val, clf.predict_proba(X_full_val)[:, 1])
    print(f"Tuned XGBoost -> Train PR: {train_pr:.4f} | Val PR: {val_pr:.4f}")

    print("\n--- G2a: Top 10 Features by Gain ---")
    booster = clf.get_booster()
    scores = booster.get_score(importance_type='gain')
    feature_names = ['cvss_score'] + list(tfidf.get_feature_names_out())
    mapped_scores = {feature_names[int(k.replace('f', ''))]: v for k, v in scores.items()}
    for feat, gain in sorted(mapped_scores.items(), key=lambda x: x[1], reverse=True)[:10]:
        print(f"  {feat:<20} Gain: {gain:.2f}")

    print("\n--- G8: Probability Calibration ---")
    calibrated_clf = CalibratedClassifierCV(clf, method='sigmoid', cv='prefit')
    calibrated_clf.fit(X_full_val, y_val)
    print("Platt Scaling (Sigmoid) calibrated successfully on validation set.")

    print("\n--- G4/G5: 5-Seed Cumulative Ablation ---")
    results = {'LogReg': [], 'RF': [], 'XGB': []}
    for seed in [42, 100, 200, 300, 400]:
        lr = LogisticRegression(class_weight='balanced', random_state=seed, max_iter=500)
        lr.fit(X_full_train, y_train)
        results['LogReg'].append(average_precision_score(y_val, lr.predict_proba(X_full_val)[:, 1]))
        
        rf = RandomForestClassifier(max_depth=6, class_weight='balanced', random_state=seed, n_estimators=100)
        rf.fit(X_full_train, y_train)
        results['RF'].append(average_precision_score(y_val, rf.predict_proba(X_full_val)[:, 1]))
        
        clf.set_params(random_state=seed)
        clf.fit(X_full_train, y_train, eval_set=[(X_full_val, y_val)], verbose=False)
        results['XGB'].append(average_precision_score(y_val, clf.predict_proba(X_full_val)[:, 1]))

    for model, s in results.items():
        print(f"  {model:<8} +Text (Masked) | Val PR-AUC: {np.mean(s):.4f} +/- {np.std(s):.4f}")

    print("\n--- G9: Freezing Configuration ---")
    params = clf.get_params()
    params.pop('early_stopping_rounds', None)
    config = {
        "timestamp": datetime.now().isoformat(),
        "features": ["cvss_score", "text_tfidf_500"],
        "blacklisted_tokens": blacklist,
        "model_type": "XGBoost",
        "hyperparameters": params,
        "calibration": "Platt Scaling (Sigmoid) on Validation",
        "split_rules": "Strict Chronological (Train 2022-2024, Val 2025, Test 2026)",
        "label_rule": "in_cisa_kev_catalog_horizon_30_days"
    }
    config_str = json.dumps(config, indent=2, default=str)
    with open('frozen_config.json', 'w') as f:
        f.write(config_str)
    config_hash = hashlib.sha256(config_str.encode()).hexdigest()
    print(f"Saved frozen_config.json | SHA-256: {config_hash}")

if __name__ == '__main__':
    run_g2_g9()
