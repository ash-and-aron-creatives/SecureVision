import pandas as pd
import numpy as np
import scipy.sparse as sp
import xgboost as xgb
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import average_precision_score
from sklearn.calibration import CalibratedClassifierCV, calibration_curve
import json
import hashlib
import warnings
warnings.filterwarnings('ignore')

def evaluate_at_k(y_true, y_scores, k_list=[50, 100, 500]):
    res = {}
    total_pos = y_true.sum()
    np.random.seed(42)
    jitter = np.random.uniform(0, 1e-9, size=len(y_true))
    idx = np.lexsort((jitter, -y_scores))
    sorted_y = y_true[idx]
    for k in k_list:
        ak = min(k, len(y_true))
        tk = sorted_y[:ak].sum()
        res[f'P@{k}'] = tk / ak if ak > 0 else 0
        res[f'R@{k}'] = tk / total_pos if total_pos > 0 else 0
    return res

def bootstrap_ci(y_true, y_scores):
    rng = np.random.RandomState(42)
    scores = []
    for _ in range(200):
        idx = rng.randint(0, len(y_true), len(y_true))
        if len(np.unique(y_true[idx])) > 1:
            scores.append(average_precision_score(y_true[idx], y_scores[idx]))
    return np.percentile(scores, 2.5), np.percentile(scores, 97.5)

def run():
    print("=== P4 FULL ML ABLATION & CALIBRATION ===")
    train_df = pd.read_csv(r'data\processed\train_2026-10-08.csv', low_memory=False)
    val_df = pd.read_csv(r'data\processed\val_2026-10-08.csv', low_memory=False)
    
    y_train, y_val = train_df['in_kev'].values, val_df['in_kev'].values
    cvss_tr = train_df[['cvss_score']].fillna(6.7).values
    cvss_val = val_df[['cvss_score']].fillna(6.7).values
    
    desc_col = 'description' if 'description' in train_df.columns else train_df.columns[1]
    
    # Text Masking
    exploit_words = ['aware', 'report', 'reports', 'attacks', 'attackers', 'observed', 'wild', 'exploit', 'exploited']
    vendor_words = ['microsoft', 'apple', 'google', 'oracle', 'cisco', 'adobe', 'linux']
    blacklist = list(TfidfVectorizer(stop_words='english').get_stop_words()) + exploit_words
    
    # TF-IDF (Headline: Exploit Masked, Vendors Kept)
    tfidf = TfidfVectorizer(max_features=500, stop_words=blacklist)
    text_tr = tfidf.fit_transform(train_df[desc_col].fillna(''))
    text_val = tfidf.transform(val_df[desc_col].fillna(''))
    
    X_full_tr = sp.hstack([cvss_tr, text_tr])
    X_full_val = sp.hstack([cvss_val, text_val])
    
    # Train Headline Model
    scale_pos = (len(y_train) - y_train.sum()) / y_train.sum()
    clf = xgb.XGBClassifier(max_depth=4, learning_rate=0.03, scale_pos_weight=scale_pos/3, random_state=42, n_estimators=150, eval_metric='aucpr')
    clf.fit(X_full_tr, y_train)
    
    val_preds = clf.predict_proba(X_full_val)[:, 1]
    headline_pr = average_precision_score(y_val, val_preds)
    headline_ci = bootstrap_ci(y_val, val_preds)
    print(f"HEADLINE XGBoost (Exploits Masked, Vendors Kept) | Val PR-AUC: {headline_pr:.4f} CI: [{headline_ci[0]:.4f}-{headline_ci[1]:.4f}]")
    
    # Features check
    feature_names = ['cvss_score'] + list(tfidf.get_feature_names_out())
    scores = clf.get_booster().get_score(importance_type='gain')
    mapped_scores = {feature_names[int(k.replace('f', ''))]: v for k, v in scores.items()}
    top_50 = [f[0] for f in sorted(mapped_scores.items(), key=lambda x: x[1], reverse=True)[:50]]
    
    print("\nTop 50 Features check against Blacklist:")
    violations = [f for f in top_50 if f in blacklist]
    print(f"Violations found: {violations} (Should be empty)")
    print(f"Top 10: {top_50[:10]}")

    print("\n=== CALIBRATION RELIABILITY TABLE (Validation) ===")
    cal_clf = CalibratedClassifierCV(clf, method='sigmoid', cv='prefit')
    cal_clf.fit(X_full_val, y_val)
    cal_preds = cal_clf.predict_proba(X_full_val)[:, 1]
    
    prob_true, prob_pred = calibration_curve(y_val, cal_preds, n_bins=10)
    print("Bin | Mean Predicted Prob | True Fraction of Positives")
    for pt, pp in zip(prob_true, prob_pred):
        print(f"    | {pp:.4f}            | {pt:.4f}")

    print("\n=== FREEZE CONFIG ===")
    config = {
        "timestamp": datetime.now().isoformat(),
        "model": "XGBoost",
        "hyperparameters": clf.get_params(),
        "features": "CVSS + Text (Exploit Blacklist, Vendors Kept)",
        "split_rules": "Train: 2022-2024, Val: 2025, Test: 2026",
        "calibration": "Platt Scaling (Sigmoid)",
        "prospective_holdout": "Active. CVEs published after freeze date form secondary untouched test set."
    }
    config_str = json.dumps(config, indent=2, default=str)
    with open('frozen_config_v2.json', 'w') as f:
        f.write(config_str)
    print("Config Hash:", hashlib.sha256(config_str.encode()).hexdigest())

if __name__ == '__main__':
    run()
