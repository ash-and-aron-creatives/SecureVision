import pandas as pd
import numpy as np
import os
import warnings
from sklearn.linear_model import LogisticRegression
from xgboost import XGBClassifier
from sklearn.metrics import precision_recall_curve, auc

warnings.simplefilter(action='ignore', category=FutureWarning)

PROCESSED_DIR = os.path.join('data', 'processed')
TODAY = '2026-10-08'

def load_split_data():
    print("Loading Train and Validation sets...")
    train = pd.read_csv(os.path.join(PROCESSED_DIR, f'train_{TODAY}.csv'), low_memory=False)
    val = pd.read_csv(os.path.join(PROCESSED_DIR, f'val_{TODAY}.csv'), low_memory=False)
    
    drop_cols = ['cve_id', 'published_date', 'description', 'cvss_vector', 'kev_date_added', 'days_to_kev', 'in_kev', 'epss', 'percentile', 'year']
    
    X_train = train.drop(columns=[c for c in drop_cols if c in train.columns]).fillna(0)
    y_train = train['in_kev']
    
    X_val = val.drop(columns=[c for c in drop_cols if c in val.columns]).fillna(0)
    y_val = val['in_kev']
    
    # Align columns perfectly
    X_val = X_val.reindex(columns=X_train.columns, fill_value=0)
    return X_train, y_train, X_val, y_val

def compute_prauc(y_true, y_probs):
    precision, recall, _ = precision_recall_curve(y_true, y_probs)
    return auc(recall, precision)

def top_k_metrics(y_true, y_probs, k_list=[50, 100, 500]):
    df_eval = pd.DataFrame({'true': y_true, 'prob': y_probs})
    df_eval = df_eval.sort_values(by='prob', ascending=False).reset_index(drop=True)
    total_positives = sum(y_true)
    
    results = {}
    for k in k_list:
        subset = df_eval.head(k)
        tp = subset['true'].sum()
        precision = tp / k if k > 0 else 0
        recall = tp / total_positives if total_positives > 0 else 0
        results[k] = {'precision': precision, 'recall': recall, 'tp': tp}
    return results

def run_diagnostics():
    X_train, y_train, X_val, y_val = load_split_data()
    
    print("\n--- Step A: Baseline Logistic Regression (CVSS Score Only) ---")
    X_train_cvss = X_train[['cvss_score']]
    X_val_cvss = X_val[['cvss_score']]
    
    lr_cvss = LogisticRegression(random_state=42, max_iter=1000)
    lr_cvss.fit(X_train_cvss, y_train)
    val_probs = lr_cvss.predict_proba(X_val_cvss)[:, 1]
    print(f"Val PR-AUC (CVSS Score Only): {compute_prauc(y_val, val_probs):.4f}")

    print("\n--- Step B: Incremental Feature Addition (Logistic Regression) ---")
    # Group 1: CVSS + Missing + Components
    cvss_cols = ['cvss_score', 'cvss_missing'] + [c for c in X_train.columns if c.startswith(('AV_', 'AC_', 'PR_', 'UI_'))]
    lr_comp = LogisticRegression(random_state=42, max_iter=1000)
    lr_comp.fit(X_train[cvss_cols], y_train)
    print(f"Val PR-AUC (+ CVSS Components): {compute_prauc(y_val, lr_comp.predict_proba(X_val[cvss_cols])[:, 1]):.4f}")

    # Group 2: Adding CWE dummies
    cwe_cols = cvss_cols + [c for c in X_train.columns if c.startswith('cwe_')]
    lr_cwe = LogisticRegression(random_state=42, max_iter=1000)
    lr_cwe.fit(X_train[cwe_cols], y_train)
    print(f"Val PR-AUC (+ CWE Dummies)    : {compute_prauc(y_val, lr_cwe.predict_proba(X_val[cwe_cols])[:, 1]):.4f}")

    # Group 3: Full Feature Set (Including 2000 TF-IDF features)
    lr_full = LogisticRegression(random_state=42, max_iter=1000)
    lr_full.fit(X_train, y_train)
    print(f"Val PR-AUC (All Features)     : {compute_prauc(y_val, lr_full.predict_proba(X_val)[:, 1]):.4f}")

    print("\n--- Step C & D: XGBoost Hyperparameter & Regularization Tuning ---")
    pos_count = y_train.sum()
    neg_count = len(y_train) - pos_count
    full_spw = neg_count / pos_count
    
    # Test different scale_pos_weight and max_depth combinations to prevent overfitting
    configs = [
        {"name": "XGB Default / Full Weight", "spw": full_spw, "max_depth": 6, "reg_lambda": 1},
        {"name": "XGB Moderate Weight (spw=10)", "spw": 10.0, "max_depth": 4, "reg_lambda": 5},
        {"name": "XGB Low Weight (spw=3)", "spw": 3.0, "max_depth": 3, "reg_lambda": 10},
    ]

    for cfg in configs:
        print(f"\nTraining {cfg['name']}...")
        model = XGBClassifier(
            scale_pos_weight=cfg['spw'],
            max_depth=cfg['max_depth'],
            reg_lambda=cfg['reg_lambda'],
            random_state=42,
            n_jobs=-1,
            eval_metric='aucpr'
        )
        model.fit(X_train, y_train)
        
        train_probs = model.predict_proba(X_train)[:, 1]
        val_probs = model.predict_proba(X_val)[:, 1]
        
        train_prauc = compute_prauc(y_train, train_probs)
        val_prauc = compute_prauc(y_val, val_probs)
        print(f"  -> Train PR-AUC: {train_prauc:.4f} | Val PR-AUC: {val_prauc:.4f}")
        
        metrics = top_k_metrics(y_val, val_probs, k_list=[50, 100, 500])
        print("  -> Validation Top-K Metrics:")
        for k, m in metrics.items():
            print(f"     K={k:<4} | Precision: {m['precision']:.3f} | Recall: {m['recall']:.3f} | True Positives: {m['tp']}")

if __name__ == '__main__':
    run_diagnostics()
