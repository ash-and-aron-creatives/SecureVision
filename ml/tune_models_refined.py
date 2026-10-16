import pandas as pd
import numpy as np
import os
import warnings
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_curve, auc

warnings.simplefilter(action='ignore', category=FutureWarning)

PROCESSED_DIR = os.path.join('data', 'processed')
TODAY = '2026-10-08'

def run_refined_tuning():
    print("Loading datasets...")
    train = pd.read_csv(os.path.join(PROCESSED_DIR, f'train_{TODAY}.csv'), low_memory=False)
    val = pd.read_csv(os.path.join(PROCESSED_DIR, f'val_{TODAY}.csv'), low_memory=False)
    
    drop_cols = ['cve_id', 'published_date', 'description', 'cvss_vector', 'kev_date_added', 'days_to_kev', 'in_kev', 'epss', 'percentile', 'year']
    
    X_train = train.drop(columns=[c for c in drop_cols if c in train.columns]).fillna(0)
    y_train = train['in_kev']
    
    X_val = val.drop(columns=[c for c in drop_cols if c in val.columns]).fillna(0)
    y_val = val['in_kev']
    X_val = X_val.reindex(columns=X_train.columns, fill_value=0)

    def compute_prauc(y_true, y_probs):
        precision, recall, _ = precision_recall_curve(y_true, y_probs)
        return auc(recall, precision)

    print("\n--- Testing Core Features with L1 Regularization & Class Balancing ---")
    core_cols = [c for c in ['cvss_score', 'cvss_missing'] + [col for col in X_train.columns if col.startswith(('AV_', 'AC_', 'PR_', 'UI_'))] if c in X_train.columns]
    
    # FIX: Added class_weight='balanced'
    lr_core = LogisticRegression(penalty='l1', solver='liblinear', C=1.0, class_weight='balanced', random_state=42)
    lr_core.fit(X_train[core_cols], y_train)
    probs_core = lr_core.predict_proba(X_val[core_cols])[:, 1]
    
    prauc_core = compute_prauc(y_val, probs_core)
    print(f"Val PR-AUC (Core Features + Balanced L1): {prauc_core:.4f}")

    print("\n--- Top-K Validation Metrics (Balanced Model) ---")
    df_eval = pd.DataFrame({'true': y_val, 'prob': probs_core})
    df_eval = df_eval.sort_values(by='prob', ascending=False).reset_index(drop=True)
    total_pos = sum(y_val)
    
    for k in [50, 100, 500]:
        subset = df_eval.head(k)
        tp = subset['true'].sum()
        prec = tp / k if k > 0 else 0
        rec = tp / total_pos if total_pos > 0 else 0
        print(f"  K={k:<4} | Precision: {prec:.3f} | Recall: {rec:.3f} | True Positives: {tp}")

if __name__ == '__main__':
    run_refined_tuning()
