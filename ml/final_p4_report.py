import pandas as pd
import numpy as np
import os
import warnings
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import precision_recall_curve, auc

warnings.simplefilter(action='ignore', category=FutureWarning)

PROCESSED_DIR = os.path.join('data', 'processed')
TODAY = '2026-10-08'

def generate_p4_report():
    print("Loading Train and Validation datasets...")
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

    print("\n==============================================")
    print("       FINAL P4 DIAGNOSTIC REPORT             ")
    print("==============================================")

    # 1. CVSS Score Only Baseline
    lr_cvss = LogisticRegression(max_iter=5000, random_state=42)
    lr_cvss.fit(X_train[['cvss_score']], y_train)
    tr_pr = compute_prauc(y_train, lr_cvss.predict_proba(X_train[['cvss_score']])[:, 1])
    val_pr = compute_prauc(y_val, lr_cvss.predict_proba(X_val[['cvss_score']])[:, 1])
    print(f"1. CVSS Score Only       | Train PR-AUC: {tr_pr:.4f} | Val PR-AUC: {val_pr:.4f}")

    # 2. CVSS Score + Components
    comp_cols = ['cvss_score', 'cvss_missing'] + [c for c in X_train.columns if c.startswith(('AV_', 'AC_', 'PR_', 'UI_'))]
    lr_comp = LogisticRegression(max_iter=5000, random_state=42)
    lr_comp.fit(X_train[comp_cols], y_train)
    tr_pr = compute_prauc(y_train, lr_comp.predict_proba(X_train[comp_cols])[:, 1])
    val_pr = compute_prauc(y_val, lr_comp.predict_proba(X_val[comp_cols])[:, 1])
    print(f"2. + CVSS Components     | Train PR-AUC: {tr_pr:.4f} | Val PR-AUC: {val_pr:.4f}")

    # 3. Core Features + L1 Regularization & Convergence Fix
    lr_l1 = LogisticRegression(penalty='l1', solver='liblinear', C=0.5, max_iter=5000, random_state=42)
    lr_l1.fit(X_train[comp_cols], y_train)
    tr_pr = compute_prauc(y_train, lr_l1.predict_proba(X_train[comp_cols])[:, 1])
    val_pr = compute_prauc(y_val, lr_l1.predict_proba(X_val[comp_cols])[:, 1])
    print(f"3. Core Features + L1    | Train PR-AUC: {tr_pr:.4f} | Val PR-AUC: {val_pr:.4f}")

    print("\n--- Validation Top-K Metrics (Best L1 Model) ---")
    probs_val = lr_l1.predict_proba(X_val[comp_cols])[:, 1]
    df_eval = pd.DataFrame({'true': y_val, 'prob': probs_val})
    df_eval = df_eval.sort_values(by='prob', ascending=False).reset_index(drop=True)
    total_pos = sum(y_val)
    
    for k in [50, 100, 500]:
        subset = df_eval.head(k)
        tp = subset['true'].sum()
        prec = tp / k if k > 0 else 0
        rec = tp / total_pos if total_pos > 0 else 0
        print(f"  K={k:<4} | Precision: {prec:.3f} | Recall: {rec:.3f} | True Positives: {tp}")

if __name__ == '__main__':
    generate_p4_report()
