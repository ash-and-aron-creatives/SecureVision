import pandas as pd
import numpy as np
import xgboost as xgb
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score
import os
import joblib
from datetime import datetime

PROCESSED_DIR = os.path.join('data', 'processed')
MODEL_DIR = os.path.join('ml', 'models')
os.makedirs(MODEL_DIR, exist_ok=True)
TODAY = datetime.now().strftime('%Y-%m-%d')

def evaluate_at_k(y_true, y_scores, k_list=[50, 100, 500]):
    results = {}
    df_eval = pd.DataFrame({'true': y_true, 'score': y_scores})
    # Sort descending by score, tie-break randomly
    df_eval = df_eval.sample(frac=1, random_state=42).sort_values(by='score', ascending=False).reset_index(drop=True)
    
    total_pos = sum(y_true)
    for k in k_list:
        actual_k = min(k, len(df_eval))
        top_k = df_eval.head(actual_k)
        precision_k = top_k['true'].sum() / actual_k if actual_k > 0 else 0
        recall_k = top_k['true'].sum() / total_pos if total_pos > 0 else 0
        results[f'P@{k}'] = precision_k
        results[f'R@{k}'] = recall_k
    return results

def run_ablation_study():
    train_df = pd.read_csv(os.path.join(PROCESSED_DIR, f'train_{TODAY}.csv'))
    val_df = pd.read_csv(os.path.join(PROCESSED_DIR, f'val_{TODAY}.csv'))
    
    # Feature engineering derivation on the fly
    for df in [train_df, val_df]:
        df['published_date'] = pd.to_datetime(df['published_date'], errors='coerce')
        df['pub_year'] = df['published_date'].dt.year.fillna(2023).astype(int)
        df['pub_month'] = df['published_date'].dt.month.fillna(1).astype(int)
        df['cvss_score'] = df['cvss_score'].fillna(df['cvss_score'].median())

    target = 'in_kev'
    y_train = train_df[target].values
    y_val = val_df[target].values
    
    # Baselines
    cvss_val_preds = val_df['cvss_score'].values / 10.0
    pr_auc_cvss = average_precision_score(y_val, cvss_val_preds)
    metrics_cvss = evaluate_at_k(y_val, cvss_val_preds)
    
    print(f"CVSS Baseline Val PR-AUC: {pr_auc_cvss:.4f} | P@50: {metrics_cvss['P@50']:.4f}")

    # Ablation Step 1: CVSS score only
    X_train_1 = train_df[['cvss_score']]
    X_val_1 = val_df[['cvss_score']]
    
    pos_count = y_train.sum()
    neg_count = len(y_train) - pos_count
    scale_pos_weight = neg_count / pos_count if pos_count > 0 else 1

    xgb_model = xgb.XGBClassifier(
        max_depth=3,
        learning_rate=0.05,
        scale_pos_weight=scale_pos_weight,
        random_state=42,
        eval_metric='logloss'
    )
    xgb_model.fit(X_train_1, y_train)
    val_preds_1 = xgb_model.predict_proba(X_val_1)[:, 1]
    
    print(f"XGB (CVSS only) Val PR-AUC: {average_precision_score(y_val, val_preds_1):.4f}")

    # Ablation Step 2: CVSS + components (pub_year, pub_month)
    X_train_2 = train_df[['cvss_score', 'pub_year', 'pub_month']]
    X_val_2 = val_df[['cvss_score', 'pub_year', 'pub_month']]
    
    xgb_model.fit(X_train_2, y_train)
    val_preds_2 = xgb_model.predict_proba(X_val_2)[:, 1]
    metrics_2 = evaluate_at_k(y_val, val_preds_2)
    
    print(f"XGB (CVSS + Components) Val PR-AUC: {average_precision_score(y_val, val_preds_2):.4f} | P@50: {metrics_2['P@50']:.4f}")

if __name__ == '__main__':
    run_ablation_study()
