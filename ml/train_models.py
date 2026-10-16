import pandas as pd
import numpy as np
import os
import joblib
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import precision_recall_curve, auc
from datetime import datetime

PROCESSED_DIR = os.path.join('data', 'processed')
MODEL_DIR = os.path.join('ml', 'models')
TODAY = datetime.now().strftime('%Y-%m-%d')

def load_data():
    print("Loading datasets...")
    train = pd.read_csv(os.path.join(PROCESSED_DIR, f'train_{TODAY}.csv'), low_memory=False)
    test = pd.read_csv(os.path.join(PROCESSED_DIR, f'test_{TODAY}.csv'), low_memory=False)
    
    drop_cols = ['cve_id', 'published_date', 'description', 'cvss_vector', 'kev_date_added', 'days_to_kev', 'in_kev', 'epss', 'percentile']
    
    X_train = train.drop(columns=[c for c in drop_cols if c in train.columns]).fillna(0)
    y_train = train['in_kev']
    X_test = test.drop(columns=[c for c in drop_cols if c in test.columns]).fillna(0)
    y_test = test['in_kev']
    
    # FIX: Force X_test to perfectly match X_train's columns and order
    X_test = X_test.reindex(columns=X_train.columns, fill_value=0)
    
    return X_train, y_train, X_test, y_test, test['cvss_score'], test['epss'].fillna(0)

def compute_prauc(y_true, y_probs):
    precision, recall, _ = precision_recall_curve(y_true, y_probs)
    return auc(recall, precision)

def train_and_evaluate():
    print("\n--- Training Models (This will take a few minutes) ---")
    X_train, y_train, X_test, y_test, cvss_baseline, epss_baseline = load_data()
    
    pos_count = y_train.sum()
    neg_count = len(y_train) - pos_count
    spw = neg_count / pos_count if pos_count > 0 else 1
    cw = {0: 1, 1: spw}
    print(f"Applying scale_pos_weight: {spw:.2f}")

    results = {}
    
    print("Training Logistic Regression...")
    lr = LogisticRegression(class_weight=cw, random_state=42, max_iter=1000)
    lr.fit(X_train, y_train)
    results['Logistic Regression'] = compute_prauc(y_test, lr.predict_proba(X_test)[:, 1])
    
    print("Training Random Forest...")
    rf = RandomForestClassifier(n_estimators=100, class_weight=cw, random_state=42, n_jobs=-1)
    rf.fit(X_train, y_train)
    results['Random Forest'] = compute_prauc(y_test, rf.predict_proba(X_test)[:, 1])
    
    print("Training XGBoost...")
    xgb = XGBClassifier(scale_pos_weight=spw, random_state=42, n_jobs=-1, eval_metric='aucpr')
    xgb.fit(X_train, y_train)
    results['XGBoost'] = compute_prauc(y_test, xgb.predict_proba(X_test)[:, 1])
    
    cvss_probs = cvss_baseline / 10.0
    results['CVSS Baseline'] = compute_prauc(y_test, cvss_probs)
    results['EPSS Baseline'] = compute_prauc(y_test, epss_baseline)
    
    print("\n--- Evaluation (PR-AUC) ---")
    print(f"{'Model / Baseline':<25} | {'PR-AUC Score'}")
    print("-" * 40)
    print(f"{'CVSS Baseline':<25} | {results['CVSS Baseline']:.4f}")
    print(f"{'EPSS Baseline':<25} | {results['EPSS Baseline']:.4f}")
    print("-" * 40)
    for model in ['Logistic Regression', 'Random Forest', 'XGBoost']:
        print(f"{model:<25} | {results[model]:.4f}")
        
    model_path = os.path.join(MODEL_DIR, f'xgb_model_{TODAY}.joblib')
    joblib.dump(xgb, model_path)
    
    print(f"\nSaved XGBoost model to {model_path} (Marked as dev placeholder per D-008)")

if __name__ == '__main__':
    train_and_evaluate()
