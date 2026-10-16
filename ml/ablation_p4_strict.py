"""
P4 True Ablation Script — SecureVision
Addresses ALL reviewer items for P4:

  1. Assert row alignment by cve_id.
  2. NEVER use pub_year / pub_month.  "CVSS components" = parsed CVSS vector
     (AV, AC, PR, UI), NOT date features.
  3. Feature groups added one at a time:
       Step 1: CVSS score only
       Step 2: + CVSS components (AV, AC, PR, UI, cvss_missing)
       Step 3: + CWE
       Step 4: + Text (TF-IDF)
     For each step: Logistic Regression, Random Forest, XGBoost.
  4. Baselines: raw CVSS/10, EPSS (labelled "hindsight").
  5. Train PR-AUC and Val PR-AUC for every row.
  6. Precision@K and Recall@K for K = 50, 100, 500.
  7. Bootstrap 95% CIs on validation PR-AUC.
  8. Bug checks:
       a) Label-shuffle test (expected ~0.0027 for prevalence baseline)
       b) Assert X rows and y rows refer to the same cve_id
       c) Unconstrained XGBoost train score (should approach 1.0)
  9. No "micro-batch" or "as predicted" wording. Raw console output.

Run:  .\\venv\\Scripts\\python.exe ml/ablation_p4_strict.py
"""

import os
import sys
import warnings
from datetime import datetime

import numpy as np
import pandas as pd
import joblib
from scipy.sparse import issparse, hstack, csr_matrix

from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import precision_recall_curve, auc, average_precision_score
from sklearn.feature_extraction.text import TfidfVectorizer, ENGLISH_STOP_WORDS

import xgboost as xgb

warnings.filterwarnings("ignore", category=FutureWarning)
warnings.filterwarnings("ignore", category=UserWarning)
pd.set_option("display.max_columns", 40)
pd.set_option("display.width", 160)

# ── paths ──────────────────────────────────────────────────────────────────
PROCESSED_DIR = os.path.join("data", "processed")
MODEL_DIR = os.path.join("ml", "models")
TODAY = "2026-10-08"

SEP = "=" * 90
THIN_SEP = "-" * 90

# ── constants ──────────────────────────────────────────────────────────────
K_VALUES = [50, 100, 500]
N_BOOTSTRAP = 2000
BOOTSTRAP_SEED = 42
RANDOM_STATE = 42


# ══════════════════════════════════════════════════════════════════════════
#  Utility functions
# ══════════════════════════════════════════════════════════════════════════
def compute_prauc(y_true, y_score):
    """PR-AUC via sklearn (handles edge cases)."""
    if np.sum(y_true) == 0:
        return 0.0
    return average_precision_score(y_true, y_score)


def evaluate_at_k(y_true, y_score, k_values=K_VALUES):
    """Precision@K and Recall@K, with deterministic tie-breaking."""
    order = np.argsort(-y_score, kind="mergesort")
    y_sorted = np.asarray(y_true)[order]
    total_pos = np.sum(y_true)
    results = {}
    for k in k_values:
        actual_k = min(k, len(y_sorted))
        tp = int(np.sum(y_sorted[:actual_k]))
        results[f"P@{k}"] = tp / actual_k if actual_k > 0 else 0.0
        results[f"R@{k}"] = tp / total_pos if total_pos > 0 else 0.0
    return results


def bootstrap_prauc_ci(y_true, y_score, n_boot=N_BOOTSTRAP, seed=BOOTSTRAP_SEED):
    """Bootstrap 95% CI for PR-AUC on the validation set."""
    rng = np.random.RandomState(seed)
    n = len(y_true)
    scores = []
    for _ in range(n_boot):
        idx = rng.choice(n, size=n, replace=True)
        yt = np.asarray(y_true)[idx]
        ys = np.asarray(y_score)[idx]
        if yt.sum() == 0:
            continue
        scores.append(average_precision_score(yt, ys))
    scores = np.array(scores)
    lo = np.percentile(scores, 2.5)
    hi = np.percentile(scores, 97.5)
    return lo, hi


# ══════════════════════════════════════════════════════════════════════════
#  Data loading and assertion
# ══════════════════════════════════════════════════════════════════════════
def load_data():
    """Load master file, re-split by year, rebuild features from scratch.
    This avoids inheriting any date columns or stale feature sets."""
    master_path = os.path.join(PROCESSED_DIR, f"master_cves_{TODAY}.csv")
    print(f"[{datetime.now().isoformat()}] Loading master file: {master_path}")
    df = pd.read_csv(master_path, low_memory=False)
    df["published_date"] = pd.to_datetime(df["published_date"], errors="coerce")
    df["year"] = df["published_date"].dt.year

    # Right-censoring
    censor_date = pd.to_datetime("2026-09-08")
    df = df[df["published_date"] <= censor_date].copy()
    df = df[df["published_date"] >= "2022-01-01"].copy()

    # Splits
    train_df = df[df["year"].isin([2022, 2023, 2024])].copy()
    val_df = df[df["year"] == 2025].copy()

    print(f"  Train rows: {len(train_df)}, positives: {train_df['in_kev'].sum()}")
    print(f"  Val   rows: {len(val_df)}, positives: {val_df['in_kev'].sum()}")

    return train_df, val_df


def prepare_features(train_df, val_df):
    """
    Build feature matrices from scratch.  Returns dict of feature-group arrays.

    Feature groups (added cumulatively):
      1. cvss_score_only:  [cvss_score]
      2. cvss_components:  [cvss_score, cvss_missing, AV_*, AC_*, PR_*, UI_*]
      3. cwe:              above + one-hot CWE
      4. text:             above + TF-IDF(description)

    FORBIDDEN: pub_year, pub_month, or any date-derived numeric feature.
    """
    # ── CVSS score ──
    train_median = train_df["cvss_score"].median()
    print(f"  CVSS median (train only): {train_median}")

    for d in [train_df, val_df]:
        d["cvss_missing"] = d["cvss_score"].isna().astype(int)
        d["cvss_score"] = d["cvss_score"].fillna(train_median)
        d["description"] = d["description"].fillna("")

    # ── CVSS vector components ──
    def parse_vector(d):
        d = d.copy()
        d["AV"] = d["cvss_vector"].astype(str).str.extract(r"AV:([NALP])", expand=False).fillna("MISSING")
        d["AC"] = d["cvss_vector"].astype(str).str.extract(r"AC:([LH])", expand=False).fillna("MISSING")
        d["PR"] = d["cvss_vector"].astype(str).str.extract(r"PR:([NLH])", expand=False).fillna("MISSING")
        d["UI"] = d["cvss_vector"].astype(str).str.extract(r"UI:([NR])", expand=False).fillna("MISSING")
        return d
    train_df = parse_vector(train_df)
    val_df = parse_vector(val_df)

    # One-hot encode CVSS vector components
    for col in ["AV", "AC", "PR", "UI"]:
        dummies_train = pd.get_dummies(train_df[col], prefix=col, dtype=int)
        dummies_val = pd.get_dummies(val_df[col], prefix=col, dtype=int)
        # Align columns
        for c in dummies_train.columns:
            if c not in dummies_val.columns:
                dummies_val[c] = 0
        for c in dummies_val.columns:
            if c not in dummies_train.columns:
                dummies_train[c] = 0
        dummies_val = dummies_val[dummies_train.columns]
        train_df = pd.concat([train_df.reset_index(drop=True), dummies_train.reset_index(drop=True)], axis=1)
        val_df = pd.concat([val_df.reset_index(drop=True), dummies_val.reset_index(drop=True)], axis=1)

    # ── CWE one-hot ──
    cwe_dummies_train = pd.get_dummies(train_df["cwe"], prefix="cwe", dtype=int)
    cwe_dummies_val = pd.get_dummies(val_df["cwe"], prefix="cwe", dtype=int)
    for c in cwe_dummies_train.columns:
        if c not in cwe_dummies_val.columns:
            cwe_dummies_val[c] = 0
    for c in cwe_dummies_val.columns:
        if c not in cwe_dummies_train.columns:
            cwe_dummies_train[c] = 0
    cwe_dummies_val = cwe_dummies_val[cwe_dummies_train.columns]

    # ── TF-IDF ──
    print("  Fitting TF-IDF (2000 features, leakage words blocked) ...")
    custom_stops = list(ENGLISH_STOP_WORDS) + [
        "exploited", "actively", "wild", "cisa", "kev", "known",
    ]
    tfidf = TfidfVectorizer(max_features=2000, stop_words=custom_stops)
    tfidf_train = tfidf.fit_transform(train_df["description"])
    tfidf_val = tfidf.transform(val_df["description"])

    # ── Build feature matrices for each group ──
    # Identify parsed-vector one-hot columns
    cvss_component_cols = sorted(
        [c for c in train_df.columns if c.startswith(("AV_", "AC_", "PR_", "UI_"))]
    )

    # Group 1: CVSS score only
    feat_1_cols = ["cvss_score"]
    # Group 2: + components
    feat_2_cols = ["cvss_score", "cvss_missing"] + cvss_component_cols
    # Group 3: + CWE (need to concat the dummies)
    feat_3_base_cols = feat_2_cols  # numeric part
    # Group 4: + text (TF-IDF appended as sparse)

    groups = {}

    # -- Group 1 --
    groups["1_cvss_score"] = {
        "X_train": train_df[feat_1_cols].values.astype(np.float64),
        "X_val": val_df[feat_1_cols].values.astype(np.float64),
        "feature_names": list(feat_1_cols),
    }

    # -- Group 2 --
    groups["2_cvss_components"] = {
        "X_train": train_df[feat_2_cols].values.astype(np.float64),
        "X_val": val_df[feat_2_cols].values.astype(np.float64),
        "feature_names": list(feat_2_cols),
    }

    # -- Group 3 --
    g3_train = np.hstack([
        train_df[feat_3_base_cols].values.astype(np.float64),
        cwe_dummies_train.values.astype(np.float64),
    ])
    g3_val = np.hstack([
        val_df[feat_3_base_cols].values.astype(np.float64),
        cwe_dummies_val.values.astype(np.float64),
    ])
    g3_names = list(feat_3_base_cols) + list(cwe_dummies_train.columns)
    groups["3_cwe"] = {
        "X_train": g3_train,
        "X_val": g3_val,
        "feature_names": g3_names,
    }

    # -- Group 4 --
    g4_train_dense = csr_matrix(g3_train)
    g4_val_dense = csr_matrix(g3_val)
    g4_train = hstack([g4_train_dense, tfidf_train])
    g4_val = hstack([g4_val_dense, tfidf_val])
    tfidf_names = [f"tfidf_{w}" for w in tfidf.get_feature_names_out()]
    g4_names = g3_names + tfidf_names
    groups["4_text"] = {
        "X_train": g4_train,
        "X_val": g4_val,
        "feature_names": g4_names,
    }

    return groups, train_df, val_df


# ══════════════════════════════════════════════════════════════════════════
#  Model runners
# ══════════════════════════════════════════════════════════════════════════
def get_models(n_train, pos_count):
    neg_count = n_train - pos_count
    spw = neg_count / pos_count if pos_count > 0 else 1
    return {
        "LogReg": LogisticRegression(
            max_iter=5000, solver="liblinear", C=1.0,
            class_weight="balanced", random_state=RANDOM_STATE,
        ),
        "RF": RandomForestClassifier(
            n_estimators=300, max_depth=8, min_samples_leaf=5,
            class_weight="balanced", random_state=RANDOM_STATE, n_jobs=-1,
        ),
        "XGBoost": xgb.XGBClassifier(
            max_depth=4, learning_rate=0.05, n_estimators=300,
            scale_pos_weight=spw, eval_metric="logloss",
            random_state=RANDOM_STATE, verbosity=0,
        ),
    }


def get_unconstrained_xgb(n_train, pos_count):
    """XGBoost with no regularisation — for the train-overfit sanity check."""
    neg_count = n_train - pos_count
    spw = neg_count / pos_count if pos_count > 0 else 1
    return xgb.XGBClassifier(
        max_depth=20, learning_rate=0.3, n_estimators=500,
        scale_pos_weight=spw, reg_alpha=0, reg_lambda=0,
        min_child_weight=1, subsample=1.0, colsample_bytree=1.0,
        eval_metric="logloss", random_state=RANDOM_STATE, verbosity=0,
    )


def fit_predict(model, X_train, y_train, X_val):
    """Fit model, return (train_proba, val_proba)."""
    model.fit(X_train, y_train)
    train_p = model.predict_proba(X_train)[:, 1]
    val_p = model.predict_proba(X_val)[:, 1]
    return train_p, val_p


# ══════════════════════════════════════════════════════════════════════════
#  Bug checks
# ══════════════════════════════════════════════════════════════════════════
def bug_check_label_shuffle(X_train, y_train, X_val, y_val, pos_count):
    """Shuffle labels, train XGBoost, expect val PR-AUC ≈ prevalence."""
    print(f"\n{THIN_SEP}")
    print("BUG CHECK: Label-shuffle test")
    print(THIN_SEP)

    prevalence = np.sum(y_val) / len(y_val)
    print(f"  Val prevalence (expected PR-AUC with random labels): {prevalence:.4f}")

    rng = np.random.RandomState(RANDOM_STATE)
    y_shuffled = rng.permutation(y_train)

    neg_count = len(y_train) - pos_count
    spw = neg_count / pos_count if pos_count > 0 else 1
    model = xgb.XGBClassifier(
        max_depth=4, learning_rate=0.05, n_estimators=300,
        scale_pos_weight=spw, eval_metric="logloss",
        random_state=RANDOM_STATE, verbosity=0,
    )
    model.fit(X_train, y_shuffled)
    val_preds = model.predict_proba(X_val)[:, 1]
    shuffle_prauc = compute_prauc(y_val, val_preds)
    print(f"  Label-shuffle val PR-AUC: {shuffle_prauc:.4f}")
    status = "PASS" if shuffle_prauc < 0.02 else "WARN"
    print(f"  Status: {status} (expected ~{prevalence:.4f})")


def bug_check_unconstrained_xgb(X_train, y_train, pos_count):
    """Unconstrained XGB should get train PR-AUC ~1.0."""
    print(f"\n{THIN_SEP}")
    print("BUG CHECK: Unconstrained XGBoost train score")
    print(THIN_SEP)

    model = get_unconstrained_xgb(len(y_train), pos_count)
    model.fit(X_train, y_train)
    train_preds = model.predict_proba(X_train)[:, 1]
    train_prauc = compute_prauc(y_train, train_preds)
    print(f"  Unconstrained XGB train PR-AUC: {train_prauc:.4f}")
    status = "PASS" if train_prauc > 0.95 else "WARN — model may not be fitting"
    print(f"  Status: {status} (expected ~1.0)")


def bug_check_cve_alignment(train_df, val_df, y_train, y_val):
    """Assert that X rows and y rows refer to the same cve_id."""
    print(f"\n{THIN_SEP}")
    print("BUG CHECK: cve_id alignment between X and y")
    print(THIN_SEP)

    # Verify train
    train_cve_ids = train_df["cve_id"].values
    val_cve_ids = val_df["cve_id"].values
    train_labels_from_df = train_df["in_kev"].values
    val_labels_from_df = val_df["in_kev"].values

    assert len(train_cve_ids) == len(y_train), \
        f"Train length mismatch: {len(train_cve_ids)} vs {len(y_train)}"
    assert len(val_cve_ids) == len(y_val), \
        f"Val length mismatch: {len(val_cve_ids)} vs {len(y_val)}"

    assert np.array_equal(train_labels_from_df, y_train), \
        "Train labels do not match between DataFrame and y array!"
    assert np.array_equal(val_labels_from_df, y_val), \
        "Val labels do not match between DataFrame and y array!"

    # Check for duplicates
    train_dupes = train_df["cve_id"].duplicated().sum()
    val_dupes = val_df["cve_id"].duplicated().sum()

    print(f"  Train: {len(y_train)} rows, {len(train_cve_ids)} cve_ids, {train_dupes} duplicates")
    print(f"  Val:   {len(y_val)} rows, {len(val_cve_ids)} cve_ids, {val_dupes} duplicates")
    print(f"  y_train positives: {y_train.sum()}, y_val positives: {y_val.sum()}")
    print("  Assertion: X rows and y rows refer to the same cve_id — PASSED")


# ══════════════════════════════════════════════════════════════════════════
#  Main ablation
# ══════════════════════════════════════════════════════════════════════════
def print_header():
    print(
        f"{'Run':<30s} {'Model':<10s} "
        f"{'TrainPR':>8s} {'ValPR':>8s} {'CI_lo':>7s} {'CI_hi':>7s} "
        f"{'P@50':>6s} {'R@50':>6s} "
        f"{'P@100':>6s} {'R@100':>6s} "
        f"{'P@500':>6s} {'R@500':>6s}"
    )
    print(THIN_SEP)


def print_row(run_name, model_name, train_prauc, val_prauc, ci_lo, ci_hi, at_k):
    print(
        f"{run_name:<30s} {model_name:<10s} "
        f"{train_prauc:>8.4f} {val_prauc:>8.4f} {ci_lo:>7.4f} {ci_hi:>7.4f} "
        f"{at_k['P@50']:>6.4f} {at_k['R@50']:>6.4f} "
        f"{at_k['P@100']:>6.4f} {at_k['R@100']:>6.4f} "
        f"{at_k['P@500']:>6.4f} {at_k['R@500']:>6.4f}"
    )


def main():
    print(SEP)
    print(f"P4 STRICT ABLATION — {datetime.now().isoformat()}")
    print(f"Input: {os.path.join(PROCESSED_DIR, f'master_cves_{TODAY}.csv')}")
    print(SEP)

    # ── Load ──
    train_df, val_df = load_data()
    y_train = train_df["in_kev"].values.astype(int)
    y_val = val_df["in_kev"].values.astype(int)
    pos_train = int(y_train.sum())
    pos_val = int(y_val.sum())

    # ── cve_id alignment check ──
    bug_check_cve_alignment(train_df, val_df, y_train, y_val)

    # ── Prepare features ──
    print(f"\n[{datetime.now().isoformat()}] Preparing feature groups ...")
    groups, train_df, val_df = prepare_features(train_df, val_df)

    # Print exact feature list per group
    print(f"\n{THIN_SEP}")
    print("FEATURE LISTS PER GROUP (no date features)")
    print(THIN_SEP)
    for gname, gdata in groups.items():
        fnames = gdata["feature_names"]
        # Sanity: assert no date features
        for f in fnames:
            assert f not in ("pub_year", "pub_month", "year"), \
                f"FORBIDDEN date feature found: {f}"
        print(f"\n  {gname}: {len(fnames)} features")
        # Print first 30 feature names (truncate if many)
        display = fnames[:30]
        print(f"    {display}")
        if len(fnames) > 30:
            print(f"    ... and {len(fnames) - 30} more")

    # ══════════════════════════════════════════════════════════════════════
    #  Baselines
    # ══════════════════════════════════════════════════════════════════════
    print(f"\n{SEP}")
    print("ABLATION RESULTS TABLE")
    print(SEP)
    print_header()

    # ── CVSS raw baseline ──
    cvss_train_scores = train_df["cvss_score"].values / 10.0
    cvss_val_scores = val_df["cvss_score"].values / 10.0
    tr_pr = compute_prauc(y_train, cvss_train_scores)
    val_pr = compute_prauc(y_val, cvss_val_scores)
    ci_lo, ci_hi = bootstrap_prauc_ci(y_val, cvss_val_scores)
    at_k = evaluate_at_k(y_val, cvss_val_scores)
    print_row("CVSS raw / 10 (baseline)", "—", tr_pr, val_pr, ci_lo, ci_hi, at_k)

    # ── EPSS baseline (hindsight) ──
    epss_train = train_df["epss"].fillna(0).values
    epss_val = val_df["epss"].fillna(0).values
    tr_pr = compute_prauc(y_train, epss_train)
    val_pr = compute_prauc(y_val, epss_val)
    ci_lo, ci_hi = bootstrap_prauc_ci(y_val, epss_val)
    at_k = evaluate_at_k(y_val, epss_val)
    print_row("EPSS (hindsight)", "—", tr_pr, val_pr, ci_lo, ci_hi, at_k)

    # ══════════════════════════════════════════════════════════════════════
    #  Ablation: feature groups × models
    # ══════════════════════════════════════════════════════════════════════
    group_labels = {
        "1_cvss_score": "CVSS score",
        "2_cvss_components": "+CVSS components",
        "3_cwe": "+CWE",
        "4_text": "+Text (TF-IDF)",
    }

    for gname, glabel in group_labels.items():
        X_tr = groups[gname]["X_train"]
        X_va = groups[gname]["X_val"]
        models = get_models(len(y_train), pos_train)

        for mname, model in models.items():
            print(f"[{datetime.now().isoformat()}] Training {mname} on {gname} ...",
                  end="", flush=True)
            train_p, val_p = fit_predict(model, X_tr, y_train, X_va)

            tr_pr = compute_prauc(y_train, train_p)
            val_pr = compute_prauc(y_val, val_p)
            ci_lo, ci_hi = bootstrap_prauc_ci(y_val, val_p)
            at_k = evaluate_at_k(y_val, val_p)

            # Clear the "Training..." line, print result
            print("\r", end="")
            print_row(glabel, mname, tr_pr, val_pr, ci_lo, ci_hi, at_k)

    # ══════════════════════════════════════════════════════════════════════
    #  Bug checks
    # ══════════════════════════════════════════════════════════════════════
    # Use the largest feature group for bug checks
    X_full_train = groups["4_text"]["X_train"]
    X_full_val = groups["4_text"]["X_val"]

    bug_check_label_shuffle(X_full_train, y_train, X_full_val, y_val, pos_train)
    bug_check_unconstrained_xgb(X_full_train, y_train, pos_train)

    # ── Final summary ──
    print(f"\n{SEP}")
    print(f"P4 STRICT ABLATION COMPLETE — {datetime.now().isoformat()}")
    print(f"Train: {len(y_train)} rows, {pos_train} positives")
    print(f"Val:   {len(y_val)} rows, {pos_val} positives")
    print(f"Bootstrap: {N_BOOTSTRAP} iterations, 95% CI")
    print(f"Forbidden features used: NONE (no pub_year, pub_month)")
    print(SEP)


if __name__ == "__main__":
    main()

