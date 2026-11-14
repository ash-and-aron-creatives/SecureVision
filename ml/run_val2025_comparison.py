"""Reproduce the five-way Validation 2025 comparison without opening the test split."""

from __future__ import annotations

import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import pandas as pd
import scipy
import scipy.sparse as sp
import sklearn
import xgboost
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    confusion_matrix,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import (
    RandomizedSearchCV,
    StratifiedKFold,
    cross_val_predict,
)
from sklearn.preprocessing import OneHotEncoder
from sklearn.feature_extraction.text import TfidfVectorizer


ROOT = Path(__file__).resolve().parents[1]
TRAIN_PATH = ROOT / "data" / "processed" / "train_2026-10-08.csv"
VALIDATION_PATH = ROOT / "data" / "processed" / "val_2026-10-08.csv"
CONFIG_PATH = ROOT / "frozen_config.json"
FROZEN_MODEL_PATH = ROOT / "ml" / "models" / "headline_model_calibrated.joblib"
OUTPUT_DIRECTORY = ROOT / "docs" / "results_offline" / "2026-11-14"
MODEL_DIRECTORY = ROOT / "ml" / "models"
SEED = 42
BOOTSTRAP_RESAMPLES = 200
TOP_K = (50, 100, 500)
CVSS_VECTOR_PATTERNS = {
    "AV": r"AV:([NALP])",
    "AC": r"AC:([LH])",
    "PR": r"PR:([NLH])",
    "UI": r"UI:([NR])",
    "S": r"S:([UC])",
    "C": r"C:([NLH])",
    "I": r"I:([NLH])",
    "A": r"A:([NLH])",
}

_LOG: list[str] = []


def log(message: str) -> None:
    print(message, flush=True)
    _LOG.append(message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_split(path: Path, expected_hash: str, split_name: str) -> pd.DataFrame:
    actual_hash = sha256_file(path)
    if actual_hash != expected_hash:
        raise ValueError(f"{split_name} CSV SHA-256 does not match frozen_config.json.")
    frame = pd.read_csv(path, low_memory=False)
    dates = pd.to_datetime(frame["published_date"], utc=True, errors="raise")
    if split_name == "train":
        valid = dates.dt.year.between(2022, 2024)
    else:
        valid = dates.dt.year.eq(2025)
    if not bool(valid.all()):
        raise ValueError(f"{split_name} CSV contains rows outside its chronological split.")
    if not np.array_equal(
        frame["in_kev"].fillna(False).astype(bool).to_numpy(),
        frame["strict_in_kev"].fillna(False).astype(bool).to_numpy(),
    ):
        raise ValueError(f"{split_name} labels disagree with the frozen 30-day label.")
    return frame


def _parse_cvss_components(frame: pd.DataFrame) -> pd.DataFrame:
    parsed: dict[str, list[str]] = {name: [] for name in CVSS_VECTOR_PATTERNS}
    vectors = frame["cvss_vector"].fillna("") if "cvss_vector" in frame else [""] * len(frame)
    compiled = {
        name: re.compile(pattern) for name, pattern in CVSS_VECTOR_PATTERNS.items()
    }
    for vector in vectors:
        text = str(vector)
        for name, pattern in compiled.items():
            match = pattern.search(text)
            parsed[name].append(match.group(1) if match else "MISSING")
    return pd.DataFrame(parsed, index=frame.index)


def _one_hot_encoder() -> OneHotEncoder:
    try:
        return OneHotEncoder(handle_unknown="ignore", sparse_output=True)
    except TypeError:
        return OneHotEncoder(handle_unknown="ignore", sparse=True)


def _build_features(
    train: pd.DataFrame,
    validation: pd.DataFrame,
    config: dict[str, Any],
) -> tuple[sp.csr_matrix, sp.csr_matrix, list[str]]:
    train_cvss_missing = train["cvss_score"].isna().astype(np.float32).to_numpy()
    val_cvss_missing = validation["cvss_score"].isna().astype(np.float32).to_numpy()
    train_cvss = np.column_stack(
        (
            train["cvss_score"].fillna(6.7).astype(np.float32).to_numpy(),
            train_cvss_missing,
        )
    )
    val_cvss = np.column_stack(
        (
            validation["cvss_score"].fillna(6.7).astype(np.float32).to_numpy(),
            val_cvss_missing,
        )
    )
    train_cvss_sparse = sp.csr_matrix(train_cvss)
    val_cvss_sparse = sp.csr_matrix(val_cvss)

    vector_encoder = _one_hot_encoder()
    train_components = _parse_cvss_components(train)
    val_components = _parse_cvss_components(validation)
    train_vector = vector_encoder.fit_transform(train_components)
    val_vector = vector_encoder.transform(val_components)
    vector_names = vector_encoder.get_feature_names_out(
        list(CVSS_VECTOR_PATTERNS)
    ).tolist()

    top_cwes = train["cwe"].value_counts().head(20).index.tolist()
    train_cwe = train["cwe"].map(
        lambda value: str(value) if value in top_cwes else "OTHER"
    ).to_frame(name="cwe")
    val_cwe = validation["cwe"].map(
        lambda value: str(value) if value in top_cwes else "OTHER"
    ).to_frame(name="cwe")
    cwe_encoder = _one_hot_encoder()
    train_cwe_encoded = cwe_encoder.fit_transform(train_cwe)
    val_cwe_encoded = cwe_encoder.transform(val_cwe)
    cwe_names = cwe_encoder.get_feature_names_out(["cwe"]).tolist()

    pattern = re.compile(config["regex_blacklist"], re.IGNORECASE)
    vectorizer = TfidfVectorizer(
        max_features=100,
        preprocessor=lambda value: pattern.sub("", str(value).lower()),
        stop_words="english",
        ngram_range=(1, 2),
        min_df=2,
    )
    train_text = vectorizer.fit_transform(train["description"].fillna(""))
    val_text = vectorizer.transform(validation["description"].fillna(""))
    text_names = vectorizer.get_feature_names_out().tolist()

    features = [
        "cvss_score",
        "cvss_missing",
        *vector_names,
        *cwe_names,
        *text_names,
    ]
    if features != config["features"] or len(features) != 152:
        raise ValueError("Train-fitted feature names/order differ from the frozen 152-feature contract.")
    if any("kev" in name.casefold() or "epss" in name.casefold() for name in features):
        raise ValueError("KEV/EPSS is prohibited in the model feature matrix.")

    train_matrix = sp.hstack(
        [train_cvss_sparse, train_vector, train_cwe_encoded, train_text],
        format="csr",
        dtype=np.float32,
    )
    val_matrix = sp.hstack(
        [val_cvss_sparse, val_vector, val_cwe_encoded, val_text],
        format="csr",
        dtype=np.float32,
    )
    if train_matrix.shape[1] != 152 or val_matrix.shape[1] != 152:
        raise ValueError("Feature matrix has an unexpected number of columns.")
    return train_matrix, val_matrix, features


def _best_f1_threshold(y_true: np.ndarray, scores: np.ndarray) -> tuple[float, float]:
    precision, recall, thresholds = precision_recall_curve(y_true, scores)
    f1 = np.divide(
        2 * precision[:-1] * recall[:-1],
        precision[:-1] + recall[:-1],
        out=np.zeros_like(precision[:-1]),
        where=(precision[:-1] + recall[:-1]) != 0,
    )
    index = int(np.argmax(f1))
    return float(thresholds[index]), float(f1[index])


def _top_k(
    labels: np.ndarray, scores: np.ndarray, cve_ids: np.ndarray
) -> tuple[dict[str, float], dict[str, float]]:
    order = np.lexsort((cve_ids, -scores))
    ranked_labels = labels[order]
    precision: dict[str, float] = {}
    recall: dict[str, float] = {}
    positive_count = int(labels.sum())
    for k in TOP_K:
        take = min(k, len(labels))
        found = int(ranked_labels[:take].sum())
        precision[str(k)] = found / take if take else 0.0
        recall[str(k)] = found / positive_count if positive_count else 0.0
    return precision, recall


def _bootstrap_pr_auc(
    labels: np.ndarray, scores: np.ndarray
) -> tuple[float, float, list[float]]:
    rng = np.random.RandomState(SEED)
    values: list[float] = []
    for _ in range(BOOTSTRAP_RESAMPLES):
        indices = rng.randint(0, len(labels), len(labels))
        if np.unique(labels[indices]).size == 2:
            values.append(float(average_precision_score(labels[indices], scores[indices])))
    if not values:
        raise ValueError("Bootstrap produced no valid two-class samples.")
    bounds = np.percentile(values, [2.5, 97.5])
    return float(np.std(values)), float(bounds[0]), [float(bounds[0]), float(bounds[1])]


def _evaluate(
    labels: np.ndarray,
    scores: np.ndarray,
    cve_ids: np.ndarray,
    threshold: float,
) -> dict[str, Any]:
    predicted = scores >= threshold
    matrix = confusion_matrix(labels, predicted, labels=[0, 1])
    pr_stddev, _, pr_ci = _bootstrap_pr_auc(labels, scores)
    precision_at_k, recall_at_k = _top_k(labels, scores, cve_ids)
    return {
        "pr_auc": float(average_precision_score(labels, scores)),
        "pr_auc_stddev": pr_stddev,
        "pr_auc_ci95": pr_ci,
        "precision": float(precision_score(labels, predicted, zero_division=0)),
        "recall": float(recall_score(labels, predicted, zero_division=0)),
        "f1": float(
            2
            * precision_score(labels, predicted, zero_division=0)
            * recall_score(labels, predicted, zero_division=0)
            / max(
                precision_score(labels, predicted, zero_division=0)
                + recall_score(labels, predicted, zero_division=0),
                np.finfo(float).eps,
            )
        ),
        "roc_auc": float(roc_auc_score(labels, scores)),
        "precision_at_k": precision_at_k,
        "recall_at_k": recall_at_k,
        "confusion_matrix": {
            "labels": ["negative", "positive"],
            "rows_actual_columns_predicted": matrix.tolist(),
            "tn": int(matrix[0, 0]),
            "fp": int(matrix[0, 1]),
            "fn": int(matrix[1, 0]),
            "tp": int(matrix[1, 1]),
        },
    }


def _fit_and_score(
    name: str,
    estimator: Any,
    train_matrix: sp.csr_matrix,
    val_matrix: sp.csr_matrix,
    y_train: np.ndarray,
    y_validation: np.ndarray,
    cve_ids: np.ndarray,
    cv: StratifiedKFold,
) -> tuple[Any, dict[str, Any], np.ndarray]:
    estimator.fit(train_matrix, y_train)
    train_scores = cross_val_predict(
        estimator,
        train_matrix,
        y_train,
        cv=cv,
        method="predict_proba",
        n_jobs=1,
    )[:, 1]
    validation_scores = estimator.predict_proba(val_matrix)[:, 1]
    threshold, train_f1 = _best_f1_threshold(y_train, train_scores)
    result = {
        "name": name,
        "threshold": threshold,
        "threshold_selection": "Maximum F1 on 3-fold out-of-fold training probabilities; validation labels not used.",
        "training_oof_f1_at_threshold": train_f1,
        "metrics": _evaluate(y_validation, validation_scores, cve_ids, threshold),
    }
    return estimator, result, validation_scores


def run() -> None:
    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    MODEL_DIRECTORY.mkdir(parents=True, exist_ok=True)
    config_bytes = CONFIG_PATH.read_bytes()
    config = json.loads(config_bytes.decode("utf-8-sig"))
    if config.get("n_features_in") != 152 or len(config.get("features", [])) != 152:
        raise ValueError("Frozen configuration does not specify exactly 152 features.")
    if sha256_file(FROZEN_MODEL_PATH) != config.get("model_sha256"):
        raise ValueError("Frozen XGBoost model hash does not match frozen_config.json.")

    train = _read_split(
        TRAIN_PATH, config["data_hashes"]["train"], "train"
    )
    validation = _read_split(
        VALIDATION_PATH, config["data_hashes"]["val"], "validation"
    )
    if train["cve_id"].duplicated().any() or validation["cve_id"].duplicated().any():
        raise ValueError("CVE identifiers must be unique within the split.")
    y_train = train["in_kev"].astype(int).to_numpy()
    y_validation = validation["in_kev"].astype(int).to_numpy()
    if np.unique(y_train).size != 2 or np.unique(y_validation).size != 2:
        raise ValueError("Both splits must contain positive and negative labels.")

    log("Validation 2025 comparison (test split is not opened)")
    log(f"Training rows={len(train)} positives={int(y_train.sum())}")
    log(f"Validation rows={len(validation)} positives={int(y_validation.sum())}")
    train_matrix, validation_matrix, features = _build_features(train, validation, config)
    log(f"Train-fitted feature matrix: {len(features)} columns")

    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=SEED)
    y_cvss_train = train["cvss_score"].fillna(6.7).to_numpy(dtype=float) / 10.0
    y_cvss_validation = validation["cvss_score"].fillna(6.7).to_numpy(dtype=float) / 10.0
    y_epss_train = train["epss"].fillna(0.0).to_numpy(dtype=float)
    y_epss_validation = validation["epss"].fillna(0.0).to_numpy(dtype=float)

    log("Tuning Random Forest with 3-fold training-only randomized search...")
    rf_search = RandomizedSearchCV(
        RandomForestClassifier(
            class_weight="balanced",
            random_state=SEED,
            n_jobs=1,
        ),
        param_distributions={
            "n_estimators": [25, 50],
            "max_depth": [4, 6, 8],
            "min_samples_leaf": [2, 4, 8],
            "max_features": ["sqrt", 0.5],
        },
        n_iter=4,
        scoring="average_precision",
        cv=cv,
        random_state=SEED,
        n_jobs=1,
        refit=True,
        return_train_score=False,
    )
    rf_search.fit(train_matrix, y_train)
    log(f"Random Forest best training CV PR-AUC={rf_search.best_score_:.6f}")

    log("Fitting Logistic Regression and scoring validation...")
    logreg = LogisticRegression(
        class_weight="balanced",
        random_state=SEED,
        max_iter=2000,
        solver="liblinear",
    )
    rf = rf_search.best_estimator_
    models: list[dict[str, Any]] = []
    validation_probabilities: dict[str, np.ndarray] = {}

    logreg, logreg_result, logreg_scores = _fit_and_score(
        "Logistic Regression (152 features)",
        logreg,
        train_matrix,
        validation_matrix,
        y_train,
        y_validation,
        validation["cve_id"].astype(str).to_numpy(),
        cv,
    )
    logreg_result["hyperparameters"] = logreg.get_params()
    logreg_result["feature_count"] = len(features)
    logreg_result["training_cv"] = {
        "method": "3-fold stratified cross-validation on training rows",
        "scoring": "average_precision",
        "random_state": SEED,
    }
    models.append(logreg_result)
    validation_probabilities[logreg_result["name"]] = logreg_scores

    rf, rf_result, rf_scores = _fit_and_score(
        "Random Forest",
        rf,
        train_matrix,
        validation_matrix,
        y_train,
        y_validation,
        validation["cve_id"].astype(str).to_numpy(),
        cv,
    )
    rf_result["hyperparameters"] = rf.get_params()
    rf_result["feature_count"] = len(features)
    rf_result["training_cv"] = {
        "method": "3-fold stratified randomized parameter search on training rows",
        "scoring": "average_precision",
        "random_state": SEED,
        "n_iter": 4,
        "best_score": float(rf_search.best_score_),
        "best_params": rf_search.best_params_,
        "candidates": [
            {
                "params": params,
                "mean_test_score": float(mean_score),
                "std_test_score": float(std_score),
            }
            for params, mean_score, std_score in zip(
                rf_search.cv_results_["params"],
                rf_search.cv_results_["mean_test_score"],
                rf_search.cv_results_["std_test_score"],
                strict=True,
            )
        ],
    }
    models.append(rf_result)
    validation_probabilities[rf_result["name"]] = rf_scores

    log("Scoring the existing frozen XGBoost model read-only...")
    frozen_calibrated = joblib.load(FROZEN_MODEL_PATH)
    if getattr(frozen_calibrated, "n_features_in_", None) != len(features):
        raise ValueError("Frozen XGBoost input width differs from the 152-feature matrix.")
    xgb_train_scores = frozen_calibrated.predict_proba(train_matrix)[:, 1]
    xgb_validation_scores = frozen_calibrated.predict_proba(validation_matrix)[:, 1]
    xgb_threshold, xgb_train_f1 = _best_f1_threshold(y_train, xgb_train_scores)
    xgb_name = "XGBoost calibrated"
    xgb_result = {
        "name": xgb_name,
        "threshold": xgb_threshold,
        "threshold_selection": (
            "Maximum F1 on training-split probabilities from the unchanged frozen "
            "calibrated classifier; validation labels not used. Its sigmoid "
            "calibrator was originally fitted on Validation 2025."
        ),
        "training_f1_at_threshold": xgb_train_f1,
        "hyperparameters": config["hyperparameters"],
        "model_sha256": config["model_sha256"],
        "calibration_note": config.get("calibration"),
        "metrics": _evaluate(
            y_validation,
            xgb_validation_scores,
            validation["cve_id"].astype(str).to_numpy(),
            xgb_threshold,
        ),
    }
    models.append(xgb_result)
    validation_probabilities[xgb_name] = xgb_validation_scores

    for name, train_scores, val_scores, note in (
        (
            "CVSS-only baseline",
            y_cvss_train,
            y_cvss_validation,
            "CVSS base score divided by 10; missing values use 6.7.",
        ),
        (
            "EPSS baseline",
            y_epss_train,
            y_epss_validation,
            "Current EPSS snapshot; hindsight baseline, not a prospective feature.",
        ),
    ):
        threshold, train_f1 = _best_f1_threshold(y_train, train_scores)
        baseline = {
            "name": name,
            "threshold": threshold,
            "threshold_selection": "Maximum F1 on training-split baseline scores; validation labels not used.",
            "training_f1_at_threshold": train_f1,
            "note": note,
            "metrics": _evaluate(
                y_validation,
                val_scores,
                validation["cve_id"].astype(str).to_numpy(),
                threshold,
            ),
        }
        models.append(baseline)
        validation_probabilities[name] = val_scores

    logreg_path = MODEL_DIRECTORY / "logreg_val2025_2026-11-14.joblib"
    rf_path = MODEL_DIRECTORY / "rf_val2025_2026-11-14.joblib"
    joblib.dump(logreg, logreg_path)
    joblib.dump(rf, rf_path)
    log(f"Saved Logistic Regression: {logreg_path.relative_to(ROOT)}")
    log(f"Saved Random Forest: {rf_path.relative_to(ROOT)}")

    for result in models:
        metrics = result["metrics"]
        log(
            f"{result['name']}: PR-AUC={metrics['pr_auc']:.6f} "
            f"Precision={metrics['precision']:.6f} Recall={metrics['recall']:.6f} "
            f"F1={metrics['f1']:.6f} ROC-AUC={metrics['roc_auc']:.6f} "
            f"P@50/100/500={metrics['precision_at_k']['50']:.4f}/"
            f"{metrics['precision_at_k']['100']:.4f}/"
            f"{metrics['precision_at_k']['500']:.4f}"
        )

    prediction_rows = []
    ids = validation["cve_id"].astype(str).to_numpy()
    for row_index, (cve_id, label) in enumerate(zip(ids, y_validation, strict=True)):
        prediction_rows.append(
            {
                "cve_id": cve_id,
                "label": int(label),
                "scores": {
                    name: float(scores[row_index])
                    for name, scores in validation_probabilities.items()
                },
            }
        )
    prediction_digest = hashlib.sha256(
        json.dumps(
            prediction_rows,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()

    metadata = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "command": "python ml/run_val2025_comparison.py",
        "python": sys.version,
        "library_versions": {
            "numpy": np.__version__,
            "pandas": pd.__version__,
            "scipy": scipy.__version__,
            "scikit_learn": sklearn.__version__,
            "xgboost": xgboost.__version__,
            "joblib": joblib.__version__,
        },
        "split": {
            "train": "2022-01-01 through 2024-12-31",
            "validation": "2025-01-01 through 2025-12-31",
            "train_rows": len(train),
            "train_positives": int(y_train.sum()),
            "validation_rows": len(validation),
            "validation_positives": int(y_validation.sum()),
            "label_rule": config["label_rule"],
            "test_split_opened": False,
        },
        "feature_count": len(features),
        "features": features,
        "seeds": {
            "model_and_search": SEED,
            "stratified_cv": SEED,
            "bootstrap": SEED,
            "bootstrap_resamples": BOOTSTRAP_RESAMPLES,
        },
        "top_k_tie_handling": "Sort descending score, then ascending stable CVE identifier.",
        "threshold_rule": "Maximum F1 on training-only scores; ties use the first (lowest) threshold.",
        "pr_auc_uncertainty": (
            "Percentile 95% interval and standard deviation from 200 unstratified "
            "bootstrap resamples; one-class resamples are skipped."
        ),
        "random_forest_search": {
            "n_iter": 4,
            "cv_folds": 3,
            "scoring": "average_precision",
            "search_random_state": SEED,
            "estimator_class_weight": "balanced",
        },
        "hashes_sha256": {
            "train_csv": config["data_hashes"]["train"],
            "validation_csv": config["data_hashes"]["val"],
            "frozen_config": hashlib.sha256(config_bytes).hexdigest(),
            "frozen_xgboost_model": config["model_sha256"],
            "feature_list": hashlib.sha256(
                json.dumps(features, separators=(",", ":")).encode("utf-8")
            ).hexdigest(),
            "validation_predictions": prediction_digest,
            "logreg_model": sha256_file(logreg_path),
            "random_forest_model": sha256_file(rf_path),
            "comparison_script": sha256_file(Path(__file__)),
        },
    }
    payload = {
        "metadata": metadata,
        "models": models,
        "validation_predictions": prediction_rows,
        "console_log": "\n".join(_LOG),
    }
    json_path = OUTPUT_DIRECTORY / "val2025_comparison.json"
    log(f"Wrote {json_path.relative_to(ROOT)}")
    log(f"Wrote {(OUTPUT_DIRECTORY / 'val2025_comparison.md').relative_to(ROOT)}")
    payload["console_log"] = "\n".join(_LOG)
    json_path.write_text(
        json.dumps(payload, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )

    table_header = (
        "| Model | PR-AUC | Precision | Recall | F1 | ROC-AUC | "
        "P@50 | P@100 | P@500 | R@50 | R@100 | R@500 |"
    )
    table_separator = "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"
    table_rows = []
    for result in models:
        metrics = result["metrics"]
        top_p = metrics["precision_at_k"]
        top_r = metrics["recall_at_k"]
        table_rows.append(
            "| {name} | {pr:.6f} | {p:.6f} | {r:.6f} | {f1:.6f} | {roc:.6f} | "
            "{p50:.4f} | {p100:.4f} | {p500:.4f} | {r50:.4f} | {r100:.4f} | {r500:.4f} |".format(
                name=result["name"],
                pr=metrics["pr_auc"],
                p=metrics["precision"],
                r=metrics["recall"],
                f1=metrics["f1"],
                roc=metrics["roc_auc"],
                p50=top_p["50"],
                p100=top_p["100"],
                p500=top_p["500"],
                r50=top_r["50"],
                r100=top_r["100"],
                r500=top_r["500"],
            )
        )
    method_lines = [
        "# Validation 2025 model comparison",
        "",
        f"- Command: `{metadata['command']}`",
        f"- Split: {metadata['split']['train']} training; {metadata['split']['validation']} validation.",
        f"- Rows: train {len(train):,} ({int(y_train.sum()):,} positives); validation {len(validation):,} ({int(y_validation.sum()):,} positives).",
        "- The test partition was not opened. All encoders and TF-IDF vocabulary were fitted on training rows only.",
        "- Model inputs are the frozen 152 features. KEV and EPSS are labels/baselines only, never model inputs.",
        "- Random Forest hyperparameters were selected using four randomized candidates (25/50 trees, depth 4/6/8) and 3-fold stratified CV on training rows only; class weight is balanced and seed is 42.",
        "- LR and RF thresholds use 3-fold out-of-fold training scores. Baseline thresholds use their training scores. The frozen XGBoost threshold uses training-split scores without changing its artifact.",
        "- Top-K ties sort by score descending then CVE identifier ascending. PR-AUC uncertainty is a 200-resample percentile bootstrap 95% interval; one-class samples are skipped.",
        "- EPSS uses the available snapshot and is explicitly a hindsight baseline.",
        "",
        table_header,
        table_separator,
        *table_rows,
        "",
        "## Thresholds and confusion matrices",
        "",
    ]
    for result in models:
        method_lines.extend(
            [
                f"### {result['name']}",
                f"- Training-selected threshold: `{result['threshold']:.10g}`",
                f"- Validation confusion matrix (actual rows, predicted columns): `{result['metrics']['confusion_matrix']['rows_actual_columns_predicted']}`",
            ]
        )
        if "training_cv" in result:
            method_lines.append(
                f"- Training CV: `{json.dumps(result['training_cv'], sort_keys=True)}`"
            )
        if result.get("note"):
            method_lines.append(f"- Note: {result['note']}")
        method_lines.append("")
    method_lines.extend(
        [
            "## Reproducibility and artifacts",
            "",
            "- Full validation predictions (CVE id, label and one probability per model), metric details, console log, library versions, seeds and SHA-256 hashes are in this JSON file.",
            "- New model files: `ml/models/logreg_val2025_2026-11-14.joblib` and `ml/models/rf_val2025_2026-11-14.joblib`.",
            "- The XGBoost validation probabilities come from the existing frozen calibrated model, used read-only. Its sigmoid calibration was fitted on Validation 2025 historically; this comparison does not refit it.",
            "",
        ]
    )
    (OUTPUT_DIRECTORY / "val2025_comparison.md").write_text(
        "\n".join(method_lines), encoding="utf-8"
    )


if __name__ == "__main__":
    run()
