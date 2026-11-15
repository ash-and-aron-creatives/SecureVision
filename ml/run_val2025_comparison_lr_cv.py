"""Tune Logistic Regression on training-only CV for a dated Validation 2025 run."""

from __future__ import annotations

import copy
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import joblib
import numpy as np
import sklearn
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GridSearchCV, StratifiedKFold, cross_val_predict

from render_val2025_charts import (
    _calibration_diagnostics,
    _comparison_note,
    _pr_curve_svg,
    _top_k_svg,
)
from run_val2025_comparison import (
    CONFIG_PATH,
    MODEL_DIRECTORY,
    ROOT,
    SEED,
    TRAIN_PATH,
    VALIDATION_PATH,
    _best_f1_threshold,
    _build_features,
    _evaluate,
    _read_split,
    sha256_file,
)


RUN_DATE = "2026-11-15"
OUTPUT_DIRECTORY = ROOT / "docs" / "results_offline" / RUN_DATE
HISTORICAL_COMPARISON_PATH = (
    ROOT / "docs" / "results_offline" / "2026-11-14" / "val2025_comparison.json"
)
MODEL_PATH = MODEL_DIRECTORY / f"logreg_cv_val2025_{RUN_DATE}.joblib"
FIXED_MODEL_NAME = "Logistic Regression (152 features)"
PARAMETER_GRID = {
    "C": [0.01, 0.1, 1, 10, 100],
    "class_weight": [None, "balanced"],
}


def _metric_line(model: dict[str, Any]) -> str:
    metrics = model["metrics"]
    precision_at_k = metrics["precision_at_k"]
    recall_at_k = metrics["recall_at_k"]
    return (
        f"| {metrics['pr_auc']:.6f} | {metrics['precision']:.6f} | "
        f"{metrics['recall']:.6f} | {metrics['f1']:.6f} | "
        f"{metrics['roc_auc']:.6f} | {precision_at_k['50']:.4f} | "
        f"{precision_at_k['100']:.4f} | {precision_at_k['500']:.4f} | "
        f"{recall_at_k['50']:.4f} | {recall_at_k['100']:.4f} | "
        f"{recall_at_k['500']:.4f} |"
    )


def run() -> None:
    if OUTPUT_DIRECTORY.exists() or MODEL_PATH.exists():
        raise FileExistsError(
            "Refusing to overwrite an existing dated result folder or model."
        )
    if not HISTORICAL_COMPARISON_PATH.is_file():
        raise FileNotFoundError(
            f"Historical comparison is missing: {HISTORICAL_COMPARISON_PATH}"
        )

    config_bytes = CONFIG_PATH.read_bytes()
    config = json.loads(config_bytes.decode("utf-8-sig"))
    train = _read_split(
        TRAIN_PATH, config["data_hashes"]["train"], "train"
    )
    if train["cve_id"].duplicated().any():
        raise ValueError("CVE identifiers must be unique within the training split.")
    y_train = train["in_kev"].astype(int).to_numpy()
    if np.unique(y_train).size != 2:
        raise ValueError("The training split must contain both label classes.")

    train_matrix, _, features = _build_features(train, train, config)
    if len(features) != 152:
        raise ValueError("The train-fitted feature matrix must contain 152 columns.")

    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=SEED)
    search = GridSearchCV(
        LogisticRegression(
            solver="liblinear",
            random_state=SEED,
            max_iter=2000,
        ),
        param_grid=PARAMETER_GRID,
        scoring="average_precision",
        cv=cv,
        n_jobs=1,
        refit=True,
        return_train_score=False,
    )
    search.fit(train_matrix, y_train)

    oof_scores = cross_val_predict(
        search.best_estimator_,
        train_matrix,
        y_train,
        cv=cv,
        method="predict_proba",
        n_jobs=1,
    )[:, 1]
    threshold, training_oof_f1 = _best_f1_threshold(y_train, oof_scores)

    # Validation is first loaded after parameter selection and threshold selection.
    validation = _read_split(
        VALIDATION_PATH, config["data_hashes"]["val"], "validation"
    )
    if validation["cve_id"].duplicated().any():
        raise ValueError("CVE identifiers must be unique within the validation split.")
    y_validation = validation["in_kev"].astype(int).to_numpy()
    _, validation_matrix, validation_features = _build_features(
        train, validation, config
    )
    if validation_features != features:
        raise ValueError("Validation feature order differs from the training feature order.")

    validation_scores = search.best_estimator_.predict_proba(validation_matrix)[:, 1]
    tuned_result = {
        "name": FIXED_MODEL_NAME,
        "threshold": threshold,
        "threshold_selection": (
            "Maximum F1 on 3-fold out-of-fold training probabilities from the "
            "training-CV-selected estimator; validation labels not used."
        ),
        "training_oof_f1_at_threshold": training_oof_f1,
        "hyperparameters": search.best_estimator_.get_params(),
        "feature_count": len(features),
        "note": (
            "Tuned with 3-fold stratified training-only CV; average_precision "
            "scoring. This is the new dated tuned result."
        ),
        "training_cv": {
            "method": "3-fold stratified grid search on training rows only",
            "scoring": "average_precision",
            "random_state": SEED,
            "parameter_grid": PARAMETER_GRID,
            "best_params": search.best_params_,
            "best_score": float(search.best_score_),
            "candidates": [
                {
                    "params": params,
                    "mean_test_score": float(mean_score),
                    "std_test_score": float(std_score),
                }
                for params, mean_score, std_score in zip(
                    search.cv_results_["params"],
                    search.cv_results_["mean_test_score"],
                    search.cv_results_["std_test_score"],
                    strict=True,
                )
            ],
        },
        "metrics": _evaluate(
            y_validation,
            validation_scores,
            validation["cve_id"].astype(str).to_numpy(),
            threshold,
        ),
    }

    historical = json.loads(
        HISTORICAL_COMPARISON_PATH.read_text(encoding="utf-8-sig")
    )
    historical_hashes = historical["metadata"]["hashes_sha256"]
    if historical_hashes["train_csv"] != config["data_hashes"]["train"]:
        raise ValueError("Historical training data hash differs from this run.")
    if historical_hashes["validation_csv"] != config["data_hashes"]["val"]:
        raise ValueError("Historical validation data hash differs from this run.")
    validation_ids = validation["cve_id"].astype(str).to_numpy()
    historical_predictions = historical["validation_predictions"]
    if len(historical_predictions) != len(validation):
        raise ValueError("Historical validation predictions have an unexpected row count.")
    if any(
        row["cve_id"] != cve_id or row["label"] != int(label)
        for row, cve_id, label in zip(
            historical_predictions, validation_ids, y_validation, strict=True
        )
    ):
        raise ValueError("Historical validation examples differ from this run.")
    previous_logreg = next(
        model for model in historical["models"] if model["name"] == FIXED_MODEL_NAME
    )
    payload = copy.deepcopy(historical)
    payload["models"] = [
        tuned_result if model["name"] == FIXED_MODEL_NAME else model
        for model in payload["models"]
    ]
    for row, score in zip(
        payload["validation_predictions"], validation_scores, strict=True
    ):
        row["scores"][FIXED_MODEL_NAME] = float(score)
    payload["historical_fixed_logistic_regression"] = previous_logreg

    MODEL_DIRECTORY.mkdir(parents=True, exist_ok=True)
    OUTPUT_DIRECTORY.mkdir(parents=True)
    joblib.dump(search.best_estimator_, MODEL_PATH)

    predictions_digest = hashlib.sha256(
        json.dumps(
            payload["validation_predictions"],
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()
    metadata = payload["metadata"]
    metadata["created_at_utc"] = datetime.now(timezone.utc).isoformat()
    metadata["command"] = "python ml/run_val2025_comparison_lr_cv.py"
    metadata["python"] = sys.version
    metadata["library_versions"]["scikit_learn"] = sklearn.__version__
    metadata["logistic_regression_search"] = {
        "method": "GridSearchCV, 3-fold StratifiedKFold on training rows only",
        "scoring": "average_precision",
        "random_state": SEED,
        "solver": "liblinear",
        "parameter_grid": PARAMETER_GRID,
        "best_params": search.best_params_,
        "best_score": float(search.best_score_),
        "candidates": tuned_result["training_cv"]["candidates"],
        "threshold_selection": (
            "Maximum F1 on 3-fold out-of-fold training probabilities; validation "
            "labels not used."
        ),
    }
    metadata["seeds"]["logistic_regression_grid_search"] = SEED
    metadata["split"]["test_split_opened"] = False
    metadata["hashes_sha256"]["logreg_model"] = sha256_file(MODEL_PATH)
    metadata["hashes_sha256"]["comparison_script"] = sha256_file(Path(__file__))
    metadata["hashes_sha256"]["validation_predictions"] = predictions_digest

    pr_path = OUTPUT_DIRECTORY / "val2025_pr_curve.svg"
    top_k_path = OUTPUT_DIRECTORY / "val2025_top_k.svg"
    pr_path.write_text(_pr_curve_svg(payload) + "\n", encoding="utf-8")
    top_k_path.write_text(_top_k_svg(payload) + "\n", encoding="utf-8")
    metadata["hashes_sha256"]["pr_curve_chart"] = sha256_file(pr_path)
    metadata["hashes_sha256"]["top_k_chart"] = sha256_file(top_k_path)
    payload["calibration_diagnostics"] = _calibration_diagnostics(payload)
    payload["console_log"] = "\n".join(
        [
            "Validation 2025 Logistic Regression tuning; test split not opened.",
            f"Training rows={len(train)} positives={int(y_train.sum())}",
            f"Validation rows={len(validation)} positives={int(y_validation.sum())}",
            "Feature encoders and TF-IDF fitted on training rows only.",
            "GridSearchCV: 3-fold stratified training-only CV, scoring=average_precision.",
            f"Selected parameters: {search.best_params_}",
            f"Selected mean CV average precision={search.best_score_:.6f}",
            f"Training OOF F1 threshold={threshold:.10g}",
            f"Saved tuned Logistic Regression: {MODEL_PATH.relative_to(ROOT)}",
        ]
    )

    tuned_metrics = tuned_result["metrics"]
    candidate_lines = [
        "| C | class_weight | Mean CV average precision | CV standard deviation |",
        "|---:|---|---:|---:|",
    ]
    for candidate in tuned_result["training_cv"]["candidates"]:
        params = candidate["params"]
        candidate_lines.append(
            f"| {params['C']:g} | {params['class_weight'] or 'None'} | "
            f"{candidate['mean_test_score']:.8f} | "
            f"{candidate['std_test_score']:.8f} |"
        )

    report_lines = [
        "# Validation 2025 model comparison — Logistic Regression tuned",
        "",
        f"- Command: `{metadata['command']}`",
        "- Run date: 2026-11-15. This is a new run; the 2026-11-14 report and model are unchanged.",
        f"- Split: {metadata['split']['train']} training; {metadata['split']['validation']} validation.",
        f"- Rows: train {len(train):,} ({int(y_train.sum()):,} positives); validation {len(validation):,} ({int(y_validation.sum()):,} positives).",
        "- The 2026 test split was not opened. Validation was loaded only after CV parameter selection and out-of-fold threshold selection on training rows.",
        "- The 152-feature encoder and TF-IDF pipeline was fitted on training rows only. KEV and EPSS are excluded from model features.",
        "- Logistic Regression grid: `C` in `[0.01, 0.1, 1, 10, 100]`; `class_weight` in `[None, \"balanced\"]`; solver `liblinear`; random seed 42.",
        f"- Selected parameters: `{json.dumps(search.best_params_, sort_keys=True)}`; mean CV average precision `{search.best_score_:.8f}`.",
        "- Decision threshold selected by maximum F1 on 3-fold out-of-fold training probabilities; the validation labels do not select the threshold.",
        "",
        "## Logistic Regression CV scores",
        "",
        *candidate_lines,
        "",
        "## Fixed vs tuned Logistic Regression on Validation 2025",
        "",
        "| Run | PR-AUC | Precision | Recall | F1 | ROC-AUC | P@50 | P@100 | P@500 | R@50 | R@100 | R@500 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
        f"| Fixed (2026-11-14; C=1, class_weight=balanced) {_metric_line(previous_logreg)}",
        f"| Tuned (2026-11-15; C={search.best_params_['C']:g}, class_weight={search.best_params_['class_weight'] or 'None'}) {_metric_line(tuned_result)}",
        "",
        "## Current Validation 2025 comparison",
        "",
        "| Model | PR-AUC | Precision | Recall | F1 | ROC-AUC | P@50 | P@100 | P@500 | R@50 | R@100 | R@500 |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for model in payload["models"]:
        report_lines.append(f"| {model['name']} {_metric_line(model)}")
    report_lines.extend(
        [
            "",
            "## Thresholds and CV details",
            "",
            f"- Tuned Logistic Regression threshold: `{threshold:.10g}`; validation confusion matrix: `{tuned_metrics['confusion_matrix']['rows_actual_columns_predicted']}`.",
            "- The Random Forest, XGBoost calibrated, CVSS-only, and EPSS baseline results and predictions are reused unchanged from the 2026-11-14 run; those models were not retrained.",
            "- Frozen XGBoost calibrator exception: its sigmoid calibrator was historically fitted on Validation 2025. The artifact and its validation results were reused read-only.",
            "- EPSS is a hindsight baseline. Top-K ties sort by score descending then CVE identifier ascending.",
            "- PR-AUC uncertainty is a 200-resample percentile bootstrap 95% interval; one-class samples are skipped.",
            "",
            "## Reproducibility and artifacts",
            "",
            "- Complete validation predictions, scores, metrics, thresholds, CV candidate scores, versions, seeds and SHA-256 hashes are in `val2025_comparison.json`.",
            f"- Tuned model: `ml/models/{MODEL_PATH.name}` ({metadata['hashes_sha256']['logreg_model']}).",
            "- Historical fixed-parameter run remains available at `docs/results_offline/2026-11-14/`; neither its result files nor model was overwritten.",
            "",
            "![Validation 2025 precision-recall curves](./val2025_pr_curve.svg)",
            "",
            "![Validation 2025 precision at K](./val2025_top_k.svg)",
            "",
            _comparison_note(payload),
            "",
            "## Calibration diagnostics",
            "",
            "| Model | Brier score | ECE (10 equal-count bins) |",
            "|---|---:|---:|",
        ]
    )
    report_lines.extend(
        f"| {name} | {values['brier_score']:.6f} | "
        f"{values['expected_calibration_error_10_equal_count_bins']:.6f} |"
        for name, values in payload["calibration_diagnostics"].items()
    )
    report_lines.extend(
        [
            "",
            "Calibration diagnostics are descriptive. No new calibrator was fitted on Validation 2025 for this run; the frozen XGBoost calibrator remains a disclosed historical exception.",
            "",
        ]
    )

    (OUTPUT_DIRECTORY / "val2025_comparison.md").write_text(
        "\n".join(report_lines), encoding="utf-8"
    )
    (OUTPUT_DIRECTORY / "val2025_comparison.json").write_text(
        json.dumps(payload, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    print(payload["console_log"])
    print(f"Wrote {OUTPUT_DIRECTORY.relative_to(ROOT)}")


if __name__ == "__main__":
    run()
