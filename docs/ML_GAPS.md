# Offline ML comparison

## What is recorded here

The historical logs below remain useful context, but the dated comparison now
provides a like-for-like Validation 2025 evaluation of the three model families
and both baselines:

| Model | Recorded split evidence | Status |
|---|---|---|
| XGBoost | Test 2026 calibrated result and Validation 2025 reference/ablation results | Available, but not every entry is a like-for-like comparison |
| Logistic Regression | Historical ablations plus full 152-feature comparison | Validation 2025 comparison is available; no test result is recorded |
| Random Forest | Dated 152-feature comparison | Validation 2025 comparison is available; no test result is recorded |

`docs/results/p5/p5_console.log` records calibrated XGBoost Test 2026 PR-AUC
`0.0114`, CVSS Test 2026 PR-AUC `0.0117 +/- 0.0018`, and XGBoost Validation
2025 reference PR-AUC `0.0352`. `docs/results/pipeline_output.txt` records
Logistic Regression Validation 2025 PR-AUCs `0.0148 +/- 0.0000` (CVSS-only)
and `0.0241 +/- 0.0000` (text-masked), plus XGBoost Validation 2025 ablation
PR-AUCs `0.0152 +/- 0.0000` (CVSS-only) and `0.0540 +/- 0.0000`
(text-masked). These are different model configurations and are not a complete,
single-protocol three-family comparison. The complete comparison is in
[`results_offline/2026-11-14/val2025_comparison.md`](results_offline/2026-11-14/val2025_comparison.md);
raw validation predictions, metrics, thresholds, confusion matrices, seeds,
versions, hashes and console log are in the adjacent JSON. The PR and top-K
charts can be regenerated with `python ml/render_val2025_charts.py`.

## Offline deliverables checklist

1. **Completed:** a versioned, reproducible evaluation package for XGBoost, Random Forest, and
   Logistic Regression on the **same 2025 validation split**. Include model
   family, feature set, hyperparameters, package versions, seeds, and the exact
   train/validation date boundaries.
2. **Completed:** one validation-only predicted probability per example and model/configuration,
   with stable example identifiers, labels, row and positive counts, and hashes
   for the split manifests and outputs. Do not include features derived from
   KEV or EPSS.
3. **Completed:** comparable validation metrics for every family/configuration: PR-AUC and its
   uncertainty, precision/recall at agreed K values, calibration, and the
   positive/base-rate counts. Explain tie handling, bootstrap method, and any
   missing metrics rather than substituting estimates.
4. **Completed:** the complete raw validation output, a concise summary table, and commands
   sufficient to reproduce it without accessing the frozen test partition.
5. If a final generalization claim is needed, propose a future prospective
   holdout that has not been used for fitting, threshold selection, or model
   comparison; do not reuse the existing 2026 test set for this request.

## Scope and frozen-model caveat

The comparison did not open the 2026 test partition, did not modify
`frozen_config.json`, `docs/results/`, or any `headline_*` artifact, and used
the recorded train and validation hashes. The existing frozen XGBoost model
was read-only; its sigmoid calibration had already been fit on Validation 2025,
which is disclosed in the generated report. New LR/RF artifacts have dated
names and are not used by live scan inference.

## Offline model comparison: rules for Random Forest and Logistic Regression runs

Goal: complete the proposal's three-model comparison (Logistic Regression, Random Forest, XGBoost) against CVSS-only and EPSS baselines, without invalidating the frozen XGBoost result.

Protocol (must match the frozen pipeline):
1. Same data snapshot, labels and feature list (frozen_config.json features; no KEV/EPSS as features), same chronological train/validation split. Fit encoders, TF-IDF and any resampling on the training split only.
2. Tuning: cross-validation on the training split only; fixed random seeds; record seeds, parameter grids and the selected parameters.
3. Class imbalance: class weights (or training-set resampling) only; never rebalance validation or test data.
4. Evaluate on Validation 2025 first. Metrics: PR-AUC (primary), precision/recall/F1 at a stated threshold, precision and recall at K (50, 100, 500), ROC-AUC (secondary), confusion matrix. Report the same metrics for the CVSS-only and EPSS baselines on the same rows.
5. Test set: the frozen test result for XGBoost already exists. Do NOT use the test set to select, tune or compare models. If a test evaluation of the other models is still wanted, run it once, label it "post-hoc: XGBoost test result was already known", and keep the XGBoost-vs-CVSS test result as the headline.
6. Never overwrite frozen artifacts: do not modify frozen_config.json, docs/results/p5, ml/models/headline_*. Save new models with a dated, versioned name (e.g. ml/models/rf_<date>.joblib) and write new results to a new folder (e.g. docs/results_offline/<date>/), including the exact command, library versions (xgboost, scikit-learn, python), data snapshot dates, seeds, file SHA-256 hashes, and the console log.
7. Report real numbers only, including negative results. State clearly which split each number is from.
8. Integration: the dated offline result is now read-only in `backend/model_results.py` and displayed with its split label. Newly trained LR/RF are not wired into live scan inference; only the existing frozen XGBoost model is used for ML advisory scoring.
Deliverables for the report: one results table (models and baselines, same rows), PR curve, top-K chart, and a written paragraph on where each model wins and fails.
