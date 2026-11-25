# Offline ML comparison

## Serving parity and feature parsing caveats

D-042 records a Validation 2025-only train/serve parity check. The serving
feature columns matched the reference; dense rows did not preserve the frozen
model's sparse zero/missing semantics, while CSR inference matched the saved
scores exactly on all 2,126 checked rows (maximum absolute difference `0`,
Spearman `1.0`). This diagnostic did not read the 2026 test split or modify
the frozen model/configuration or protected results.

The same investigation confirmed a separate CVSS vector parsing limitation:
the runtime `C` and `I` patterns are unanchored, and the probe matched `C=L`
from `AC:L` and `I=N` from `UI:N` instead of the later `C:H` and `I:H`. The
repository's `ml/run_pipeline_final.py` writer parses AV/AC/PR/UI, not C/I, so
it does not define the full runtime pattern set. Treat this as a disclosed
limitation, not a claim that all vector fields have train/serve parity.

## What is recorded here

The historical logs below remain useful context, but the dated comparison now
provides a like-for-like Validation 2025 evaluation of the three model families
and both baselines:

| Model | Recorded split evidence | Status |
|---|---|---|
| XGBoost | Test 2026 calibrated result and Validation 2025 reference/ablation results | Available, but not every entry is a like-for-like comparison |
| Logistic Regression | Historical fixed-parameter comparison and new tuned 152-feature run | Validation 2025 comparison is available; no test result is recorded. The 2026-11-15 run selected `C=100`, `class_weight=None` (mean training-CV average precision `0.062506`) from a 10-candidate, 3-fold stratified CV grid. Validation PR-AUC is `0.021292`, compared with `0.020851` for the fixed `C=1.0`, `class_weight="balanced"` run retained in the 2026-11-14 folder. |
| Random Forest | Dated 152-feature comparison | Validation 2025 comparison is available; no test result is recorded. Parameters were selected by 3-fold randomized CV on training rows only. |
| XGBoost calibrated | Frozen artifact | Validation 2025 and Test 2026 metrics are recorded. The sigmoid calibrator was fitted on Validation 2025, so calibration was not training-only; this is a disclosed validation-fitted artifact, not a new fit in the dated comparison. |

`docs/results/p5/p5_console.log` records calibrated XGBoost Test 2026 PR-AUC
`0.0114`, CVSS Test 2026 PR-AUC `0.0117 +/- 0.0018`, and XGBoost Validation
2025 reference PR-AUC `0.0352`. `docs/results/pipeline_output.txt` records
Logistic Regression Validation 2025 PR-AUCs `0.0148 +/- 0.0000` (CVSS-only)
and `0.0241 +/- 0.0000` (text-masked), plus XGBoost Validation 2025 ablation
PR-AUCs `0.0152 +/- 0.0000` (CVSS-only) and `0.0540 +/- 0.0000`
(text-masked). These are different model configurations and are not a complete,
single-protocol three-family comparison. The fixed-parameter Logistic Regression comparison is preserved in
[`results_offline/2026-11-14/val2025_comparison.md`](results_offline/2026-11-14/val2025_comparison.md).
The new training-CV-tuned result is in
[`results_offline/2026-11-15/val2025_comparison.md`](results_offline/2026-11-15/val2025_comparison.md);
raw validation predictions, metrics, thresholds, confusion matrices, seeds,
versions, hashes and console log are in the adjacent JSON. The new run's PR
and top-K charts are included alongside the report; the historical 2026-11-14
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
2. Tuning: cross-validation on the training split only; fixed random seeds; record seeds, parameter grids, candidate CV scores and selected parameters. Logistic Regression uses the 10-candidate `C` / class-weight grid, and Random Forest uses its recorded 3-fold randomized search. Logistic Regression's F1 threshold is separately selected from 3-fold out-of-fold training probabilities. The frozen XGBoost calibrator was historically fitted on Validation 2025; disclose this exception and do not describe all three as training-CV-tuned.
3. Class imbalance: class weights (or training-set resampling) only; never rebalance validation or test data.
4. Evaluate on Validation 2025 first. Metrics: PR-AUC (primary), precision/recall/F1 at a stated threshold, precision and recall at K (50, 100, 500), ROC-AUC (secondary), confusion matrix. Report the same metrics for the CVSS-only and EPSS baselines on the same rows.
5. Test set: the frozen test result for XGBoost already exists. Do NOT use the test set to select, tune or compare models. If a test evaluation of the other models is still wanted, run it once, label it "post-hoc: XGBoost test result was already known", and keep the XGBoost-vs-CVSS test result as the headline.
6. Never overwrite frozen artifacts: do not modify frozen_config.json, docs/results/p5, ml/models/headline_*. Save new models with a dated, versioned name (e.g. ml/models/rf_<date>.joblib) and write new results to a new folder (e.g. docs/results_offline/<date>/), including the exact command, library versions (xgboost, scikit-learn, python), data snapshot dates, seeds, file SHA-256 hashes, and the console log.
7. Report real numbers only, including negative results. State clearly which split each number is from.
8. Integration: the dated offline result is now read-only in `backend/model_results.py` and displayed with its split label. Newly trained LR/RF are not wired into live scan inference; only the existing frozen XGBoost model is used for ML advisory scoring.
Deliverables for the report: one results table (models and baselines, same rows), PR curve, top-K chart, and a written paragraph on where each model wins and fails.

## Reviewer notes

- **Precision@K ties:** `ml/run_val2025_comparison.py::_top_k` ranks by descending score and then ascending CVE identifier using `np.lexsort((cve_ids, -scores))`. It takes exactly `min(K, row_count)` entries, so a score tie at the K boundary is resolved by CVE identifier rather than extending the selection past K.
- **XGBoost precision/recall/F1 threshold:** `ml/run_val2025_comparison.py` calls `_best_f1_threshold` on the unchanged frozen calibrated XGBoost model's probabilities for the 2022-2024 training rows and their labels. The threshold is the one maximizing training F1; `np.argmax` selects the first maximum. That selected threshold (`0.05650065467`) is applied to Validation 2025 to report precision, recall, F1, and the confusion matrix; validation labels do not select it. The model's sigmoid calibrator had previously been fitted on Validation 2025, and this comparison did not refit or modify the frozen artifact.
