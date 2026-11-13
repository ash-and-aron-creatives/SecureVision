# Offline ML comparison gaps

## What is recorded here

The checked-in evaluation outputs identify these model families and splits:

| Model | Recorded split evidence | Status |
|---|---|---|
| XGBoost | Test 2026 calibrated result and Validation 2025 reference/ablation results | Available, but not every entry is a like-for-like comparison |
| Logistic Regression | Validation 2025 CVSS-only and text-masked ablations | Validation results only; no test result is recorded |
| Random Forest | No evaluation row or metric in the recorded outputs | Not available |

`docs/results/p5/p5_console.log` records calibrated XGBoost Test 2026 PR-AUC
`0.0114`, CVSS Test 2026 PR-AUC `0.0117 +/- 0.0018`, and XGBoost Validation
2025 reference PR-AUC `0.0352`. `docs/results/pipeline_output.txt` records
Logistic Regression Validation 2025 PR-AUCs `0.0148 +/- 0.0000` (CVSS-only)
and `0.0241 +/- 0.0000` (text-masked), plus XGBoost Validation 2025 ablation
PR-AUCs `0.0152 +/- 0.0000` (CVSS-only) and `0.0540 +/- 0.0000`
(text-masked). These are different model configurations and are not a complete,
single-protocol three-family comparison.

## Offline deliverables Ashley must produce

1. A versioned, reproducible evaluation package for XGBoost, Random Forest, and
   Logistic Regression on the **same 2025 validation split**. Include model
   family, feature set, hyperparameters, package versions, seeds, and the exact
   train/validation date boundaries.
2. One validation-only predicted probability per example and model/configuration,
   with stable example identifiers, labels, row and positive counts, and hashes
   for the split manifests and outputs. Do not include features derived from
   KEV or EPSS.
3. Comparable validation metrics for every family/configuration: PR-AUC and its
   uncertainty, precision/recall at agreed K values, calibration, and the
   positive/base-rate counts. Explain tie handling, bootstrap method, and any
   missing metrics rather than substituting estimates.
4. The complete raw validation output, a concise summary table, and commands
   sufficient to reproduce it without accessing the frozen test partition.
5. If a final generalization claim is needed, propose a future prospective
   holdout that has not been used for fitting, threshold selection, or model
   comparison; do not reuse the existing 2026 test set for this request.

## Why these results cannot be generated in this change

This work is explicitly prohibited from retraining, modifying frozen models or
configuration, evaluating any model on the test set, or touching
`docs/results/`. The repository contains no recorded Random Forest evaluation
and no common three-family validation output. Therefore this change reads only
the committed result logs, reports missing entries as unavailable, and leaves
the offline comparison for Ashley to run under the project's approved data and
evaluation process.
