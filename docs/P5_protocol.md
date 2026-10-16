# P5: Final Test Evaluation Protocol
* **Single Execution Command:** python ml/run_pipeline.py --final --config frozen_config.json
* **Frozen Model:** data/processed/headline_model_calibrated.joblib
* **Evaluation Dataset:** data/processed/test_2026-10-08.csv (Strictly untouched; no parameter tuning or re-runs permitted).
* **Metrics:** PR-AUC, Precision@K and Recall@K (K = 50, 100, 500).
* **Comparisons:**
  * CVSS ranking baseline (uniform random tie-breaking across 100 runs).
  * EPSS hindsight baseline (from snapshot).
  * Paired bootstrap (1,000 resamples) reporting mean differences and 95% confidence intervals for PR-AUC, P@100, and P@500 against CVSS.
* **Sub-groups:** Metrics evaluated separately on 1-30 day exploitation vs. same-day/earlier exploitation using the isolated positive masking method.
* **Calibration:** 2026 out-of-sample reliability table with bin counts and Brier score.
* **Reporting:** All metrics reported exactly as produced into docs/results/p5/ with cryptographic manifest.
