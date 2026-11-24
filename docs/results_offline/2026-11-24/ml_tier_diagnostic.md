# Validation-2025 ML tier diagnostic

- Dataset: `C:\Users\Cornellious\SecureVision\data\processed\master_cves_2026-10-08.csv`
- Included rows: published 2025-01-01 through 2025-12-31 only.
- Rows published outside 2025 were routed using `published_date` only; no other fields from those rows were inspected or used.
- Validation rows: 48152; positives: 126; negatives: 48026.
- Sample: all 126 positives plus 2000 randomly selected negatives (seed 42); negative weight: 24.01300000.
- Frozen model: `headline_model_calibrated.joblib:1390b1e65ff9`.
- Runtime: 40.733 seconds.

## A. Threshold provenance

- `Decision_Log.md` D-023 records thresholds from Validation 2025 (48,152 CVEs; 481,520 risk values), using all ten exposure/criticality combinations: Internet/Internal crossed with criticality 1-5.
- The recorded formula is `ml_risk = likelihood × exposure_factor × criticality_factor`; thresholds are P99 Critical, P90 High, and P50 Medium, with Low below P50.
- Runtime constants: Critical `0.044082497805357`, High `0.00705601121066138`, Medium `0.000854613399133086`; percentile settings: `{"Critical": 99, "High": 90, "Medium": 50}`.
- Threshold-generation script: **unverified**. Repository search found the recorded method in D-023 and runtime constants, but no reproducible script that generated the three values. `scripts/priority_distribution.py` is a distinct 40-CVE sample diagnostic, not the threshold-generation script.

## B. Prediction parity with saved Validation 2025 predictions

- Matched by CVE ID: 2126 of 2126 sampled rows; unmatched: 0; label mismatches: 0.
- Mean absolute difference: 0.00307745906428.
- Maximum absolute difference: 0.0825621361582.
- Rows differing by more than 1e-6: 2125.
- Spearman correlation: -0.351209873128.
- Runtime path: `backend.ml_inference._feature_row` plus the frozen model's `predict_proba`; SHAP explanations were bypassed. Saved scores are the `XGBoost calibrated` entries from `docs/results_offline/2026-11-14/val2025_comparison.json`.
- Frozen XGBoost SHA-256 recorded by the saved comparison: `1390b1e65ff9bbf9dc3a3f37659a577c32af0f7aac9bb47711f8394331bc8ed1`; runtime artifact hash prefix: `1390b1e65ff9`.

## C. Weighted tier distribution

- Table share estimates use all positives and weight each sampled negative by validation negatives / 2,000. Positive distribution is the share of all validation positives. Weighted precision is weighted positives / weighted rows within the raw `ml_priority` tier; no KEV floor is applied.
- The 1/9/40/50 target is the documented pooled target across ten contexts. Individual profile rows are shown for diagnosis and need not independently meet the pooled target.

| Profile | Tier | Estimated share | Intended reference | Difference (pp) | Positive rows (share) | Weighted precision |
|---|---|---:|---:|---:|---:|---:|
| Internet / criticality 5 | Critical | 0.0000% | 1.0000% | -1.0000 | 0 (0.0000%) | not available |
| Internet / criticality 5 | High | 0.0000% | 9.0000% | -9.0000 | 0 (0.0000%) | not available |
| Internet / criticality 5 | Medium | 0.3512% | 40.0000% | -39.6488 | 1 (0.7937%) | 0.5914% |
| Internet / criticality 5 | Low | 99.6488% | 50.0000% | +49.6488 | 125 (99.2063%) | 0.2605% |
| Internal / criticality 2 | Critical | 0.0000% | 1.0000% | -1.0000 | 0 (0.0000%) | not available |
| Internal / criticality 2 | High | 0.0000% | 9.0000% | -9.0000 | 0 (0.0000%) | not available |
| Internal / criticality 2 | Medium | 0.0000% | 40.0000% | -40.0000 | 0 (0.0000%) | not available |
| Internal / criticality 2 | Low | 100.0000% | 50.0000% | +50.0000 | 126 (100.0000%) | 0.2617% |
| Internal / criticality 3 | Critical | 0.0000% | 1.0000% | -1.0000 | 0 (0.0000%) | not available |
| Internal / criticality 3 | High | 0.0000% | 9.0000% | -9.0000 | 0 (0.0000%) | not available |
| Internal / criticality 3 | Medium | 0.0000% | 40.0000% | -40.0000 | 0 (0.0000%) | not available |
| Internal / criticality 3 | Low | 100.0000% | 50.0000% | +50.0000 | 126 (100.0000%) | 0.2617% |

### Combined three-profile reference

- This combines only the three requested profiles, not all ten contexts used in the documented threshold derivation.

| Tier | Estimated share | Intended reference | Positive scenarios (share) | Weighted precision |
|---|---:|---:|---:|---:|
| Critical | 0.0000% | 1.0000% | 0 (0.0000%) | not available |
| High | 0.0000% | 9.0000% | 0 (0.0000%) | not available |
| Medium | 0.1171% | 40.0000% | 1 (0.2646%) | 0.5914% |
| Low | 99.8829% | 50.0000% | 377 (99.7354%) | 0.2613% |

### Saved-prediction reference on the same sampled CVE IDs

- This applies the same risk formula and thresholds to the saved Validation 2025 scores, not to the runtime inference output. It is a useful parity reference only; the reported requested distribution above is from `backend.ml_inference`.

| Profile | Tier | Saved-score estimated share | Intended reference |
|---|---|---:|---:|
| Internet / criticality 5 | Critical | 2.5287% | 1.0000% |
| Internet / criticality 5 | High | 11.8189% | 9.0000% |
| Internet / criticality 5 | Medium | 58.8227% | 40.0000% |
| Internet / criticality 5 | Low | 26.8296% | 50.0000% |
| Internal / criticality 2 | Critical | 0.1558% | 1.0000% |
| Internal / criticality 2 | High | 6.6720% | 9.0000% |
| Internal / criticality 2 | Medium | 28.6228% | 40.0000% |
| Internal / criticality 2 | Low | 64.5494% | 50.0000% |
| Internal / criticality 3 | Critical | 0.3179% | 1.0000% |
| Internal / criticality 3 | High | 8.6647% | 9.0000% |
| Internal / criticality 3 | Medium | 34.1084% | 40.0000% |
| Internal / criticality 3 | Low | 56.9090% | 50.0000% |

#### Combined saved-score three-profile reference

| Tier | Saved-score estimated share | Intended reference |
|---|---:|---:|
| Critical | 1.0008% | 1.0000% |
| High | 9.0519% | 9.0000% |
| Medium | 40.5180% | 40.0000% |
| Low | 49.4293% | 50.0000% |

## D. Verdict

- Evidence supports explanation (2): inference does not reproduce saved Validation 2025 predictions within the 1e-6 tolerance. With the saved and runtime model hashes matching, the most likely area is the train/serve feature path: `backend/ml_inference.py` `_feature_row`'s TF-IDF transform/input (lines 194-198) versus the separately fitted vectorizer in `ml/run_val2025_comparison.py` `_build_features` (lines 160-171). `_load_bundle` checks the TF-IDF vocabulary hash (lines 110-116), but not its IDF values. Vector parsing (lines 173-179), CWE encoding (lines 181-192), missing-value handling, and dense feature ordering (line 198) also warrant comparison. The prediction metrics alone do not isolate the cause; the specific feature mismatch is **unverified**.
- The recorded threshold formula and ten-profile method agree with the documented runtime formula; no evidence here supports explanation (3). The generating script remains **unverified**.

## Scope and reproducibility

- Run `python -m scripts.ml_tier_diagnostic` from the repository root with the dataset available at `CVE_DATASET_PATH` (default: `C:\Users\Cornellious\SecureVision\data\processed\master_cves_2026-10-08.csv`).
- The script uses a streaming reservoir sample with seed 42, then calls the inference feature builder and frozen model directly so SHAP is not run.
- It does not import or execute `scripts/priority_distribution.py`, modify backend code/configuration, or access the securevision SQLite databases.
