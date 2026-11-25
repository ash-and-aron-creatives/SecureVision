# Validation-2025 ML tier diagnostic

- Dataset: `data/processed/master_cves_2026-10-08.csv`
- Included rows: published 2025-01-01 through 2025-12-31 only.
- Rows published outside 2025 were routed using `published_date` only; no other fields from those rows were inspected or used.
- Validation rows: 48152; positives: 126; negatives: 48026.
- Sample: all 126 positives plus 2000 randomly selected negatives (seed 42); negative weight: 24.01300000.
- Frozen model: `headline_model_calibrated.joblib:1390b1e65ff9`.
- Runtime: 55.177 seconds.

## A. Threshold provenance

- `Decision_Log.md` D-023 records thresholds from Validation 2025 (48,152 CVEs; 481,520 risk values), using all ten exposure/criticality combinations: Internet/Internal crossed with criticality 1-5.
- The recorded formula is `ml_risk = likelihood × exposure_factor × criticality_factor`; thresholds are P99 Critical, P90 High, and P50 Medium, with Low below P50.
- Runtime constants: Critical `0.044082497805357`, High `0.00705601121066138`, Medium `0.000854613399133086`; percentile settings: `{"Critical": 99, "High": 90, "Medium": 50}`.
- Threshold-generation script: **unverified**. Repository search found the recorded method in D-023 and runtime constants, but no reproducible script that generated the three values. `scripts/priority_distribution.py` is a distinct 40-CVE sample diagnostic, not the threshold-generation script.

## B. Prediction parity with saved Validation 2025 predictions

- Matched by CVE ID: 2126 of 2126 sampled rows; unmatched: 0; label mismatches: 0.
- Mean absolute difference: 0.
- Maximum absolute difference: 0.
- Rows differing by more than 1e-6: 0.
- Spearman correlation: 1.
- Runtime path: `backend.ml_inference._feature_row` plus the frozen model's `predict_proba`; SHAP explanations were bypassed. Saved scores are the `XGBoost calibrated` entries from `docs/results_offline/2026-11-14/val2025_comparison.json`.
- Frozen XGBoost SHA-256 recorded by the saved comparison: `1390b1e65ff9bbf9dc3a3f37659a577c32af0f7aac9bb47711f8394331bc8ed1`; runtime artifact hash prefix: `1390b1e65ff9`.

## C. Weighted tier distribution

- Table share estimates use all positives and weight each sampled negative by validation negatives / 2,000. Positive distribution is the share of all validation positives. Weighted precision is weighted positives / weighted rows within the raw `ml_priority` tier; no KEV floor is applied.
- The 1/9/40/50 target is the documented pooled target across ten contexts. Individual profile rows are shown for diagnosis and need not independently meet the pooled target.

| Profile | Tier | Estimated share | Intended reference | Difference (pp) | Positive rows (share) | Weighted precision |
|---|---|---:|---:|---:|---:|---:|
| Internet / criticality 5 | Critical | 2.5287% | 1.0000% | +1.5287 | 41 (32.5397%) | 3.3672% |
| Internet / criticality 5 | High | 11.8189% | 9.0000% | +2.8189 | 48 (38.0952%) | 0.8434% |
| Internet / criticality 5 | Medium | 58.8227% | 40.0000% | +18.8227 | 37 (29.3651%) | 0.1306% |
| Internet / criticality 5 | Low | 26.8296% | 50.0000% | -23.1704 | 0 (0.0000%) | 0.0000% |
| Internal / criticality 2 | Critical | 0.1558% | 1.0000% | -0.8442 | 3 (2.3810%) | 3.9979% |
| Internal / criticality 2 | High | 6.6720% | 9.0000% | -2.3280 | 67 (53.1746%) | 2.0855% |
| Internal / criticality 2 | Medium | 28.6228% | 40.0000% | -11.3772 | 47 (37.3016%) | 0.3410% |
| Internal / criticality 2 | Low | 64.5494% | 50.0000% | +14.5494 | 9 (7.1429%) | 0.0290% |
| Internal / criticality 3 | Critical | 0.3179% | 1.0000% | -0.6821 | 9 (7.1429%) | 5.8794% |
| Internal / criticality 3 | High | 8.6647% | 9.0000% | -0.3353 | 66 (52.3810%) | 1.5819% |
| Internal / criticality 3 | Medium | 34.1084% | 40.0000% | -5.8916 | 47 (37.3016%) | 0.2862% |
| Internal / criticality 3 | Low | 56.9090% | 50.0000% | +6.9090 | 4 (3.1746%) | 0.0146% |

### Combined three-profile reference

- This combines only the three requested profiles, not all ten contexts used in the documented threshold derivation.

| Tier | Estimated share | Intended reference | Positive scenarios (share) | Weighted precision |
|---|---:|---:|---:|---:|
| Critical | 1.0008% | 1.0000% | 53 (14.0212%) | 3.6659% |
| High | 9.0519% | 9.0000% | 181 (47.8836%) | 1.3842% |
| Medium | 40.5180% | 40.0000% | 131 (34.6561%) | 0.2238% |
| Low | 49.4293% | 50.0000% | 13 (3.4392%) | 0.0182% |

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

- Evidence supports explanation (1): inference reproduces the saved Validation 2025 likelihoods within 1e-6 on the sampled rows, while D-023 documents thresholds derived with the same risk formula and all ten supported asset contexts. That makes a material train/serve mismatch on this validation sample unlikely.
- The 80-scenario sample's 2026+ composition/distribution shift is a plausible explanation for all raw model tiers being Low, but it is **unverified** here: this diagnostic did not read or calculate from those sample rows.

## Scope and reproducibility

- Run `python -m scripts.ml_tier_diagnostic` from the repository root with the dataset available at `CVE_DATASET_PATH` (default: `data/processed/master_cves_2026-10-08.csv`).
- The script uses a streaming reservoir sample with seed 42, then calls the inference feature builder and frozen model directly so SHAP is not run.
- It does not import or execute `scripts/priority_distribution.py`, modify backend code/configuration, or access the securevision SQLite databases.
