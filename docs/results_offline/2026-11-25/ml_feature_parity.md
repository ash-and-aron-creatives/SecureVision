# Validation 2025 ML feature parity

- Validation sample rows: 2126
- Dataset: `data/processed/master_cves_2026-10-08.csv`
- Saved predictions: `docs/results_offline/2026-11-14/val2025_comparison.json`
- Feature columns differing: 0

## Feature column differences

No differing feature columns.

## Saved-score comparison

| Input | Mean absolute difference | Max absolute difference | Spearman | Rows over 1e-6 |
| --- | ---: | ---: | ---: | ---: |
| dense serving features | 0.003077459064 | 0.08256213616 | -0.35120987 | 2125 |
| CSR serving features | 0 | 0 | 1.00000000 | 0 |

## Native XGBoost explanation

- Feature contributions plus bias matched the booster margin; absolute error: `8.465849533e-08`.
