# Proposal Traceability

This trace maps the proposal requirements provided for Ashley's submission to
the current checked-in implementation. Evidence references name repository
files and functions rather than line numbers. Statuses describe the
implementation, not whether a recorded model result is favorable.

| Requirement | Status | Code evidence and notes |
|---|---|---|
| a. Manage assets and findings with search, filters, and status tracking | MET | Asset CRUD is handled by `create_asset`, `update_asset`, `delete_asset`, and `get_assets` in `backend/main.py`; `AssetsView` in `frontend/src/components/assets/AssetsView.tsx` provides client-side search across name, IP/domain, and owner, plus exposure, environment, and review-status filters. Findings use `get_findings` for query/priority/status/asset/sort/pagination and `update_status` for status changes in `backend/main.py`; `FindingsView` in `frontend/src/components/findings/FindingsView.tsx` exposes the finding queue and status action. |
| b. Import scanner-export CSVs and look up CVEs from the prepared dataset | MET | `detect_format` and `parse_and_validate` in `backend/csv_import.py` implement scanner-format detection and parsing; `preview_csv` and `commit_csv` in `backend/main.py` implement import preview and commit. `lookup_catalog` and `search_catalog` in `backend/cve_dataset.py` serve the prepared catalog. The catalog is loaded via `scripts/load_cve_catalog.py`; on a fresh clone lookups fall back to the live provider. CSV import is not active scanning. |
| c. Predict exploit likelihood per CVE from NVD features and KEV labels, excluding KEV/EPSS as features | DEVIATION-DOCUMENTED | The proposal labels a CVE positive if it appears in KEV, while the implemented label requires it to be in KEV and added within 30 days of publication (see `Decision_Log.md`). `_feature_row` and `predict_exploit_likelihood` in `backend/ml_inference.py` assemble features and predict; the model-bundle loader rejects KEV/EPSS feature names. |
| d. Combine likelihood with exposure and criticality into four `ml_asset` tiers, and state what default mode does | DEVIATION-DOCUMENTED | Risk factors and tier cutoffs are in `backend/rules_config.py`; `resolve_final_priority` in `backend/scoring_engine.py` selects the final tier and applies the post-prediction KEV floor. Unset `PRIORITY_MODE` defaults to `ml_asset`; `deterministic` remains selectable. D-043 records the default and the retained High floor as the documented proposal deviation. |
| e. Explain priority decisions and provide a recommended action | MET | Rule rationale is assembled by `calculate_priority` in `backend/scoring_engine.py`. `recommended_action_for_priority` in `backend/rules_config.py` selects a fixed template from the final tier at response/export time. The finding-list, detail, and scan routes in `backend/main.py` return that action independently of ML availability; `FindingDetailsDrawer` displays it separately from `ml_recommended_action`. The CSV and executive PDF exports in `backend/reports.py` include the final-tier action. |
| f. Provide RBAC, an audit log, dashboard, and PDF/CSV export | MET | JWT authentication and user roles are in `backend/auth.py` and `backend/users.py`; audit-log protections are defined by `AuditLog` in `backend/models.py` and the PostgreSQL audit migrations. `get_dashboard_analytics` in `backend/main.py` returns dashboard metrics. CSV and PDF exports are implemented by `export_findings_csv` and `export_executive_pdf` in `backend/reports.py`. |
| g. Compare Logistic Regression, Random Forest, and XGBoost with CVSS-only and EPSS baselines using the requested metrics and time-based split; tune by training-only CV | PARTIAL | The dated Validation 2025 comparison includes same-row results and metrics. Logistic Regression is tuned with a 10-candidate grid over `C` and `class_weight` using 3-fold stratified CV on training rows only; its threshold is selected from training-only out-of-fold predictions. Random Forest was also tuned by training-only CV. XGBoost remains a frozen artifact whose sigmoid calibrator was fitted on Validation 2025, a disclosed exception; it was not refit or described as training-only tuned. The 2026 test split was opened once, for the frozen XGBoost vs CVSS comparison; LR, RF and EPSS have no test result. The fixed-parameter LR run remains available as a historical record. Details are in `docs/ML_GAPS.md` and `docs/results_offline/2026-11-15/val2025_comparison.md`. |
| h. Explain model predictions with SHAP | MET | `_explanation_contributions` in `backend/ml_inference.py` uses native XGBoost TreeSHAP contributions (`pred_contribs`) and verifies contributions plus bias against the booster margin; the scan evidence panel and `FindingDetailsDrawer` display top factors. |
| i. Use PostgreSQL, Docker, FastAPI, and Next.js/TypeScript | MET | PostgreSQL configuration is in `backend/database.py`; FastAPI routes are in `backend/main.py`; service definitions are in `docker-compose.yml`; Next.js and TypeScript dependencies/configuration are in `frontend/package.json` and `frontend/tsconfig.json`. |
| j. Keep scanning, auto-patching, LLM agents, and a mobile app out of scope | MET | The product accepts scanner CSV imports and does not implement host/network scanning, automatic patching, LLM agents, or a mobile client. `ImportView` in `frontend/src/components/import/ImportView.tsx` describes scanner imports, and the frontend is a Next.js web application. |

## Status totals

| MET | PARTIAL | MISSING | DEVIATION-DOCUMENTED |
|---:|---:|---:|---:|
| 7 | 1 | 0 | 2 |

The remaining partial is the model-tuning/calibration protocol. The totals count
each of the ten requirement rows once: seven MET, one PARTIAL, none MISSING,
and two DEVIATION-DOCUMENTED. Requirement c documents the narrower KEV label
window; requirement d documents the retained post-prediction High floor for
known-exploited findings. The runtime default is now proposal-aligned
`ml_asset` (D-043).

## Pending non-code requirements and validation

- The submitted master blueprint and its exact Section 18 viva questions are
  absent from this checkout; obtain them before claiming verbatim criterion or
  viva-question sign-off.
- The manual browser/UI checklist has not been completed.
- A draft `docker-compose.tls.yml` overlay provides local HTTPS but is
  unvalidated. Production still requires a real certificate and deployment
  validation.
- Full PostgreSQL suite: 529 passed, 0 failed (pytest -v via the Docker
  `postgres-tests` profile, 2026-11-25, commit 7b38e1d, with the working-tree
  `backend/` and `alembic/` mounted). Earlier recorded counts (501) predate
  these changes and are historical.
