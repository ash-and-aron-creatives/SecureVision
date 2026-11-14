# Proposal Traceability

This trace maps the proposal requirements provided for Ashley's submission to
the current checked-in implementation. Evidence references use repository
paths and 1-based line numbers. Statuses describe the implementation, not
whether a recorded model result is favorable.

| Requirement | Status | Code evidence and notes |
|---|---|---|
| a. Manage assets and findings with search, filters, and status tracking | PARTIAL | Asset CRUD is available through `backend/main.py:250-358` and `frontend/src/components/assets/AssetsView.tsx:10-129`, but the asset list has no search/filter controls. Findings support query, priority, status, asset, sort, and pagination in `backend/main.py:710-718`; status changes are implemented at `backend/main.py:687-708` and shown in `frontend/src/components/findings/FindingsView.tsx:52-61`. |
| b. Import scanner-export CSVs and look up CVEs from the prepared dataset | MET | Scanner format detection and row parsing are in `backend/csv_import.py:56-145`; the preview/commit API is `backend/main.py:1030-1064`. Catalog lookup/search are `backend/cve_dataset.py:22-43`; the optional prepared CSV is loaded explicitly by `scripts/load_cve_catalog.py`, and `backend/main.py:431-490` serves catalog/cache lookup and search. CSV import is not active scanning. |
| c. Predict exploit likelihood per CVE from NVD features and KEV labels, excluding KEV/EPSS as features | MET | Feature assembly and prediction are in `backend/ml_inference.py:156-198` and `backend/ml_inference.py:275-330`; the loader rejects feature names containing KEV or EPSS at `backend/ml_inference.py:99-110`. The KEV-label definition, chronological split, and NVD model source are recorded in `Decision_Log.md:7,13,20` and `docs/results_offline/2026-11-14/val2025_comparison.md:3-6`. |
| d. Combine likelihood with exposure and criticality into four `ml_asset` tiers, and state what default mode does | DEVIATION-DOCUMENTED | Risk factors and tier cutoffs are `backend/rules_config.py:10-12,188-230`; final selection and the post-prediction KEV floor are `backend/scoring_engine.py:29-40`. Unset `PRIORITY_MODE` is `deterministic` (`backend/rules_config.py:6`): it stores the 320-rule tier, source `rules`, and uses ML only as advisory. The default-mode difference is DEVIATION-DOCUMENTED by D-038/D-039. The implemented post-prediction High KEV floor is also DEVIATION-DOCUMENTED by D-033; it applies only in ML mode when it raises a lower ML tier. |
| e. Explain priority decisions and provide a recommended action | MET | Rule rationale is assembled by `backend/scoring_engine.py:67-142`. Per-tier ML actions are defined in `backend/rules_config.py:194-199`, returned by `backend/ml_inference.py:310-324`, and displayed with the final tier and rule cross-check in `frontend/src/components/findings/FindingDetailsDrawer.tsx:42-114`. An action is unavailable when ML inference is unavailable. |
| f. Provide RBAC, an audit log, dashboard, and PDF/CSV export | MET | JWT authentication and user roles are in `backend/auth.py:10-23` and `backend/users.py:19-25`; the audit model and immutability hooks are `backend/models.py:103-119`, with database triggers in `alembic/versions/0001_initial_postgresql_schema.py:89-113` and `alembic/versions/0002_prevent_audit_log_truncate.py:17-24`. Dashboard response and route are `backend/schemas.py:211-230` and `backend/main.py:803-924`. CSV/PDF exports are in `backend/reports.py:84-139,160-240`. |
| g. Compare Logistic Regression, Random Forest, and XGBoost with CVSS-only and EPSS baselines using the requested metrics and time-based split; tune by training-only CV | PARTIAL | Same-row Validation 2025 results (PR-AUC, precision, recall, F1, ROC-AUC, precision/recall at K) and the chronological split are in `docs/results_offline/2026-11-14/val2025_comparison.md:3-20`. Random Forest was tuned with 3-fold randomized CV on training rows only. Logistic Regression used fixed `C=1.0` and `class_weight=balanced`; its 3-fold out-of-fold predictions selected the threshold, not its hyperparameters. Frozen XGBoost has a validation-fitted sigmoid calibrator and was not tuned by this train-only CV. No LR/RF test result exists, and the known 2026 test split was not opened. Details are in `docs/ML_GAPS.md` and the dated validation report. |
| h. Explain model predictions with SHAP | MET | SHAP TreeExplainer and native XGBoost contribution fallback are in `backend/ml_inference.py:226-263`; the UI displays the top factors at `frontend/src/components/findings/FindingDetailsDrawer.tsx:96-109`. |
| i. Use PostgreSQL, Docker, FastAPI, and Next.js/TypeScript | MET | PostgreSQL and FastAPI runtime/deployment are evidenced by `backend/database.py:1-20`, `backend/main.py:1-40`, and `docker-compose.yml:1-105`; the frontend uses Next.js/TypeScript (`frontend/package.json:1-29`, `frontend/tsconfig.json`). |
| j. Keep scanning, auto-patching, LLM agents, and a mobile app out of scope | MET | The product accepts scanner CSV imports (`backend/csv_import.py:56-145`) and does not implement host/network scanning, automatic patching, LLM agents, or a mobile client. The UI describes scanner imports rather than active scanning in `frontend/src/components/import/ImportView.tsx:17-31`; the repository frontend is a Next.js web app (`frontend/package.json:1-29`). |

## Status totals

| MET | PARTIAL | MISSING | DEVIATION-DOCUMENTED |
|---:|---:|---:|---:|
| 7 | 2 | 0 | 1 |

The two partials are asset search/filter coverage and the model-tuning/calibration
protocol. Requirement d has one DEVIATION-DOCUMENTED status row containing both
documented items: the proposal-target mode is `ml_asset`, but the runtime
default is `deterministic` under D-038/D-039; D-033 documents the rules-layer
High floor for known-exploited findings in `ml_asset` mode.
