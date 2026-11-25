# SecureVision Project Snapshot

Generated from the checked-out source and recorded artifacts on 2026-11-15.
Environment variable names are listed without values. The frozen test split and
protected `docs/results/p5` outputs were not opened; the Test 2026 table below
contains only values already transcribed in repository documentation.

## Repository tree (two levels)

Generated folders (`.git`, `venv`, `node_modules`, `.next`, caches) and protected
data files are omitted.

```text
.
|-- .env.example
|-- Dockerfile
|-- README.md
|-- BLUEPRINT_TRACEABILITY.md
|-- Decision_Log.md
|-- PROJECT_STATE.md
|-- UI_STYLING_GUIDE.md
|-- requirements.txt
|-- alembic.ini
|-- docker-compose.yml
|-- docker-compose.local.yml
|-- docker-compose.cve-dataset.yml
|-- dedupe_findings.py
|-- init_db.py
|-- postcss.config.js
|-- seed_db.py
|-- setup_dev.ps1
|-- update_admin.py
|-- upgrade_role.py
|-- alembic/
|   |-- env.py
|   |-- script.py.mako
|   `-- versions/
|-- backend/
|   |-- __init__.py, auth.py, check_db.py, csv_import.py
|   |-- cve_dataset.py, database.py, demo_seed.py, generate_matrix.py
|   |-- init_db.py, main.py, ml_inference.py, model_results.py
|   |-- models.py, reports.py, rules_config.py, schemas.py
|   |-- scoring_engine.py, test_scoring.py, threat_intel.py, users.py
|   `-- tests/
|-- data/
|   |-- processed/
|   `-- raw/
|-- docker/
|   `-- postgres/
|-- docs/
|   |-- ARCHITECTURE_AND_FLOWS.md, DEMO_SCRIPT.md, FREEZE.md
|   |-- FREEZE_ERRATA.md, ML_GAPS.md, P5_protocol.md
|   |-- PROPOSAL_TRACEABILITY.md, PROJECT_SNAPSHOT.md, UI_CHECKLIST.md
|   |-- VIVA_NOTES.md, backend_schema_diff.md, domain_summary.md
|   |-- results/
|   `-- results_offline/
|-- frontend/
|   |-- package.json, tsconfig.json, next.config.mjs
|   |-- public/
|   `-- src/
|-- ml/
|   |-- offline pipeline and evaluation scripts (`*.py`)
|   `-- models/
|-- notebooks/
|-- sample_data/
`-- scripts/
```

## API routes

Roles: `public` means no bearer token; `authenticated` means any logged-in
role. Admin/Analyst routes reject Viewer accounts. Routes are declared in
`backend/main.py`; `/users` and `/reports` routers are mounted there and have
their prefixes in `backend/users.py` and `backend/reports.py`.

| Method | Path | Role required | Response model / response |
|---|---|---|---|
| POST | `/token` | Public | `TokenResponse` |
| GET | `/me` | Authenticated | `CurrentUserResponse` |
| GET | `/assets` | Authenticated | `list[AssetResponse]` |
| POST | `/assets` | Admin, Analyst | `AssetResponse` |
| PUT | `/assets/{asset_id}` | Admin, Analyst | `AssetResponse` |
| DELETE | `/assets/{asset_id}` | Admin, Analyst | `DeletedAssetResponse` |
| GET | `/cves/{cve_id}` | Authenticated | `CVEResponse` |
| GET | `/cves` | Authenticated | `list[CVEResponse]` |
| GET | `/intel/{cve_id}` | Authenticated | `IntelResponse` |
| GET | `/model/results` | Authenticated | `ModelResultsResponse` |
| POST | `/scan` | Admin, Analyst | `ScanResultResponse` (includes final-tier `recommended_action`) |
| GET | `/findings` | Authenticated | `FindingsPageResponse` (each finding includes final-tier `recommended_action`) |
| GET | `/findings/{finding_id}` | Authenticated | `FindingDetailResponse` (includes final-tier `recommended_action`) |
| PUT | `/findings/{finding_id}/status` | Admin, Analyst | `StatusUpdateResponse` |
| GET | `/dashboard/analytics` | Authenticated | `DashboardAnalyticsResponse` |
| GET | `/audit` | Admin | `list[AuditEntryResponse]` |
| POST | `/imports/preview` | Admin, Analyst | `ImportPreviewResponse` |
| POST | `/imports/commit` | Admin, Analyst | `ImportCommitResponse` |
| GET | `/users` | Admin | `list[UserResponse]` |
| POST | `/users` | Admin | `UserResponse` (HTTP 201) |
| PATCH | `/users/{user_id}` | Admin | `UserResponse` |
| PUT | `/users/{user_id}/role` | Admin | `UserResponse` |
| DELETE | `/users/{user_id}` | Admin | `DeletedUserResponse` |
| GET | `/reports/findings.csv` | Authenticated | `StreamingResponse` (`text/csv`); no Pydantic response model |
| GET | `/reports/executive.pdf` | Authenticated | PDF `Response`; no Pydantic response model |

## Database schema

Columns are taken from `backend/models.py`; the Alembic chain head is
`0005_cve_catalog`.

| Table | Columns |
|---|---|
| `users` | `id`, `username`, `hashed_password`, `role` |
| `assets` | `id`, `name`, `type`, `ip_or_domain`, `owner`, `environment`, `exposure`, `criticality`, `needs_review` |
| `cves` | `cve_id`, `data` |
| `cve_catalog` | `cve_id`, `published_date`, `description`, `cvss_score`, `cvss_vector`, `cwe`, `kev_date_added`, `epss`, `percentile`, `in_kev` |
| `findings` | `id`, `asset_id`, `cve_id`, `cvss_score`, `in_kev`, `final_priority`, `priority_source`, `status`, `date_found` |
| `finding_scores` | `id`, `finding_id`, `provider_id`, `likelihood`, `priority_tier`, `provenance`, `explanation`, `ml_likelihood`, `ml_risk`, `ml_priority`, `ml_top_reasons`, `ml_model_version`, `ml_recommended_action`, `ml_unavailable_reason` |
| `audit_logs` | `id`, `user_id`, `action`, `details`, `timestamp` |

Named uniqueness/index constraints include `uq_assets_name_ci`,
`uq_findings_asset_cve`, `ix_users_username`, `ix_findings_final_priority`,
`ix_assets_name`, `ix_findings_asset_id`, and `ix_findings_cve_id`.
PostgreSQL Alembic head: `0005_cve_catalog`.

## Environment variable names

`ADMIN_INITIAL_PASSWORD`, `BACKEND_IMAGE`, `CORS_ORIGINS`, `CVE_DATASET_FILENAME`,
`CVE_DATASET_HOST_PATH`, `CVE_DATASET_PATH`, `DATABASE_URL`,
`MIGRATION_DATABASE_URL`, `LOG_LEVEL`, `NEXT_PUBLIC_API_BASE`, `POSTGRES_DB`,
`POSTGRES_USER`, `POSTGRES_PASSWORD`, `POSTGRES_APP_USER`,
`POSTGRES_APP_PASSWORD`, `PRIORITY_MODE`, `SECRET_KEY`,
`SECUREVISION_DEMO_MODE`, `SECUREVISION_POSTGRES_TESTS`,
`SECUREVISION_TESTING`.

## Scoring pipeline (10 lines)

1. Manual scan or validated scanner CSV supplies a CVE and asset context.
2. Read CVE data from the prepared PostgreSQL catalog/cache; use NVD/FIRST lookup on applicable misses.
3. Calculate the deterministic 320-case rule tier from CVSS, EPSS, KEV, exposure, and criticality.
4. Build the frozen model row from publication-time CVSS/vector/CWE/description fields; KEV and EPSS are excluded.
5. Predict CVE exploitation likelihood with the frozen calibrated XGBoost model when available.
6. Compute ML risk as likelihood x exposure factor x criticality factor.
7. Map ML risk to Critical/High/Medium/Low using configured validation-derived thresholds.
8. Default `PRIORITY_MODE` is `ml_asset`: persist the ML tier when available; otherwise fall back to the rule tier and source `rules`.
9. In `ml_asset` mode, use ML tier when available; otherwise fall back to the rule tier and source `rules`.
10. In `ml_asset` mode only, raise a KEV ML tier below High to High (`ml+kev_floor`); persist the finding and score history.

## Recorded results

### Frozen Test 2026

This compact table is transcribed from existing `docs/VIVA_NOTES.md` and
`Decision_Log.md` summaries. The protected P5 log was not opened, so a complete
row-by-row extraction from that raw output is **unverified**.

| Model/baseline | Rows / positives | PR-AUC | P@100 | P@500 |
|---|---:|---:|---:|---:|
| XGBoost calibrated | 61,611 / 122 | 0.0114 | 0.0000 | 0.0060 |
| CVSS baseline | 61,611 / 122 | 0.0117 +/- 0.0018 | 0.0428 | 0.0243 |

Recorded paired-bootstrap XGBoost-minus-CVSS PR-AUC difference is `-0.0004`
(95% CI `-0.0081` to `0.0045`). This is a negative result; no Test 2026 model
evaluation was performed for this snapshot.

### Validation 2025

Values below are copied from `docs/results_offline/2026-11-15/val2025_comparison.md`.
Train: 2022-2024 (93,842 rows, 270 positives); validation: 2025 (48,152 rows,
126 positives). This comparison did not open the test split.

| Model | PR-AUC | Precision | Recall | F1 | ROC-AUC | P@50 | P@100 | P@500 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Logistic Regression (152 features; tuned) | 0.021292 | 0.041096 | 0.047619 | 0.044118 | 0.845647 | 0.0200 | 0.0300 | 0.0400 |
| Logistic Regression (fixed; 2026-11-14 historical) | 0.020851 | 0.032967 | 0.047619 | 0.038961 | 0.854879 | 0.0400 | 0.0200 | 0.0420 |
| Random Forest | 0.033932 | 0.060606 | 0.031746 | 0.041667 | 0.887909 | 0.0400 | 0.0500 | 0.0440 |
| XGBoost calibrated | 0.035183 | 0.060000 | 0.023810 | 0.034091 | 0.889134 | 0.0600 | 0.0700 | 0.0320 |
| CVSS-only baseline | 0.014753 | 0.062500 | 0.103175 | 0.077844 | 0.790278 | 0.0800 | 0.0900 | 0.0280 |
| EPSS baseline (hindsight) | 0.283077 | 0.593750 | 0.150794 | 0.240506 | 0.967154 | 0.5600 | 0.3800 | 0.1320 |

Logistic Regression tuning selected `C=100`, `class_weight=None` with mean
training-CV average precision `0.062506` from a 10-candidate, 3-fold stratified
grid search; its threshold was selected from training-only out-of-fold scores.
The fixed `C=1.0`, balanced-class-weight result is retained as a historical row.
Random Forest tuning used 3-fold randomized CV on training rows. The frozen
XGBoost calibrator was fitted on Validation 2025, a disclosed exception. EPSS
is a hindsight baseline.

## Artifact inventory: SHA-256 and bytes

Hashes and sizes below are for `ml/models/` and `docs/results_offline/`.
No listed file exceeds 25,000,000 bytes. The frozen configuration hash and size
are recorded in the comparison manifest and root inventory; the protected
configuration file was not re-read for this snapshot.

| Artifact | Classification | Bytes | SHA-256 |
|---|---|---:|---|
| `frozen_config.json` | Frozen config (manifest hash) | 4,453 | `15ea96d149675c830677f4bed9a505ca5e5fe293b043df4f17ef44603c9e7fec` |
| `ml/models/headline_model_calibrated.joblib` | Frozen production model | 170,368 | `1390b1e65ff9bbf9dc3a3f37659a577c32af0f7aac9bb47711f8394331bc8ed1` |
| `ml/models/headline_tfidf_transformer.joblib` | Frozen production transformer | 18,010,971 | `ed8a5daaad9fa1b7455f32ccb9005372a6bb1da3f993a768485cf4e446ecc58d` |
| `ml/models/feature_transformers_2026-10-08.joblib` | Historical/auxiliary | 2,059,482 | `965d28a42b0701723b02ecbcc6076afbb4fba05024d1bc9fd02365df924b8368` |
| `ml/models/logreg_val2025_2026-11-14.joblib` | Offline Validation 2025 | 2,113 | `16b9e5cf4846b975633df76182d8e93f27dd523c63659b92b8d12740b9f02334` |
| `ml/models/logreg_cv_val2025_2026-11-15.joblib` | Tuned offline Validation 2025 | 2,097 | `8e8914a38cea6be1937e2c7f4f54df42a5fcc96e3e651ad6f02c1377dfa0b6ad` |
| `ml/models/rf_val2025_2026-11-14.joblib` | Offline Validation 2025 | 252,329 | `334e2e2451ce79b741759ced1bb0a1ae3fe100b9835168d633d5b111ca7fab4c` |
| `ml/models/xgb_model_2026-10-07.joblib` | Historical/auxiliary | 120,672 | `559a10ab428401f6f9e6a625b240529bebf3b47fdfe7a2ab4531360c6ed77a84` |
| `ml/models/xgb_model_2026-10-08.joblib` | Historical/auxiliary | 230,046 | `6b7d79436d10e59c916bf20673b09c1337170968ad7a56086064e94becb1388b` |
| `docs/results_offline/2026-11-14/val2025_comparison.json` | Validation metrics and predictions | 16,386,275 | `b503373812fcded4a48dbb2cad71b108bf788d10952187c16e61a9077505ed01` |
| `docs/results_offline/2026-11-14/val2025_comparison.md` | Validation report | 6,491 | `d1869f8c18e5c2bde7f484c20e351f1b5c3547dd51d698ceb528d994676d8072` |
| `docs/results_offline/2026-11-14/val2025_pr_curve.svg` | Validation chart | 63,123 | `95d4f6687b9d1a4e8c03076f49dac13cc269791d901cf3aade169312a69bca5a` |
| `docs/results_offline/2026-11-14/val2025_top_k.svg` | Validation chart | 3,539 | `778627ce53c33da36c62a5f87130d9d6c7c927f8972df0b2e965fed8bc33a20b` |
| `docs/results_offline/2026-11-15/val2025_comparison.json` | Tuned validation metrics and predictions | 16,467,026 | `d208af1e00f339561d082ed981d7b980b64ecc3156da4e2d8f145219a3adc40b` |
| `docs/results_offline/2026-11-15/val2025_comparison.md` | Tuned validation report | 5,506 | `7fb8669b5a394075ac1a97ccde50dbf588d54b614ad87eea4236fc89a7d13ead` |
| `docs/results_offline/2026-11-15/val2025_pr_curve.svg` | Tuned validation chart | 63,122 | `4b2b13ddf9ea0e8e12fa682ad877ab6dc0473cfd7b9de252a0f3ce001cce0c2c` |
| `docs/results_offline/2026-11-15/val2025_top_k.svg` | Tuned validation chart | 3,539 | `37126db8ebda6171c4c481074f1998da0e36f670d277e0183d56ad6d582dbf46` |

## Test collection, dependencies, and limitations

Root `pytest --collect-only -q` in the `postgres-tests` profile collected 501
tests from these files:

| Test file | Count | Test file | Count |
|---|---:|---|---:|
| `test_auth.py` | 8 | `test_cli_sqlite_migration.py` | 1 |
| `test_csv_import.py` | 27 | `test_cve_lookup.py` | 4 |
| `test_dashboard_analytics.py` | 4 | `test_demo_seed.py` | 2 |
| `test_findings_api.py` | 9 | `test_ml_advisory.py` | 12 |
| `test_model_results.py` | 1 | `test_postgres_migrations.py` | 15 |
| `test_reports.py` | 7 | `test_response_models_and_transactions.py` | 11 |
| `test_role_based_api.py` | 42 | `test_scan_assets_audit.py` | 12 |
| `test_scoring.py` | 332 | `test_startup_warmup.py` | 5 |
| `test_threat_intel.py` | 2 | `test_users_rbac.py` | 7 |

| Dependency | Pinned version |
|---|---|
| FastAPI | 0.110.0 |
| SQLAlchemy | 2.0.29 |
| Alembic | 1.13.1 |
| XGBoost | 2.0.3 |
| scikit-learn | 1.4.1.post1 |
| SHAP | 0.46.0 |
| Next.js | 16.4.5 |

Known limitations: no active scanning, auto-patching, LLM agents, or mobile
client; no live CISA KEV feed; LR and RF have no test result; the frozen XGBoost
calibrator was fitted on validation; and uncached CVE
lookups depend on external NVD/FIRST availability. Asset search and exposure,
environment, and review-status filters are client-side in `AssetsView`.
The optional prepared catalog loader handles 384,522 rows in about 33 minutes;
on a fresh clone, uncached single-CVE lookups fall back to the live provider.
`ml_asset` is the code default; deterministic mode remains selectable. The
known-exploited High floor is retained as a documented proposal deviation
(D-043).

The current collection count is 501 tests: four per-tier finding-detail cases
were added for rule-only final-tier action templates. Finding list, detail, and
scan responses derive `recommended_action` from `final_priority`; the separate
ML-specific action remains unchanged.
