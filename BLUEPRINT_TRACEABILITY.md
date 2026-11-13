# Blueprint Traceability (P8–P12)

## Source and status caveat

`SecureVision_Master_Blueprint` is not present in this checkout. Therefore its
Section 4 and Sections 9–13 wording, Section 18 viva questions, and the original
P8–P12 acceptance-criteria text cannot be verified verbatim. The phase labels
below are a provisional grouping of deliverables evidenced in this repository,
not a claim that they reproduce the missing blueprint. Supply the source
blueprint before treating this as final criterion-by-criterion sign-off.

**Met** means the traced behavior exists and has relevant repository evidence.
**Partial** means a material limitation or documented deviation remains.
**Not met** means the capability is absent.

## Provisional P8–P12 evidence map

| Phase / traced criterion | Status | Evidence in this repository | Remaining gap |
|---|---|---|---|
| P8 — Selectable, explainable final priority | met | `backend/scoring_engine.py`, `backend/rules_config.py`, Alembic revisions `0004_final_priority` and `0005_cve_catalog`, and `backend/tests/test_ml_advisory.py`; the active mode is exposed in `/me` and the UI, and the 320-row matrix remains a persisted cross-check. | The recorded frozen test result is negative; it remains visible alongside the proposal-default `ml_asset` mode. |
| P9 — Authenticated roles, password handling, and audit trail | partial | JWT auth, PBKDF2-HMAC-SHA256 at 600,000 iterations, role checks, login throttling, ORM audit guards, and PostgreSQL trigger coverage are implemented in `backend/tests/test_auth.py`, `backend/tests/test_role_based_api.py`, `backend/tests/test_users_rbac.py`, and `backend/tests/test_postgres_migrations.py`. | PBKDF2 is retained instead of Argon2/bcrypt for existing hash compatibility; refresh tokens are absent; throttling is process-local. PostgreSQL runtime status depends on the validation results recorded below. |
| P10 — Asset lifecycle and scanner-data intake | partial | Asset CRUD and review metadata are covered by `backend/tests/test_scan_assets_audit.py`; generic/Nessus/Qualys/OpenVAS CSV parsing and validation are covered by `backend/tests/test_csv_import.py`. | CSV import is not active network scanning. KEV is not refreshed from a live CISA feed. |
| P11 — Triage workflow, reports, and intelligence lookup | partial | Paginated findings and status changes are in `backend/main.py`; export filtering/audit behavior is covered by `backend/tests/test_reports.py`; threat-intelligence failure handling is covered by `backend/tests/test_threat_intel.py`. NVD/FIRST lookups are implemented in `backend/threat_intel.py`; `cve_catalog` is populated only by the manual streaming loader and is read-only to the app role. | External provider availability is required for catalog misses. The app uses `Resolved` as its terminal status, not `fixed`. |
| P12 — ML priority mode, model-results reporting, and demo packaging | partial | `backend/ml_inference.py` excludes KEV/EPSS features and uses SHAP TreeExplainer with native-contribution fallback; the rules layer applies the known-exploited floor after ML priority selection. The results screen reads split-labelled recorded metrics only and labels the active mode. | The model did not beat CVSS on the recorded test PR-AUC; `ml_asset` is the proposal default and deterministic remains selectable. Random Forest results are unavailable. Synthetic demo ML fields remain unavailable absent NVD enrichment. |

## Requirement-level traceability (Sections 4 and 9–13, provisionally mapped)

| Traced requirement | Status | Implementation and verification evidence |
|---|---|---|
| Final priority is selectable and explainable | met | `PRIORITY_MODE` in `backend/rules_config.py` defaults to the available ML asset priority (`ml_asset`) or selects the rule tier (`deterministic`), with deterministic fallback. `/me`, `final_priority`, `priority_source`, and the rule cross-check expose the active choice. |
| Model features use publication-time information without KEV/EPSS leakage | met | `backend/ml_inference.py`, `frozen_config.json`, and `backend/tests/test_ml_advisory.py`. |
| ML risk formula, validation cutoffs, and KEV floor are rules-layer choices | met | `ml_likelihood × exposure_factor × criticality_factor`, validation-percentile cutoffs, and `KNOWN_EXPLOITED_FLOOR` are centralized in `backend/rules_config.py`. KEV is applied only after prediction and is never a feature. |
| Model evaluation is reported without invented missing metrics | met | `backend/model_results.py` reads recorded files under `docs/results/`; absent fields remain null/not available. The measured result is negative, not evidence of improvement. |
| Model comparison split availability | partial | XGBoost has recorded test and validation results; Logistic Regression has validation results; Random Forest is not available. `docs/ML_GAPS.md` lists offline evidence Ashley must provide. | A common full three-model comparison is not recorded here; no test-set evaluation or retraining is allowed in this work. |
| Auth, RBAC, transactional audit, and exports | partial | `backend/auth.py`, `backend/users.py`, `backend/reports.py`, `backend/main.py`; coverage in auth, RBAC, report, scan, and transaction tests. The initial Alembic migration installs PostgreSQL audit UPDATE/DELETE triggers; `backend/tests/test_postgres_migrations.py` exercises them. |
| Inventory and supported scanner-export CSV ingestion | met | Asset CRUD and CSV adapters are implemented and covered by the tests listed above. This means CSV ingestion, not a scanner. |
| Live threat-intelligence lookup and prepared CVE catalog | partial | Live EPSS/FIRST and NVD lookups are in `backend/threat_intel.py`. Revision `0005_cve_catalog` provides an indexed reference table loaded manually from the optional CSV; the Docker image excludes that 201,498,667-byte file and the app role has SELECT-only access. Catalog misses use the live provider and report unavailability explicitly. Three hard-coded `DEMO_CACHE` entries in `backend/threat_intel.py` are fixtures, not authoritative current scores. |
| Live CISA KEV feed and active network scanning | not met | The README lists live CISA KEV integration as a roadmap item. The application ingests scanner CSVs and provides scoring; it does not discover or scan hosts. |
| P12/P13 reproducible local Docker deployment | partial | `docker-compose.yml` runs PostgreSQL 16 with a named volume and a one-shot owner-credentialed migration service. The backend receives only the app-role URL and depends on migration completion; `docker-compose.local.yml` adds a loopback-only database port. Test suites require PostgreSQL and disposable schemas. Verification results for the isolated `sv_verify4` project are recorded in `PROJECT_STATE.md`. |
| Clearly labeled synthetic demo data | met | `backend/demo_seed.py`, fixed synthetic inputs in `backend/rules_config.py`, the Compose-only `SECUREVISION_DEMO_MODE` flag, the demo-mode badge, and the synthetic-data warnings in README/demo script. The seeder uses `DATABASE_URL` and never overwrites existing records. |
| Exact Section 18 viva-question coverage | not met | The master blueprint and its viva prompts are absent from this checkout. `docs/VIVA_NOTES.md` provides evidence-grounded answers to likely topics but does not claim to reproduce or answer unseen wording. |

## Verification evidence

The isolated `sv_verify4` verification and test results are recorded in
`PROJECT_STATE.md`. The real-PostgreSQL suite passed 490 tests with no skips.
The manual browser checklist remains unverified, and the final full frontend
lint rerun was not performed. Passing automated checks does not remove the
limitations above or establish model effectiveness.
