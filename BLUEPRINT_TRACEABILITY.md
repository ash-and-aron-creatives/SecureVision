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
| P8 — Deterministic, explainable priority tier | met | `backend/scoring_engine.py`; all 320 rows in `docs/scoring_matrix_v1.csv` are checked by `backend/tests/test_scoring.py::test_scoring_matches_documented_expected_tier_table`; `backend/rules_config.py` holds runtime constants. | None identified for the implemented matrix. |
| P9 — Authenticated roles, password handling, and audit trail | partial | JWT auth, PBKDF2-HMAC-SHA256 at 600,000 iterations, role checks, login throttling, ORM audit guards, and PostgreSQL trigger coverage are implemented in `backend/tests/test_auth.py`, `backend/tests/test_role_based_api.py`, `backend/tests/test_users_rbac.py`, and `backend/tests/test_postgres_migrations.py`. | PBKDF2 is retained instead of Argon2/bcrypt for existing hash compatibility; refresh tokens are absent; throttling is process-local. PostgreSQL runtime status depends on the validation results recorded below. |
| P10 — Asset lifecycle and scanner-data intake | partial | Asset CRUD and review metadata are covered by `backend/tests/test_scan_assets_audit.py`; generic/Nessus/Qualys/OpenVAS CSV parsing and validation are covered by `backend/tests/test_csv_import.py`. | CSV import is not active network scanning. KEV is not refreshed from a live CISA feed. |
| P11 — Triage workflow, reports, and intelligence lookup | partial | Paginated findings and status changes are in `backend/main.py`; export filtering/audit behavior is covered by `backend/tests/test_reports.py`; threat-intelligence failure handling is covered by `backend/tests/test_threat_intel.py`. NVD/FIRST lookups are implemented in `backend/threat_intel.py`. | External provider availability is required for uncached live lookups. The app uses `Resolved` as its terminal status, not `fixed`. The demo container omits the large prepared CVE CSV and uses the fallback cache path for `/cves`. |
| P12 — ML advisory, model-results reporting, and P12–P13 demo packaging | partial | `backend/ml_inference.py` excludes KEV/EPSS features; `backend/tests/test_ml_advisory.py` verifies this and deterministic-tier invariance. `docs/results/p5/p5_console.log` records the negative held-out result. PostgreSQL/Alembic, Compose, and synthetic seeding are implemented in `Dockerfile`, `docker-compose.yml`, `alembic/`, and `backend/demo_seed.py`. | The model did not beat CVSS on the recorded held-out metrics; ML remains advisory. PostgreSQL/Compose verification status is recorded below. The seeded ML fields are intentionally unavailable absent NVD enrichment. |

## Requirement-level traceability (Sections 4 and 9–13, provisionally mapped)

| Traced requirement | Status | Implementation and verification evidence |
|---|---|---|
| Primary tier is deterministic and explainable | met | `backend/scoring_engine.py`, `docs/scoring_matrix_v1.csv`, `backend/tests/test_scoring.py`; the UI drawer separates the deterministic tier from the advisory. |
| Model features use publication-time information without KEV/EPSS leakage | met | `backend/ml_inference.py`, `frozen_config.json`, and `backend/tests/test_ml_advisory.py`. |
| ML risk formula is supplemental, not the deterministic tier | met | `ml_likelihood × exposure_factor × criticality_factor` and thresholds are centralized in `backend/rules_config.py`; the drawer labels it experimental/advisory. |
| Model evaluation is reported without invented missing metrics | met | `backend/model_results.py` reads recorded files under `docs/results/`; absent fields remain null/not available. The measured result is negative, not evidence of improvement. |
| Auth, RBAC, transactional audit, and exports | partial | `backend/auth.py`, `backend/users.py`, `backend/reports.py`, `backend/main.py`; coverage in auth, RBAC, report, scan, and transaction tests. The initial Alembic migration installs PostgreSQL audit UPDATE/DELETE triggers; `backend/tests/test_postgres_migrations.py` exercises them. |
| Inventory and supported scanner-export CSV ingestion | met | Asset CRUD and CSV adapters are implemented and covered by the tests listed above. This means CSV ingestion, not a scanner. |
| Live threat-intelligence lookup and prepared CVE catalog | partial | Live EPSS/FIRST and NVD lookups are in `backend/threat_intel.py`. `/cves` uses `data/processed/master_cves_2026-10-08.csv` when present; the Docker image excludes that 201,498,667-byte file and uses the migrated PostgreSQL cache when the catalog is unavailable. Three hard-coded `DEMO_CACHE` entries in `backend/threat_intel.py` are fixtures, not authoritative current scores. |
| Live CISA KEV feed and active network scanning | not met | The README lists live CISA KEV integration as a roadmap item. The application ingests scanner CSVs and provides scoring; it does not discover or scan hosts. |
| P12/P13 reproducible local Docker deployment | partial | `docker-compose.yml` runs PostgreSQL 16 with a named volume, healthcheck, environment-supplied credentials, and no default host port. `docker-compose.local.yml` explicitly adds a loopback-only port for local tools. The SQLite unit suite and Compose configuration passed. PostgreSQL validation exposed missing test-only CSV fixtures and migration setup, now corrected in the profile; rerun before marking PostgreSQL runtime verified. |
| Clearly labeled synthetic demo data | met | `backend/demo_seed.py`, fixed synthetic inputs in `backend/rules_config.py`, the Compose-only `SECUREVISION_DEMO_MODE` flag, the demo-mode badge, and the synthetic-data warnings in README/demo script. The seeder uses `DATABASE_URL` and never overwrites existing records. |
| Exact Section 18 viva-question coverage | not met | The master blueprint and its viva prompts are absent from this checkout. `docs/VIVA_NOTES.md` provides evidence-grounded answers to likely topics but does not claim to reproduce or answer unseen wording. |

## Commands required for completion evidence

Run `pytest` for the isolated fast suite and
`docker compose --env-file .env --profile postgres-tests run --build --rm backend-tests`
for the full PostgreSQL suite. Also run `npx tsc --noEmit`, `npm run lint`,
`npm run build`, `npm audit`, `git diff --check`, and `docker compose config`.
Record command output and test counts after execution. Passing a command
verifies only the behavior it exercises; it does not remove the limitations
above or establish model effectiveness.
