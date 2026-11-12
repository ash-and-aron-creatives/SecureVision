# SecureVision Architectural Decision Log
### D-001: Pinned Tooling
* **Decision:** Python 3.12, scikit-learn 1.4.1.post1, XGBoost 2.0.3, FastAPI 0.110.0, next@16.4.0, react@19.3.0.
### D-003, D-004, D-005
* **Decision:** [SUPERSEDED]
### D-006: Environment Execution Policy
* **Decision:** Disabled Windows 11 Smart App Control for C++ extensions. WSL2/Docker rejected to maintain local access.
### D-007: 30-Day Label Horizon
* **Decision:** Positive ONLY if KEV date <= published_date + 30 days. All others are negatives.
### D-008: Model Artifact Hashing
* **Decision:** Models saved via joblib must have SHA-256 hashes recorded.
### D-009: Strict Chronological Splitting
* **Decision:** Train (2022-2024), Val (2025), Test (2026).
### D-010: Median Imputation & Baseline Tie-Breaking
* **Decision:** Missing CVSS imputed using train median (6.7). CVSS Baseline PR-AUC uses uniform random noise for tie-breaking.
### D-011: EPSS Baseline
* **Decision:** EPSS remains 'hindsight' until daily t+1 archives are ingested.
### D-012: Next.js Upgrade
* **Decision:** Upgraded from vulnerable next@14.1.4 to next@16.4.0 to resolve CVE-2025-29927.
### D-013: NLP Headline Model & Blacklist
* **Decision:** Headline model uses TF-IDF on descriptions. Vendor names are KEPT. Post-publication exploitation wording is BLACKLISTED via Regex.
### D-014: Same-Day Positives
* **Decision:** Positives published to KEV on/before NVD pub are valid triage targets.
### D-015: Prospective Holdout
* **Decision:** The 2026 test set was prematurely scored. A future prospective holdout (CVEs published after freeze date) will act as the true pristine test set.
### D-016: Rejected CVEs
* **Decision:** NVD API returns rejected CVEs by default. Our local pipeline drops them, creating a volume discrepancy.

### D-017: 2026 Test Set Size Correction
* **Decision:** The earlier 60,052 row figure improperly excluded September 8th (1,559 CVEs), contradicting the stated <= 2026-09-08 rule. The master rebuild enforces the correct 61,611 row count.

### D-018: Master & Split Regeneration
* **Decision:** Master was rebuilt to hardcode the 30-day label and purge rejected CVEs. All splits were regenerated, accounting for the changed dataset hashes despite stable row counts.

### D-019: Boundary Day Audit Limitation
* **Decision:** The KEV snapshot was downloaded at 08:01 UTC on Oct 8, meaning CVEs published late on Sep 8 only had ~29.5 days of observation. Excluded via sensitivity analysis, this boundary effect did not alter the negative outcome.

### D-020: P5 Final Test Result
* **Decision:** The v1 text-based XGBoost model is formally declared a negative result, failing to outperform CVSS on held-out PR-AUC and underperforming at top-500 triage precision.

### D-021: TF-IDF Mask Defect (Resolved)
* **Decision:** The initial report of "attacker" surviving the regex mask was a hallucination caused by the incident in D-022. Programmatic validation confirms the e.IGNORECASE mask successfully removed all targeted exploit variants from the vocabulary.

### D-022: Reporting Artifact Hallucination
* **Decision:** A prior evaluation report displayed an improperly reconstructed configuration summary rather than verbatim file contents. All future file contents will be presented strictly via terminal output commands (Get-Content, 	ype, cat).

### D-023: Additive ML Advisory and Frozen Artifact Use
* **Decision:** Keep the existing 320-rule deterministic matrix as the sole source of `priority_tier` and score. The calibrated XGBoost likelihood and its exposure/criticality-adjusted risk are supplemental, experimental fields only; unavailable predictions remain null with an explicit reason.
* **Frozen headline artifact:** `headline_model_calibrated.joblib` named by `frozen_config.json`, SHA-256 `1390b1e65ff9bbf9dc3a3f37659a577c32af0f7aac9bb47711f8394331bc8ed1`. The runtime copy in `ml/models/` was byte-verified against that hash. The model requires 152 ordered features: CVSS score/missing indicator; CVSS vector categories; CWE categories; and 100 description TF-IDF terms. KEV and EPSS are not model features. The compatible TF-IDF transformer was regenerated from the frozen 2022-2024 training descriptions using the configured blacklist and TF-IDF settings; its 100-term vocabulary hash matches `frozen_config.json` (`35af7ab9e1cab7dbd5e035a47ad24b36913800819eaefac45ee99c2efdf3931e`). Existing incompatible transformer artifacts are not used.
* **Risk formula:** `ml_risk = ml_likelihood × exposure_factor × criticality_factor`. Exposure is 1.5 for Internet and 1.0 for Internal. Criticality 1-5 maps linearly to 0.6, 0.8, 1.0, 1.2, and 1.4. Implementation constants and recommended-action templates live in `backend/rules_config.py`.
* **Threshold method:** Compute risk on the 2025 validation-set likelihoods for each of the ten supported exposure/criticality contexts (48,152 validation CVEs; 481,520 risk values). Set Critical at or above P99 (`0.044082497805356974`), High at or above P90 (`0.007056011210661384`), Medium at or above P50 (`0.0008546133991330863`), and Low below P50. No test-set observations were used.
* **Explanations and dependencies:** SHAP is not installed; use XGBoost native `pred_contribs` for the top three factors. `requirements.txt` already pins XGBoost 2.0.3, scikit-learn 1.4.1.post1, and joblib 1.6.0; the current runtime matches these pins. The frozen config does not record artifact-producer versions, so exact train-time package parity cannot be independently established.
* **Model Results:** Read only recorded files in `docs/results/`. Logistic Regression validation PR-AUC results exist; no Random Forest metric result is recorded. Missing precision/recall/F1/ROC-AUC values remain not available. EPSS is labeled hindsight. The test-set negative result remains explicit and does not change the deterministic tier.
* **Conclusion:** Held-out XGBoost PR-AUC was 0.0114 versus CVSS 0.0117; top-K precision was also lower at P@100 and P@500. This offline evaluation did not demonstrate an improvement, so ML is an advisory signal only and does not drive the tier.

### D-024: Asset Inventory Metadata and Lifecycle
* **Decision:** Add `type`, `ip_or_domain`, `owner`, and `environment` as additive asset fields. Existing rows migrate with `type=Other`, blank address/owner, and `environment=Unknown`; type/environment choices and limits live in `backend/rules_config.py`. Admins and analysts may create, edit, and delete assets. Deletion is blocked while any finding references the asset. Asset changes and their audit records share one transaction.

### D-025: Login Throttling and Password Hash Compatibility
* **Decision:** Limit each normalized username + direct client IP to five login attempts in a rolling 15-minute window; the next request returns HTTP 429. State is bounded, process-local memory, so deployments with multiple workers need a shared rate-limit backend for cross-process enforcement.
* **Password hashing:** Keep PBKDF2-HMAC-SHA256, 600k iterations instead of argon2/bcrypt. This preserves existing password hashes and avoids a migration/dependency change; changing the password-hashing scheme is outside this gap closure.

### D-026: CVE Lookup Source
* **Decision:** Use `data/processed/master_cves_2026-10-08.csv` when present. The file is read lazily and individual identifier/search results are cached in memory; searches return at most 100 results. If the file is absent, use the `cves` cache table and fill it from successful threat-intelligence lookups. With the prepared file present, startup skips creating the `cves` table and does not write to the dataset. KEV and EPSS remain excluded from ML model features.

### D-027: Refresh-Token Deviation
* **Decision:** Do not add refresh tokens in this change. A secure refresh lifecycle requires token rotation/revocation and frontend session-handling changes, which is not a small additive change; the existing 30-minute access-token behavior remains.

### D-028: Dashboard Screen 2 Metrics
* **Decision:** Dashboard asset/open totals come from current database records. “Fixed this month” counts currently resolved findings with a recorded resolution audit event in the current UTC month; findings without audit history are not inferred as recently fixed.

### D-029: P12-P13 Synthetic Docker Demo and Deployment Deviations
* **Decision:** Docker Compose starts the frontend and backend against a dedicated `securevision_demo_data` named volume containing `/data/securevision_demo.db`. It does not bind-mount either repository database. Ports are bound to loopback for the local demo. The container database is SQLite; PostgreSQL is not configured or verified in this delivery.
* **Secrets:** Compose requires `SECRET_KEY` and `ADMIN_INITIAL_PASSWORD` from the operator's `.env`, based on `.env.example`. The examples are blank; no secrets are copied into either image. The container always overrides `DATABASE_URL` with the isolated demo database path.
* **Synthetic records:** The seed inputs in `backend/rules_config.py` are explicitly synthetic. `backend/demo_seed.py` only accepts the isolated demo `DATABASE_URL`, seeds only an empty inventory, and never clears or replaces existing records. Synthetic seed model advisories are unavailable until actual enrichment is supplied; no predicted value is fabricated. A build-time `NEXT_PUBLIC_DEMO_MODE` flag controls the UI synthetic-data label.
* **CVE source trade-off:** Live NVD/FIRST provider requests remain the runtime threat-intelligence path, subject to availability. The prepared `data/processed/master_cves_2026-10-08.csv` remains the local `/cves` catalog when present, but is excluded from the Docker image because it is 201,498,667 bytes; Docker therefore uses the database-cache fallback for `/cves`. The three static entries in `backend/threat_intel.py:DEMO_CACHE` remain clearly identified in the demo documentation as illustrative fixtures, not authoritative current values.
* **Scoring and model:** Keep the existing 320-rule matrix as the sole source of `priority_tier`. The ML risk calculation remains `likelihood × exposure_factor × criticality_factor`, is shown only as an advisory, and uses no KEV/EPSS features. The measured negative held-out result remains unchanged and is not reframed as a successful model outcome.
* **Authentication:** Retain PBKDF2-HMAC-SHA256 at 600,000 iterations rather than migrate existing hashes to Argon2/bcrypt. Refresh tokens remain deferred; login throttling remains process-local.
* **Status vocabulary:** Persist and display `Resolved`; do not rename it to `fixed`. “Fixed this month” is a dashboard aggregate backed by resolution audit events, not a finding status.
* **Blueprint traceability:** The master blueprint was not present in the checkout. The P8-P12 mapping and viva notes are explicitly provisional and do not claim to reproduce missing acceptance-criteria or viva wording.
* **Container verification:** `docker compose config` succeeded with temporary validation-only environment values. The Docker CLI is installed, but `docker info` could not connect to the Docker Desktop Linux engine; image build and container startup are therefore unverified in this environment.

### D-030: PostgreSQL Database of Record
* **Decision:** Supersede D-029's SQLite database choice. PostgreSQL 16 is now the application database; `DATABASE_URL` is mandatory and drives SQLAlchemy and Alembic. The pinned `psycopg2-binary` driver is used through `postgresql+psycopg2`.
* **Schema ownership:** Alembic applies the initial model schema before startup. It includes asset metadata and review fields, full finding-score ML history fields, the CVE cache table, login audit rows, the findings asset/CVE indexes, and PostgreSQL audit-log mutation triggers. There are no import-time `create_all` calls or raw startup ALTER migrations. The ORM's audit immutability guards remain.
* **PostgreSQL differences:** CVE-cache and export search/filter normalization is performed in Python rather than relying on dialect-specific `ILIKE` or SQLite collation behavior; CVE duplicate matching and username uniqueness checks also normalize values in Python. Canonical priority comparisons use exact stored tier values. PostgreSQL owns native boolean, JSON, and timezone-aware timestamp behavior.
* **Compose and local setup:** Compose runs PostgreSQL 16 with a named data volume and env-supplied credentials; no database host port is published by default. Local development opts into a separate loopback-only port override. The backend waits for PostgreSQL health, migrates before serving, and only seeds synthetic rows when the explicit demo-mode environment flag is enabled.
* **Testing:** Default tests use temporary isolated SQLite fixtures. The PostgreSQL test profile runs the full suite with per-test disposable PostgreSQL schemas and verifies the migrated schema and UPDATE/DELETE audit triggers. The same test suite must pass on both paths; recorded counts belong in the validation report after execution.
* **Manual data conversion:** `scripts/sqlite_to_postgres.py` is never called automatically. It accepts source/target URLs, opens the SQLite source read-only, requires an empty migrated PostgreSQL target, copies users/assets/findings/score history/audit rows including IDs and timestamps, fills only missing legacy asset metadata from `backend/rules_config.py`, interprets SQLite-naive audit timestamps as UTC consistently with the API, resets sequences, and checks row counts. It must not be run as part of routine startup or tests.
* **Safety and model scope:** No SQLite database file, frozen model/configuration, or `docs/results` content is part of the migration procedure. No model feature or score changes; KEV and EPSS remain excluded from ML features.

### D-031: PostgreSQL Migration Verification Safety Boundary
* **Decision:** Verify runtime behavior only in the explicitly named `sv_verify` Compose project with throwaway credentials supplied through process environment variables. Inspect its containers and volumes before any cleanup; never use the default Compose project or the existing local database files.
* **Local setup:** `setup_dev.ps1` refuses to change an existing `backend/.env` unless the operator explicitly passes `-UpdateExisting`. Do not run that opt-in in this checkout because it would alter existing user configuration and start PostgreSQL under the default Compose project. The default refusal and the SQLite URL startup guard were verified without changing the existing file.
* **Synthetic migration fixture:** Any migration-script test uses a newly created temporary synthetic SQLite source and the isolated verification PostgreSQL database only. Do not open or modify pre-existing SQLite/database files.
* **Superseded runtime note:** D-029's container-unverified note was an earlier checkpoint. The isolated PostgreSQL Compose stack was subsequently built, started, and exercised through the application API.
* **Audit immutability:** Initial PostgreSQL verification confirmed UPDATE/DELETE triggers but allowed TRUNCATE. Additive migration `0002_audit_truncate` installs a statement-level TRUNCATE trigger; direct PostgreSQL probes confirmed UPDATE, DELETE, and TRUNCATE are rejected without changing audit rows.
* **Container startup:** The first isolated startup failed with `/bin/sh: set: Illegal option -`; `docker-entrypoint.sh` was confirmed to contain CRLF on every line. `.gitattributes` now forces LF, and a clean PostgreSQL startup succeeded.
* **Database role and constraints:** The isolated application role `sv_verify_user` has `rolsuper=true`; this is a least-privilege deployment limitation, not a production-ready role configuration. `users.username` is unique; asset names and `(findings.asset_id, findings.cve_id)` have no unique constraint. `findings.final_priority` is not present in this schema revision.
* **Synthetic migration evidence:** A new throwaway SQLite database copied one user, one asset, one finding, two score-history rows, and one audit row into a fresh migrated PostgreSQL database. IDs and timestamp were preserved, legacy asset metadata received defaults, source SHA-256 stayed unchanged, the next user sequence ID was 8, and a rerun refused to merge into the nonempty target.
* **Migration lifecycle:** On a disposable PostgreSQL database, two successive `alembic upgrade head` calls and `alembic check` succeeded; `alembic downgrade base` followed by `alembic upgrade head` also succeeded.
* **CVE catalog packaging:** `data/processed/master_cves_2026-10-08.csv` exists only as ignored local data, is not tracked, and is excluded from Docker builds. Fresh clones and the Docker image rely on the PostgreSQL cache and external NVD/FIRST provider availability when the prepared catalog is absent.
* **PostgreSQL test profile:** The first full profile run exposed that the Docker test container did not contain the SQLite conversion script used by its regression test. Commit `e3bc003` mounts `scripts/` read-only in the test service; the focused regression test then passed.
* **Windows fast-suite stability:** The CLI subprocess regression passed alone but returned Windows status `0xC000070A` when run after the resource-heavy tests. Its test module now sorts early; the complete fast suite passed with 466 passed, 4 PostgreSQL-only skips, and 98 warnings.
