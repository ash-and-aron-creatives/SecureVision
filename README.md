# SecureVision

SecureVision is a vulnerability-prioritization application with a FastAPI backend and a Next.js frontend. It provides selectable ML-plus-asset and deterministic priority modes, an explainable 320-rule cross-check, role-based access control (RBAC), an immutable audit log, scanner CSV import, and CVE intelligence lookup. The code default is `PRIORITY_MODE=ml_asset`; deterministic selection remains available. ML remains experimental: the frozen 2026 test was negative (XGBoost PR-AUC 0.0114 vs CVSS 0.0117), so the active mode, final-priority source, and rule-matrix cross-check remain visible. See [proposal traceability](./docs/PROPOSAL_TRACEABILITY.md) and the [project snapshot](./docs/PROJECT_SNAPSHOT.md).

## Requirements

- Python and pip
- Node.js and npm
- PostgreSQL 16 for local backend development
- Docker Desktop with Compose (for the demo and PostgreSQL test suite)

## One-command Docker demo

The Docker Compose setup starts PostgreSQL, the frontend, and the backend
together. PostgreSQL data is stored in the `securevision_postgres_data` named
volume. The database container does not publish a host port by default.

1. Copy `.env.example` to `.env`.
2. Set `SECRET_KEY`, `ADMIN_INITIAL_PASSWORD`, `POSTGRES_PASSWORD`, and
   `POSTGRES_APP_PASSWORD` to private, URL-safe random values. Set
   `POSTGRES_DB`, `POSTGRES_USER` (owner/migrator), and `POSTGRES_APP_USER` as
   needed. The example intentionally contains no usable secrets.
3. From the repository root, run:

   ```powershell
   docker compose up --build
   ```

4. Open `http://localhost:3000` and sign in as `admin` using the password from
   `.env`. The API docs are at `http://localhost:8000/docs`.

The PostgreSQL init script creates the app role only for a new data volume.
For a database volume created by an older SecureVision version, retain its
original owner credentials and provision/rotate the app role before replacing
its configuration; otherwise use a new Compose project name to create an
isolated volume.

The demo UI is visibly labeled **SYNTHETIC DEMO DATA** and seeds eight assets
with 40 findings spanning Critical, High, Medium, and Low rule-matrix tiers.
Asset context, finding-to-asset associations, statuses, and dates are synthetic;
the CVE IDs and CVSS/EPSS values use the prepared local dataset where available.
This is not real inventory or an observation of those vulnerabilities in the
demo assets. The seeded rows have no NVD enrichment, so their ML advisory is
shown as unavailable instead of inventing a prediction. Consequently, `deterministic` and `ml_asset` both use the rule-matrix tier as
the final priority for these fixed demo rows. This differs from the separate
fixed-seed 80-scenario offline distribution in `docs/priority_distribution.txt`,
which uses prediction-capable sample CVEs and includes the ML-mode KEV floor.
`sample_data/generic.csv` is illustrative input, not scanner output.
`backend/threat_intel.py` also
contains three hard-coded demonstration lookup fixtures; they are not
authoritative current NVD/FIRST scores. Other live lookups require provider
network access.

The Compose demo binds its services to loopback and does not terminate TLS.
External deployments must provide TLS termination at a suitably configured
reverse proxy; this repository does not configure or verify that deployment
layer.

The backend runs only with the app-role `DATABASE_URL`; it receives no owner
URL or owner password. A one-shot `migrate` service runs Alembic as
`POSTGRES_USER` before the backend starts, and the app role cannot perform DDL
or mutate audit rows. The container build excludes the 201,498,667-byte
prepared CVE CSV and all databases. CVE lookups use the indexed PostgreSQL
`cve_catalog`; a catalog miss falls through to the live provider and reports
unavailability explicitly if that provider also misses.
Synthetic seeding is enabled only in the Compose demo and does not delete or
overwrite existing records.

## Setup

From the repository root, create and activate a Python virtual environment, then install the backend dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Run `.\setup_dev.ps1` from the repository root to create local configuration
files, start PostgreSQL 16, run the owner-credentialed migration service, and
initialize the administrator through the app role. It generates random
URL-safe credentials for both database roles and prints the new administrator
password once. The local script publishes PostgreSQL only on `127.0.0.1:5432`
using `docker-compose.local.yml` and the isolated `securevision-dev` Compose
project. It never overwrites an existing
`backend\.env`; move it aside manually before requesting fresh settings. For an
isolated project, pass `-ComposeProjectName sv_local_test`. `DATABASE_URL` is
the app-role URL; `MIGRATION_DATABASE_URL` is reserved for the migration
service and maintenance/test tools, not the backend service.

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Private JWT signing key; required by the API and must be at least 32 characters. |
| `ADMIN_INITIAL_PASSWORD` | Password used when bootstrapping or rotating the `admin` account; must be at least 8 characters. |
| `DATABASE_URL` | Required SQLAlchemy PostgreSQL runtime URL for the app role. |
| `MIGRATION_DATABASE_URL` | Owner/migrator URL supplied only to the migration service and explicit maintenance/test tools. |
| `PRIORITY_MODE` | `ml_asset` (code default, D-043) or `deterministic`; selects which available tier is persisted as final priority. |
| `POSTGRES_DB` | PostgreSQL database name supplied to the Compose database service. |
| `POSTGRES_USER` | Owner/migrator login supplied to the Compose database service. |
| `POSTGRES_PASSWORD` | Owner/migrator password; use a private, URL-safe value. |
| `POSTGRES_APP_USER` | Non-superuser PostgreSQL login used by the running API. |
| `POSTGRES_APP_PASSWORD` | App-role password; use a private, URL-safe value. |
| `CVE_DATASET_FILENAME` | Dated filename supplied to the one-shot catalog loader. |
| `CVE_DATASET_HOST_PATH` | Read-only host path to the CSV supplied to the loader. |
| `CORS_ORIGINS` | Comma-separated, exact browser origins allowed to call the API. The default is empty; `*` is rejected. |
| `NEXT_PUBLIC_API_BASE` | Frontend API URL. Defaults to `http://localhost:8000`; set it in `frontend/.env.local` when needed. |

`backend/.env` and `frontend/.env.local` are ignored by Git. Next.js reads
`frontend/.env.local` automatically. Python does not load `backend/.env`
automatically, so load it into the backend terminal before starting the API as
shown below.

## Administrator bootstrap and password rotation

There is no default administrator password. For a new database, apply
`alembic upgrade head` through the owner-credentialed migration service first,
then initialize the database with `ADMIN_INITIAL_PASSWORD`. The script creates
the `admin` account only if it does not already exist:

Load the generated backend settings into the current PowerShell session before
running the supported initializer:

```powershell
Get-Content backend\.env | ForEach-Object {
    if ($_ -match '^\s*([^#=]+?)\s*=\s*(.*?)\s*$' -and
        $matches[1].Trim() -in @("DATABASE_URL", "SECRET_KEY", "ADMIN_INITIAL_PASSWORD", "CORS_ORIGINS", "PRIORITY_MODE")) {
        [Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2], "Process")
    }
}
$securePassword = Read-Host "Initial administrator password" -AsSecureString
$env:ADMIN_INITIAL_PASSWORD = [System.Net.NetworkCredential]::new("", $securePassword).Password
python -m backend.init_db
Remove-Item Env:ADMIN_INITIAL_PASSWORD
```

For an existing installation, use the administrator user-management API
`PATCH /users/{user_id}` with a new password to reset an administrator's password;
the root-level `update_admin.py` legacy entry point is disabled.

Run the initializer from the repository root. Load `DATABASE_URL` (app role)
before running it. Root-level SQLite-era maintenance scripts are guarded; use
`scripts/dedupe_postgres.py` for PostgreSQL deduplication and
`SECUREVISION_DEMO_MODE=true` synthetic seeding where appropriate.
The setup script runs migrations in the Compose `migrate` service using the
owner URL.

## Run locally

Initialize the development PostgreSQL database after completing the dependency
setup above:

```powershell
.\setup_dev.ps1
```

`setup_dev.ps1` stops without modifying an existing `backend\.env`. Move or
rename that file yourself only when you intend to create fresh local settings.
An old SQLite URL is rejected when the backend starts; use PostgreSQL as the
`DATABASE_URL`.

In a PowerShell terminal at the repository root, load the generated backend settings and start the API on port 8000:

```powershell
.\.venv\Scripts\Activate.ps1
Get-Content backend\.env | ForEach-Object {
    if ($_ -match '^\s*([^#=]+?)\s*=\s*(.*?)\s*$' -and
        $matches[1].Trim() -in @("DATABASE_URL", "SECRET_KEY", "ADMIN_INITIAL_PASSWORD", "CORS_ORIGINS", "PRIORITY_MODE")) {
        [Environment]::SetEnvironmentVariable($matches[1].Trim(), $matches[2], "Process")
    }
}
python -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

In a second terminal, install and start the frontend on port 3000:

```powershell
Set-Location frontend
npm install
npm run dev
```

The API is available at `http://localhost:8000` and its interactive
documentation at `http://localhost:8000/docs`; open the frontend at
`http://localhost:3000`.

To run the backend in Docker and keep PostgreSQL private to the Compose network,
use `docker compose up --build` instead of starting Uvicorn locally. For local
tools that need a host PostgreSQL connection, `setup_dev.ps1` uses the explicit
loopback-only Compose override; the default Compose file still publishes no
database port.

## Database migrations and SQLite conversion

Alembic owns every schema change. The one-shot Compose `migrate` service runs
`alembic upgrade head` with the owner URL and completes before the API starts.
`docker-entrypoint.sh` does not run migrations; `python init_db.py` only
bootstraps the administrator through the app URL. The migrations create the current models,
audit-log UPDATE/DELETE/TRUNCATE triggers, uniqueness constraints, and
least-privilege app grants and final-priority fields. Alembic uses
`MIGRATION_DATABASE_URL` in the migration service; the backend receives only
the app-role `DATABASE_URL`.
Migration `0003` refuses to proceed if case-insensitive asset-name duplicates
or duplicate `(asset_id, cve_id)` findings exist. It reports each conflict and
points to `scripts/dedupe_postgres.py`; that manual-only script takes a
PostgreSQL owner URL, prints a plan without changing data by default, keeps the
oldest finding per pair, and moves all its score history to that finding.
Pass `--apply` explicitly to write. Asset-name conflicts must be resolved
manually. Never run the script against real data without a reviewed backup and
approval.

For a one-time migration from an existing SQLite installation, first create an
empty PostgreSQL database and apply `alembic upgrade head` using its
`MIGRATION_DATABASE_URL`; use the app URL as `DATABASE_URL`. Then run the
manual-only script with explicit source and target URLs:

```powershell
python scripts\sqlite_to_postgres.py "sqlite:///file:path/to/source.db?mode=ro&uri=true" "postgresql+psycopg2://user:password@host:5432/database"
```

The script opens the source read-only, refuses a non-empty or unmigrated target,
copies users, assets, findings, score history, and audit rows with their IDs and
timestamps, resets PostgreSQL sequences, and verifies copied row counts. It is
not called by setup, startup, Compose, or tests.

## CVE intelligence and scoring

The prepared dataset is optional and is never committed. The current
`data/processed/master_cves_2026-10-08.csv` is 201,498,667 bytes. Other files
read at runtime are:

| Runtime file | Size (bytes) |
|---|---:|
| `ml/models/headline_model_calibrated.joblib` | 170,368 |
| `ml/models/headline_tfidf_transformer.joblib` | 18,010,971 |
| `frozen_config.json` | 4,453 |
| `docs/results/p5/p5_console.log` | 3,246 |
| `docs/results/pipeline_output.txt` | 1,595 |
| `Decision_Log.md` | 21,427 |

These are inference/configuration and evaluation artifacts, not ML training
data. Teammates should request the dated file from the project's approved
internal data custodian/artifact store, then keep it at the documented local
path. CVE lookup requests do not read this file. To populate the database
explicitly, set `CVE_DATASET_FILENAME` and `CVE_DATASET_HOST_PATH` and run the
manual owner-role loader:

```powershell
$env:CVE_DATASET_FILENAME = "master_cves_2026-10-08.csv"
$env:CVE_DATASET_HOST_PATH = ".\data\processed\master_cves_2026-10-08.csv"
docker compose --env-file .env -f docker-compose.yml -f docker-compose.cve-dataset.yml --profile load-catalog run --rm load-catalog
```

The optional `scripts/load_cve_catalog.py` loader streams the read-only CSV in
batches, upserts idempotently into `cve_catalog`, and is never invoked by
application startup. Loading the prepared
catalog of 384,522 rows takes about 33 minutes. Catalog loading is optional: on
a fresh clone without a populated catalog, an uncached single-CVE lookup falls
back to the live provider. The runtime app role has SELECT-only privileges on
the catalog. `GET /cves/{cve_id}` reports
`catalog`, `postgres_cache`, or `live_provider`; when the catalog is empty or
does not contain an ID, a live provider miss returns an explicit unavailable
response. `GET /cves` search uses the catalog and cache and reports its source in
`X-CVE-Lookup-Source`. Scans use catalog descriptions and missing score fields
for their ML advisory when the live provider has no network response.

For reproducible host-side distribution evidence, run
`python -m scripts.priority_distribution`; it samples 20 KEV and 20 non-KEV
CVEs with a fixed seed and compares the rules and `ml_asset` tiers on two
hypothetical assets. Its checked-in output is `docs/priority_distribution.txt`.

`POST /token` returns a typed bearer-token response. Authenticated `GET /intel/{cve_id}` validates identifiers using the same `CVE-YYYY-NNNN...` format as scans and returns EPSS/CVSS plus the NVD description, CVSS vector, CWE, and publication date as nullable values. A provider failure or missing score is not represented as a numeric zero.

The scan form can look up scores before submission. Blank score fields are resolved by the backend; if a score required for scoring cannot be obtained, `POST /scan` returns `503` and does not create a finding. CSV imports likewise skip rows whose intelligence is unavailable and report the provider error in the row result. Explicitly entered scan scores remain manual inputs.

The scorer evaluates CVSS, EPSS, recorded KEV status, internet exposure, and asset criticality against the documented 320-row rule matrix. KEV status is a scoring input; there is no live CISA KEV feed integration. Every finding stores `final_priority` and `priority_source`; the rule tier remains available as a visible cross-check.

The additional calibrated XGBoost likelihood uses only CVSS score/vector, CWE, and the publication-time NVD description; KEV and EPSS are explicitly excluded from its feature list. ML risk is `likelihood × exposure_factor × criticality_factor`: Internet exposure is 1.5, Internal is 1.0, and criticality 1-5 maps linearly from 0.6 to 1.4. The P99/P90/P50 risk thresholds are derived from the 2025 validation-set risk distribution, not the test set. Factors, thresholds, mode, the known-exploited High floor, and recommended-action templates are centralized in [`backend/rules_config.py`](./backend/rules_config.py).

In `ml_asset` mode, a successful prediction makes `final_priority` the ML priority (`ml`); absent ML output falls back to the rule-matrix tier (`rules`). This is the current default (D-043). `deterministic` mode stores the rule-matrix tier and source `rules`. If a KEV-flagged finding's ML tier is below High, a rules-layer floor raises it to High and records `ml+kev_floor` (D-043). KEV remains a runtime fact and never enters model features. The API `/me` response and UI label the active mode and show the final priority/source, ML evidence, and rule cross-check. The drawer and Model Results screen preserve the negative test result (PR-AUC 0.0114 vs CVSS 0.0117) and validation reference (0.0352). Missing model inputs or artifacts leave ML fields null with an explicit reason.

The authenticated `GET /model/results` endpoint and **Model Results** screen are available to all roles. They show immutable recorded results and the dated offline validation package. Test 2026 evidence exists for XGBoost and CVSS/EPSS baselines; the Validation 2025 comparison includes training-CV-tuned Logistic Regression, Random Forest, XGBoost, CVSS-only, and EPSS. The tuned LR achieved PR-AUC `0.021292` versus `0.020851` for the historical fixed-parameter run, which remains visible and available in `docs/results_offline/2026-11-14/`. No LR or RF test result is recorded. The frozen test result is negative: XGBoost PR-AUC 0.0114 versus CVSS 0.0117; XGBoost also trails CVSS at P@100 and P@500. EPSS is shown as a hindsight baseline, not a prospective comparison. Metrics not present in the recorded results are shown as not available. The frozen XGBoost calibrator was fitted on Validation 2025; this disclosed exception keeps proposal requirement (g) PARTIAL.

## CSV scanner imports

The Import tab previews generic CSVs and Nessus, Qualys, and OpenVAS/Greenbone
exports. The preview identifies the detected format, expands multi-CVE cells
into separate findings, and reports all validation problems for each imported
row. Inputs support UTF-8 (including a BOM), quoted CSV fields, ISO dates,
ISO datetimes, and slash dates in day/month/year or month/day/year order.
The day/month order selector defaults to DD/MM; the preview reports how many
rows contain ambiguous dates and which order will be applied. CVSS supplied by
the file is used when present; otherwise the backend uses threat intelligence. Findings
are skipped when the required intelligence remains unavailable.

The optional **Create missing assets** checkbox defaults off. When enabled,
missing assets are created as Internal with criticality 3 and marked **Needs
review** in the asset inventory. Their creation and the import audit record are
committed atomically with the findings. CSV limits remain 5 MiB and 5,000 data
rows. Example files for each supported format are in [`sample_data/`](./sample_data/).

For generic CSVs, the required fields are:

- `asset_name` (also recognizes host, hostname, DNS, FQDN, and IP aliases)
- `cve_id` (also recognizes CVE and vulnerability-ID aliases)
- `date_found` (also recognizes common first/last-seen, detected, and discovered date aliases)

`cvss_score` is optional (common CVSS header variants are accepted). Exposure,
exploit status, and data-sensitivity columns are not accepted as import fields.
Scanner-specific formats are detected from their headers and mapped through the
same required fields.

## Reports, RBAC, and audit log

Authenticated `GET /reports/findings.csv` and `GET /reports/executive.pdf`
produce server-side downloads. The CSV endpoint accepts priority, status,
asset, search, and sort filters. Each export records its format, filters, row
count, and SHA-256 digest in the audit log.

Administrators can create users, change roles, reset passwords, deactivate and
reactivate users, and delete users without audit history. Deleting a user with
audit history returns `409` and directs the administrator to deactivate instead.
Administrators cannot deactivate themselves or the last active administrator.
Successful and failed login attempts are audited with the
attempted username and timestamp; passwords are never written to audit details.
Failed attempts for existing and unknown usernames return the same response.

## Research: offline ML evaluation (negative result; ml_asset code default)

The calibrated XGBoost model is an experimental priority input when
`PRIORITY_MODE=ml_asset`, the current code default (Decision Log D-043).
The frozen
single-pass evaluation on 61,611 held-out rows
(122 positives) reported test PR-AUC 0.0114 versus 0.0117 +/- 0.0018 for CVSS.
The paired-bootstrap mean PR-AUC difference was -0.0004 (95% CI: -0.0081 to
0.0045), which does not establish an improvement. The model also had lower
P@100 (0.0000 vs. 0.0428) and P@500 (0.0060 vs. 0.0243). EPSS is a hindsight
snapshot and is not a like-for-like prospective baseline. This negative result
is also recorded in `Decision_Log.md`; see
[`docs/results/p5/p5_console.log`](./docs/results/p5/p5_console.log) and
[`docs/P5_protocol.md`](./docs/P5_protocol.md).

The configured headline artifact is XGBoost 2.0.3 with scikit-learn 1.4.1.post1
and joblib 1.6.0 as pinned in `requirements.txt`. Top-factor explanations use
native XGBoost TreeSHAP contributions (`pred_contribs`), with the contribution
sum checked against the booster margin. CSR serving preserves sparse
zero/missing semantics and exactly matches saved Validation 2025 scores on the
2,126-row parity sample (D-042). The CVSS C/I parser probe also exposed an
unanchored-pattern limitation: `AC:L` can be matched as `C=L`, and `UI:N` as
`I=N`; see D-042. The test set is not used to configure the ML risk thresholds.

## Roadmap (not implemented)

- Jira ticket creation and webhook automation
- Live CISA KEV feed integration
- Data-sensitivity weighting in scoring

## Tests

All application/database tests require PostgreSQL and use disposable schemas;
there is no SQLite fallback. Prepare a dedicated `.env.verify` file with
throwaway credentials, then run the full suite in an isolated Compose project:

```powershell
docker compose -p sv_verify4 --env-file .env.verify --profile postgres-tests run --rm backend-tests
```

For `pytest` outside Compose, set the explicit test flag and both PostgreSQL
URLs; never point them at a development or production database:

```powershell
$env:SECUREVISION_POSTGRES_TESTS = "1"
$env:DATABASE_URL = "postgresql+psycopg2://user:password@localhost:5432/securevision"
$env:MIGRATION_DATABASE_URL = "postgresql+psycopg2://owner:password@localhost:5432/securevision"
pytest
Remove-Item Env:SECUREVISION_POSTGRES_TESTS
Remove-Item Env:DATABASE_URL
Remove-Item Env:MIGRATION_DATABASE_URL
```
