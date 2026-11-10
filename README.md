# SecureVision

SecureVision is a vulnerability-prioritization application with a FastAPI backend and a Next.js frontend. It provides deterministic, explainable scoring across a 320-rule matrix, role-based access control (RBAC), an immutable audit log, scanner CSV import, and CVSS/EPSS lookup. The live priority tier comes from the deterministic backend scorer; experimental machine-learning work is offline and does not drive scoring.

## Requirements

- Python and pip
- Node.js and npm

## Setup

From the repository root, create and activate a Python virtual environment, then install the backend dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Run `.\setup_dev.ps1` from the repository root to create local configuration files if they do not already exist and initialize `securevision_dev.db`. The script generates a random signing key and initial administrator password, then prints the initial credentials once when it creates the backend configuration. The script never targets `securevision.db`.

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Private JWT signing key; required by the API and must be at least 32 characters. |
| `ADMIN_INITIAL_PASSWORD` | Password used when bootstrapping or rotating the `admin` account; must be at least 8 characters. |
| `DATABASE_URL` | SQLAlchemy database URL. The local setup script sets this to `sqlite:///./securevision_dev.db`, relative to the repository root. |
| `CORS_ORIGINS` | Comma-separated, exact browser origins allowed to call the API. The default is empty; `*` is rejected. |
| `NEXT_PUBLIC_API_BASE` | Frontend API URL. Defaults to `http://localhost:8000`; set it in `frontend/.env.local` when needed. |

`backend/.env` and `frontend/.env.local` are ignored by Git. Next.js reads `frontend/.env.local` automatically. Python does not load `backend/.env` automatically, so load it into the backend terminal before starting the API as shown below.

## Administrator bootstrap and password rotation

There is no default administrator password. For a new database, set `ADMIN_INITIAL_PASSWORD` securely and initialize the database. The script creates the `admin` account only if it does not already exist:

```powershell
$securePassword = Read-Host "Initial administrator password" -AsSecureString
$env:ADMIN_INITIAL_PASSWORD = [System.Net.NetworkCredential]::new("", $securePassword).Password
python init_db.py
Remove-Item Env:ADMIN_INITIAL_PASSWORD
```

For an existing installation, use the same `DATABASE_URL` as the running application and run `update_admin.py` to rotate the existing administrator's password. This operation also records an audit event:

```powershell
$securePassword = Read-Host "Replacement administrator password" -AsSecureString
$env:ADMIN_INITIAL_PASSWORD = [System.Net.NetworkCredential]::new("", $securePassword).Password
python update_admin.py
Remove-Item Env:ADMIN_INITIAL_PASSWORD
```

Both scripts must be run from the repository root so Python can import the `backend` package.

## Run locally

Initialize the development database after completing the dependency setup above:

```powershell
.\setup_dev.ps1
```

In a PowerShell terminal at the repository root, load the generated backend settings and start the API on port 8000:

```powershell
.\.venv\Scripts\Activate.ps1
Get-Content backend\.env | ForEach-Object {
    if ($_ -match '^\s*([^#=]+?)\s*=\s*(.*?)\s*$') {
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

The API is available at `http://localhost:8000` and its interactive documentation at `http://localhost:8000/docs`; open the frontend at `http://localhost:3000`.

## CVE intelligence and scoring

`POST /token` returns a typed bearer-token response. Authenticated `GET /intel/{cve_id}` validates identifiers using the same `CVE-YYYY-NNNN...` format as scans and returns EPSS and CVSS as nullable values, with an `available` flag and provider errors. A provider failure or missing score is not represented as a numeric zero.

The scan form can look up scores before submission. Blank score fields are resolved by the backend; if a score required for scoring cannot be obtained, `POST /scan` returns `503` and does not create a finding. CSV imports likewise skip rows whose intelligence is unavailable and report the provider error in the row result. Explicitly entered scan scores remain manual inputs.

The scorer evaluates CVSS, EPSS, recorded KEV status, internet exposure, and asset criticality against the documented 320-row rule matrix. KEV status is a scoring input; there is no live CISA KEV feed integration. Scoring returns the tier, ordinal score, and rationale. The queue and dashboard use backend findings and analytics; the queue loads findings pages up to a 10,000-item safety cap and shows a notice if the cap is reached.

## CSV scanner imports

The Import tab previews generic CSVs and Nessus, Qualys, and OpenVAS/Greenbone
exports. The preview identifies the detected format, expands multi-CVE cells
into separate findings, and reports all validation problems for each imported
row. Inputs support UTF-8 (including a BOM), quoted CSV fields, ISO dates,
ISO datetimes, and slash dates in day/month/year or month/day/year order
(ambiguous slash dates are interpreted day-first). CVSS supplied by the file
is used when present; otherwise the backend uses threat intelligence. Findings
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

Administrators can create users, change roles, reset passwords, and delete
other users. Administrators cannot remove themselves or demote/delete the last
administrator. Successful and failed login attempts are audited with the
attempted username and timestamp; passwords are never written to audit details.
Failed attempts for existing and unknown usernames return the same response.

## Research: offline ML evaluation (negative result, not used in live scoring)

SecureVision's ML experiments are an offline, experimental advisory signal; no
ML model is connected to the live scoring path or determines a finding's tier.
The frozen single-pass evaluation on 61,611 held-out rows (122 positives)
reported test PR-AUC 0.0114 for the calibrated XGBoost model versus
0.0117 +/- 0.0018 for the CVSS ranking baseline. The paired-bootstrap mean
PR-AUC difference was -0.0004 (95% CI: -0.0081 to 0.0045), which does not
establish an improvement. The model also had lower P@100 (0.0000 vs. 0.0428)
and P@500 (0.0060 vs. 0.0243). The hindsight EPSS snapshot is not a
like-for-like prospective baseline. See [`docs/results/p5/p5_console.log`](./docs/results/p5/p5_console.log)
and [`docs/P5_protocol.md`](./docs/P5_protocol.md) for the recorded metrics and
protocol.

## Roadmap (not implemented)

- Jira ticket creation and webhook automation
- Live CISA KEV feed integration
- Data-sensitivity weighting in scoring

## Tests

Run all backend tests from the repository root with the Python environment activated:

```powershell
pytest
```

Pytest configures its own temporary SQLite database for the tests.
