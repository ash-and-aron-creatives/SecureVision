# SecureVision

SecureVision is a vulnerability-prioritization application with a FastAPI backend and a Next.js frontend. The backend scores findings using KEV, internet exposure, asset criticality, EPSS, and CVSS; the frontend provides dashboards, triage, CVE intelligence lookup, CSV import, asset management, and administrator views.

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

## Tests

Run all backend tests from the repository root with the Python environment activated:

```powershell
pytest
```

Pytest configures its own temporary SQLite database for the tests.
