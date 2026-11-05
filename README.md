# SecureVision

SecureVision is a vulnerability-prioritization application with a FastAPI backend and a Next.js frontend. The backend scores findings using KEV, internet exposure, asset criticality, EPSS, and CVSS; the frontend provides dashboards, triage, CSV import, asset management, and administrator views.

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

The backend reads configuration from its process environment. `.env.example` lists the variable names and example values, but the Python scripts do not load that file automatically. Configure the variables in the same PowerShell session used to initialize and run the backend:

```powershell
$env:SECRET_KEY = python -c "import secrets; print(secrets.token_urlsafe(48))"
$env:DATABASE_URL = "sqlite:///./securevision.db"
$env:CORS_ORIGINS = "http://localhost:3000,http://127.0.0.1:3000"
```

| Variable | Purpose |
|---|---|
| `SECRET_KEY` | Private JWT signing key; required by the API and must be at least 32 characters. |
| `ADMIN_INITIAL_PASSWORD` | Password used when bootstrapping or rotating the `admin` account; must be at least 8 characters. |
| `DATABASE_URL` | SQLAlchemy database URL. Defaults to `sqlite:///./securevision.db`, relative to the backend process's working directory. |
| `CORS_ORIGINS` | Comma-separated, exact browser origins allowed to call the API. The default is empty; `*` is rejected. |
| `NEXT_PUBLIC_API_BASE` | Frontend API URL. Defaults to `http://localhost:8000`; set it in `frontend/.env.local` when needed. |

`frontend/.env.example` is the frontend template. Next.js reads `frontend/.env.local` automatically; that local file is ignored by Git.

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

## Run the applications

Run the backend in one PowerShell terminal from the repository root. Set `SECRET_KEY`, `DATABASE_URL`, and `CORS_ORIGINS` as shown above; initialize a new database first if needed:

```powershell
python -m uvicorn backend.main:app --reload
```

The API is available at `http://localhost:8000`, with interactive API documentation at `http://localhost:8000/docs`.

In a second terminal, install and start the frontend:

```powershell
Set-Location frontend
Copy-Item .env.example .env.local
npm install
npm run dev
```

Open `http://localhost:3000`. If the backend is hosted elsewhere, update `NEXT_PUBLIC_API_BASE` in `frontend/.env.local` and restart the frontend process.

## Tests

Run all backend tests from the repository root with the Python environment activated:

```powershell
pytest
```

Pytest configures its own temporary SQLite database for the tests.
