# SecureVision ? Master Blueprint Traceability Matrix

| Blueprint Requirement | Backend Implementation | Frontend View / Hook | Automated Verification (`pytest`) |
| :--- | :--- | :--- | :--- |
| **Core: 320-Rule Deterministic Scoring Engine** | `backend/scoring_engine.py` (`calculate_priority`, 320 combinations) | Dashboard Queue & Provenance Modal (`selectedFinding`) | `test_scoring.py::test_scoring_monotonicity_and_exhaustiveness` (1/1) |
| **Auth: JWT & Bcrypt Authentication** | `backend/auth.py` (`os.getenv("SECRET_KEY")`, `/token`) | Login Screen (`handleLogin`, Bearer token header) | `test_auth.py` (3/3: hashing, login 200/401, missing/invalid JWT 401) |
| **Step 1: Batch CSV Import & Validation** | `backend/csv_import.py` (`/imports/preview`, `/imports/commit`, 2MB/1000-row limits, BOM, formula guard) | `view === "import"` (2-step Preview & Commit wizard) | `test_csv_import.py` (8/8 tests) |
| **Step 2: Prioritized Queue & Triage** | `backend/main.py` (`GET /findings`, ` GET /findings/{id}`, `PUT /findings/{id}/status`) | `view === "dashboard"` (Filter bar, Queue table, Explain modal) | `test_findings_api.py` (4/4 tests) |
| **Step 3: Executive PDF & CSV Reports** | `backend/reports.py` (`/reports/findings.csv`, `/reports/executive.pdf`, SHA-256 digest) | Dashboard Export CSV & Export PDF buttons | `test_reports.py` (6/6 tests) |
| **Step 4: Admin RBAC & User Management** | `backend/users.py` (`/users` CRUD, self-demotion/deletion guards, role matrix) | `view === "users"` (Admin RBAC management table) | `test_users_rbac.py` (4/4 tests) |
| **Security: True Audit Trail Immutability** | `backend/models.py` (ORM listeners) + `backend/database.py` (SQLite `BEFORE UPDATE/DELETE` triggers) | `view === "audit"` (Chronological security audit table) | `test_scan_assets_audit.py` (3/3 tests) |
| **Demo Readiness: Pre-Seeded Dataset** | `seed_db.py` & `securevision.db` (Enterprise assets + realistic CVEs) | Populated immediately on login | Verified live at `http://localhost:3000` |
