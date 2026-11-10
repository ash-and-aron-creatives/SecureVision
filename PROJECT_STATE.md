# Project State: SecureVision
* **Current Phase:** P6 (Backend Architecture & Rules Layer)
* **Status:** P5 Complete (Negative Result Confirmed). ML-assisted likelihood and risk are integrated as nullable, experimental advisory fields; the deterministic 320-rule tier remains primary and unchanged. Blueprint sections 10-11 and 13 gap closure is implemented.
* **Data Split:** Train: 2022-2024, Val: 2025, Test: 2026-01 to 2026-09-08 (Held-Out). Prospective Holdout running daily.
* **Label Definition:** in_cisa_kev_catalog AND (kev_date_added <= published_date + 30 days).
* **Likelihood Provider:** Deterministic scoring remains unchanged. Frozen calibrated XGBoost is an additional advisory signal using publication-time CVSS/vector/CWE/description features only; KEV and EPSS are excluded from model features.
* **ML Risk Formula:** `likelihood × exposure_factor × criticality_factor`; constants, validation-derived risk thresholds, and recommended-action templates are in `backend/rules_config.py`.
* **Model Results:** Authenticated `/model/results` and frontend Model Results screen expose only recorded evaluation data, with unavailable metrics left null/not available.
* **Migration:** Startup idempotently adds nullable ML fields to existing `finding_scores` tables and metadata fields to existing `assets` tables; existing rows are preserved. The fallback `cves` table is only created when the prepared CVE dataset is unavailable.
* **Authentication:** `/me` is available; login throttling allows five failed attempts per username/IP in 15 minutes and is process-local. Refresh tokens were deferred; PBKDF2-HMAC-SHA256 remains at 600,000 iterations.
* **Assets:** Admin/analyst create, edit, and delete are audited transactionally; assets with findings cannot be deleted. CSV host/IP lookup checks both asset name and `ip_or_domain`.
* **CVE lookup:** Authenticated endpoints use the prepared `data/processed/master_cves_2026-10-08.csv` read-only and lazily when available; KEV/EPSS remain excluded from model features.
* **Dashboard:** Real total-assets, open-vulnerabilities, critical, and fixed-this-month values are exposed from persisted assets/findings/audit history.
* **Validation:** `pytest -q` passed 465 tests. Frontend type-check, lint, and production build passed; `npm audit` reported zero vulnerabilities.
* **Next Step:** Continue prospective evaluation; do not promote ML to the deterministic tier without new evidence.
