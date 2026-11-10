# SecureVision 10-minute demo

This walkthrough is for the Docker Compose synthetic demo. All seeded asset
names, observations, CVSS/EPSS inputs, and dates are illustrative synthetic
records, not real customer data or scanner output. The demo-mode UI badge is
deliberately visible. The model advisory for seeded rows is unavailable because
the synthetic records contain no NVD enrichment; do not present invented
predictions as measured results.

## Before the demo

1. Copy `.env.example` to `.env` and set a private `SECRET_KEY` (at least 32
   characters) and `ADMIN_INITIAL_PASSWORD` (at least 8 characters).
2. From the repository root, run `docker compose up --build`; open
   `http://localhost:3000`. The API documentation is at
   `http://localhost:8000/docs`.
3. Sign in as `admin` using the password in the local `.env`. No default
   password is supplied. The backend creates its database in the
   `securevision_demo_data` named volume; it does not mount either repository
   SQLite database.
4. The seeded assets are `Payment-DB` and `Internal-API`. The seeded CVE IDs
   beginning `CVE-2099-` are synthetic placeholders.

## Timed flow

### 0:00–1:00 — Login and scope

- Sign in as the configured `admin`.
- Point out the **SYNTHETIC DEMO DATA** badge.
- Explain the app roles: administrators can manage users and inspect audit
  events; analysts can triage and import; viewers have read-only access.

### 1:00–2:00 — Import a CSV

- Open **Import CSV** and select `sample_data/generic.csv`.
- Preview the detected Generic format, then commit the row.
- Explain that the checked-in sample is illustrative input, not a real scanner
  export. The current service has three hard-coded demo intelligence fixtures;
  they are not current authoritative EPSS/NVD values. Live NVD/FIRST lookups
  may be used for other CVEs when network access is available.
- If live providers or the demo fixture are unavailable, show the reported
  import error rather than claiming the row was imported.

### 2:00–3:00 — Dashboard

- Return to **Dashboard**.
- Point out that counts are based on current persisted demo records.
- Do not describe the synthetic counts as production prevalence or evaluation
  metrics.

### 3:00–4:30 — Finding drawer and the two signals

- Open **Priority Queue** and select a seeded `CVE-2099-` finding.
- Show the deterministic tier, rationale, and scoring inputs.
- Show the separate **ML-assisted risk (experimental, advisory)** panel.
  Seeded values correctly show **Unavailable** and explain that synthetic rows
  lack NVD enrichment; the ML section is not a fabricated score.
- Clarify that the 320-rule matrix is the only source of the operational tier.
  ML risk uses `likelihood × exposure_factor × criticality_factor` and does
  not use KEV or EPSS as model features.

### 4:30–5:30 — Model Results

- Open **Model Results**.
- Explain that the view reads recorded evaluation outputs and leaves missing
  metrics unavailable.
- Report the recorded held-out comparison only: XGBoost PR-AUC `0.0114` vs
  CVSS `0.0117 +/- 0.0018`; the recorded report also shows lower XGBoost
  P@100 (`0.0000` vs `0.0428`) and P@500 (`0.0060` vs `0.0243`).
- State the conclusion plainly: the offline result is negative; it does not
  support replacing CVSS or promoting ML to the primary tier.

### 5:30–6:30 — Exports

- Return to **Priority Queue** and use **Export CSV**.
- Return to **Dashboard** and use **Export Report** for the executive PDF.
- Explain that exports are authenticated and each export is recorded with its
  format, filters, row count, and digest in the audit trail.

### 6:30–7:30 — Audit log

- Open **Audit Log**.
- Point out login, seed, import, and export events that exist in the current
  demo session. The synthetic seed event is explicitly named.
- Note that SQLite triggers prevent updates and deletes to audit entries.

### 7:30–9:30 — Roles

- Open **Users (RBAC)**, create one analyst and one viewer with temporary demo
  passwords, and sign out.
- Sign in as the analyst: show import/triage availability and the absence of
  administrator-only user and audit tabs.
- Sign in as the viewer: show read-only findings and explain that write
  endpoints reject viewer actions.
- Do not reuse these demo accounts outside the isolated demo.

### 9:30–10:00 — Close with limitations

- Reiterate: synthetic assets/findings, no active network scanning, incomplete
  KEV freshness, dependence on external providers for uncached intelligence,
  and a negative ML result.
- State that the exact SecureVision Master Blueprint was not included in this
  checkout, so its original Section 18 viva prompts could not be reproduced.

## Recovery

- The seed runs once on the isolated named volume. It never clears existing
  data; restarting the stack leaves the demo records unchanged.
- If an import cannot reach providers, report that limitation and continue to
  the seeded findings and recorded results. Do not change the synthetic seed
  to make the walkthrough appear more successful.
