# Project State: SecureVision
* **Current Phase:** P6 (Backend Architecture & Rules Layer)
* **Status:** P5 Complete (Negative Result Confirmed). ML-assisted likelihood and risk are integrated as nullable, experimental advisory fields; the deterministic 320-rule tier remains primary and unchanged.
* **Data Split:** Train: 2022-2024, Val: 2025, Test: 2026-01 to 2026-09-08 (Held-Out). Prospective Holdout running daily.
* **Label Definition:** in_cisa_kev_catalog AND (kev_date_added <= published_date + 30 days).
* **Likelihood Provider:** Deterministic scoring remains unchanged. Frozen calibrated XGBoost is an additional advisory signal using publication-time CVSS/vector/CWE/description features only; KEV and EPSS are excluded from model features.
* **ML Risk Formula:** `likelihood × exposure_factor × criticality_factor`; constants, validation-derived risk thresholds, and recommended-action templates are in `backend/rules_config.py`.
* **Model Results:** Authenticated `/model/results` and frontend Model Results screen expose only recorded evaluation data, with unavailable metrics left null/not available.
* **Migration:** Startup idempotently adds nullable ML fields to existing `finding_scores` tables; existing rows are preserved.
* **Next Step:** Continue backend/frontend validation and prospective evaluation; do not promote ML to the deterministic tier without new evidence.
