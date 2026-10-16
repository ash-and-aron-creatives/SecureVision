# Project State: SecureVision
* **Current Phase:** P6 (Backend Architecture & Rules Layer)
* **Status:** P5 Complete (Negative Result Confirmed). Backend scoring and architecture under development based on Option A (Modular Likelihood Provider).
* **Data Split:** Train: 2022-2024, Val: 2025, Test: 2026-01 to 2026-09-08 (Held-Out). Prospective Holdout running daily.
* **Label Definition:** in_cisa_kev_catalog AND (kev_date_added <= published_date + 30 days).
* **Likelihood Provider:** Default = EPSS (daily FIRST snapshot) + KEV flag + CVSS fallback.
* **Open Issues:** Evaluating Option B time-boxed scope vs. academic deadline.
* **Next Step:** Implement Backend Schema & Scenario-based Pytest Matrix validation.
