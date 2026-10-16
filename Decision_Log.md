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
