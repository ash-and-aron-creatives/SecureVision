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

### D-023: Additive ML Advisory and Frozen Artifact Use
* **Decision:** Keep the existing 320-rule deterministic matrix as the sole source of `priority_tier` and score. The calibrated XGBoost likelihood and its exposure/criticality-adjusted risk are supplemental, experimental fields only; unavailable predictions remain null with an explicit reason.
* **Frozen headline artifact:** `headline_model_calibrated.joblib` named by `frozen_config.json`, SHA-256 `1390b1e65ff9bbf9dc3a3f37659a577c32af0f7aac9bb47711f8394331bc8ed1`. The runtime copy in `ml/models/` was byte-verified against that hash. The model requires 152 ordered features: CVSS score/missing indicator; CVSS vector categories; CWE categories; and 100 description TF-IDF terms. KEV and EPSS are not model features. The compatible TF-IDF transformer was regenerated from the frozen 2022-2024 training descriptions using the configured blacklist and TF-IDF settings; its 100-term vocabulary hash matches `frozen_config.json` (`35af7ab9e1cab7dbd5e035a47ad24b36913800819eaefac45ee99c2efdf3931e`). Existing incompatible transformer artifacts are not used.
* **Risk formula:** `ml_risk = ml_likelihood × exposure_factor × criticality_factor`. Exposure is 1.5 for Internet and 1.0 for Internal. Criticality 1-5 maps linearly to 0.6, 0.8, 1.0, 1.2, and 1.4. Implementation constants and recommended-action templates live in `backend/rules_config.py`.
* **Threshold method:** Compute risk on the 2025 validation-set likelihoods for each of the ten supported exposure/criticality contexts (48,152 validation CVEs; 481,520 risk values). Set Critical at or above P99 (`0.044082497805356974`), High at or above P90 (`0.007056011210661384`), Medium at or above P50 (`0.0008546133991330863`), and Low below P50. No test-set observations were used.
* **Explanations and dependencies:** SHAP is not installed; use XGBoost native `pred_contribs` for the top three factors. `requirements.txt` already pins XGBoost 2.0.3, scikit-learn 1.4.1.post1, and joblib 1.6.0; the current runtime matches these pins. The frozen config does not record artifact-producer versions, so exact train-time package parity cannot be independently established.
* **Model Results:** Read only recorded files in `docs/results/`. Logistic Regression validation PR-AUC results exist; no Random Forest metric result is recorded. Missing precision/recall/F1/ROC-AUC values remain not available. EPSS is labeled hindsight. The test-set negative result remains explicit and does not change the deterministic tier.
* **Conclusion:** Held-out XGBoost PR-AUC was 0.0114 versus CVSS 0.0117; top-K precision was also lower at P@100 and P@500. This offline evaluation did not demonstrate an improvement, so ML is an advisory signal only and does not drive the tier.
