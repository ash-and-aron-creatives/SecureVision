# Viva notes — repository evidence only

## Scope note

The repository does not include `SecureVision_Master_Blueprint`, so the exact
Section 18 viva questions are unavailable. These are concise evidence-grounded
answers to likely project topics, not a claim that unseen questions have been
answered verbatim. Numerical results below are transcribed from the recorded
repository results and are not estimates.

## Evidence-grounded answers

### What does SecureVision do?

It is a FastAPI and Next.js vulnerability-triage application. It imports scanner
CSV exports, maintains an asset inventory and finding queue, and supports
deterministic or ML-plus-asset priority modes with a visible 320-row rule
cross-check. It also supports role-based access and audited reports. The code
does not perform active network discovery or vulnerability scanning.

### How is the operational priority determined?

`PRIORITY_MODE=ml_asset` is the current code default and stores the successful
model priority as `final_priority`, falling back to the rule-matrix tier when
ML is unavailable. `PRIORITY_MODE=deterministic` remains selectable. The recorded test PR-AUC is lower than CVSS
(0.0114 vs 0.0117), so the Model Results screen preserves that evidence and the
finding drawer shows the active mode and rule-matrix cross-check. The ML tier is
calculated from likelihood × exposure × criticality with 2025 validation
percentile cutoffs, and falls back to the rule tier when ML is unavailable.
The rule-matrix tier remains visible as a cross-check. In ML mode, KEV applies
after prediction as a documented rules-layer High floor; if it changes the tier,
`priority_source` is `ml+kev_floor`. KEV and EPSS are never model features.

### What is the ML contribution, and does it improve results?

The calibrated XGBoost model is experimental. Native XGBoost
`pred_contribs` supplies TreeSHAP contributions; contributions plus bias are
checked against the booster margin. Serving uses CSR rows to preserve sparse
zero/missing semantics, matching the Validation 2025 training matrix (D-042).
Publication-time CVSS/vector/CWE/description features are used; KEV and EPSS
are excluded from the feature set.

The recorded held-out test contains 61,611 rows (122 positives). XGBoost
PR-AUC is `0.0114`, compared with CVSS `0.0117 +/- 0.0018`. The recorded
paired-bootstrap mean difference is `-0.0004` (95% CI `-0.0081` to `0.0045`).
XGBoost P@100 is `0.0000` vs `0.0428` for CVSS and P@500 is `0.0060` vs
`0.0243`. This is a negative result: the evidence does not establish an
improvement. Source: `docs/results/p5/p5_console.log`, `docs/P5_protocol.md`,
and `Decision_Log.md`. Validation reference PR-AUC is `0.0352`. Recorded split
availability now includes the five-way Validation 2025 comparison:
XGBoost, training-CV-tuned Logistic Regression, Random Forest, CVSS-only, and
EPSS hindsight baseline. Logistic Regression uses a 10-candidate `C` and
class-weight grid with 3-fold stratified CV on training rows; out-of-fold
training scores separately select its threshold. Random Forest was tuned by
3-fold randomized CV on training rows only. The prior fixed-parameter LR result
remains in `docs/results_offline/2026-11-14/`; the tuned run and CV scores are
in `docs/results_offline/2026-11-15/`. XGBoost's frozen sigmoid calibrator was
fit on Validation 2025, a disclosed exception. Neither run changes the prior
Test 2026 result. Despite the negative test result, `ml_asset` is now the
proposal-aligned default; it is still experimental.
The tuned LR achieved Validation 2025 PR-AUC `0.021292` (precision `0.041096`,
recall `0.047619`, F1 `0.044118`, ROC-AUC `0.845647`), versus historical fixed
LR PR-AUC `0.020851` (precision `0.032967`, recall `0.047619`, F1 `0.038961`,
ROC-AUC `0.854879`). This modest PR-AUC/F1 increase does not establish
generalization beyond this validation split.

### How was time separation handled?

The recorded split is training 2022–2024, validation 2025, and held-out test
2026-01 through 2026-09-08. Risk thresholds are derived from validation-set
values, not the test set. The repository also records a boundary-day
observation limitation in `Decision_Log.md` (D-019). Past results still may
not predict future behavior; prospective evaluation remains necessary.

### How do CVE and threat-intelligence lookups work?

`backend/threat_intel.py` requests EPSS from FIRST and CVE data from NVD for
live lookups, and preserves missing values/provider errors instead of
substituting zero. Three hard-coded entries in `DEMO_CACHE` are demonstration
fixtures and must not be presented as authoritative current values.
Separately, authenticated `/cves` lookup uses the prepared
`data/processed/master_cves_2026-10-08.csv` when it is present; without that
file it uses the database cache. The Docker demo omits the 201,498,667-byte
prepared CSV and therefore uses the fallback path.

### Why PostgreSQL and PBKDF2?

PostgreSQL 16 is the application and test database. Alembic runs as a one-shot
owner-credentialed Compose service before the backend; the backend receives
only the app-role `DATABASE_URL`.
PBKDF2-HMAC-SHA256 at 600,000 iterations is retained to preserve existing
password hashes; Argon2/bcrypt migration was not performed.

### How are access and audit events protected?

JWT authentication and role checks gate APIs. Admin-only screens include user
management and audit review; analyst write permissions and viewer restrictions
are tested. PostgreSQL audit records have ORM protections and database
triggers against update/delete/truncate. Login throttling is process-local,
and refresh tokens are not implemented.

## Limitations to state explicitly

- **KEV incomplete:** there is no live CISA KEV feed integration; KEV state can
  be stale or absent.
- **Historical generalization:** past data and held-out results may not predict
  future exploitation behavior; ongoing prospective evaluation is needed.
- **Synthetic assets:** demo records, asset names, values, and dates are
  synthetic. They are not customer assets, scanner output, or performance
  evidence.
- **Rules layer:** the 320-rule matrix is a visible cross-check and deterministic
  fallback; it is not shown to be universally optimal.
- **Synthetic distribution:** the fixed demo findings have no descriptions/model
  outputs, so ML mode falls back to the rule tier; the two modes have the same
  distribution on those fixed rows. The separate 80-scenario offline sample
  has different prediction-capable inputs and reports rule tiers
  Critical 21 / High 28 / Medium 17 / Low 14 versus `ml_asset` Critical 0 /
  High 40 / Medium 0 / Low 40, with the KEV floor raising 40 scenarios.
- **No scanning:** the application imports scanner CSV files but does not
  actively scan hosts or networks.
- **Negative ML result:** the recorded ML model did not outperform the CVSS
  baseline on the reported held-out PR-AUC or P@100/P@500 comparisons.
- **External dependencies:** uncached NVD/FIRST intelligence depends on
  network/provider availability; the three demo-cache entries are not
  authoritative current scores.
- **Deployment gaps:** login throttling is process-local and access-token
  refresh is absent.
- **Blueprint source missing:** exact Section 18 question coverage and
  verbatim P8–P12 criterion sign-off require the missing master blueprint.
