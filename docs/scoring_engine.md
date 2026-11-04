# Scoring engine

`backend/scoring_engine.py` is the canonical implementation used by manual scans and CSV imports. It evaluates KEV status, Internet exposure, asset criticality, EPSS percentile, and CVSS base score.

The expected tier for every combination of KEV, exposure, criticality, EPSS band, and CVSS band is documented in [scoring_matrix_v1.csv](scoring_matrix_v1.csv). The parameterized scoring test exercises all 320 rows in that table.

| Input | Band boundaries |
|---|---|
| EPSS percentile | Missing; Low `< 0.20`; Medium `0.20-0.95` inclusive; High `> 0.95` |
| CVSS | Low `< 4.0`; Medium `4.0-6.9`; High `7.0-8.9`; Critical `>= 9.0` |

The API score is the ordinal tier rank: Low `1`, Medium `2`, High `3`, Critical `4`. API explanations include the input values and the rationale used to select the tier.
