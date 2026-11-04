import csv
from pathlib import Path

import pytest

from backend.scoring_engine import TIER_SCORES, calculate_priority


EXPECTED_TIERS_PATH = Path(__file__).parents[2] / "docs" / "scoring_matrix_v1.csv"
EPSS_BAND_VALUES = {
    "High (>0.95)": 0.96,
    "Med (0.2-0.95)": 0.5,
    "Low (<0.2)": 0.1,
    "Missing": None,
}
CVSS_BAND_VALUES = {
    "Crit (9.0+)": 9.0,
    "High (7.0-8.9)": 7.0,
    "Med (4.0-6.9)": 4.0,
    "Low (0.0-3.9)": 0.0,
}


def _documented_matrix_cases():
    with EXPECTED_TIERS_PATH.open(newline="", encoding="utf-8") as matrix_file:
        rows = list(csv.DictReader(matrix_file))

    return [
        pytest.param(
            row["in_kev"] == "True",
            row["internet"] == "True",
            int(row["crit"]),
            EPSS_BAND_VALUES[row["epss"]],
            CVSS_BAND_VALUES[row["cvss"]],
            row["priority"],
            id=(
                f"kev-{row['in_kev']}-internet-{row['internet']}-crit-{row['crit']}"
                f"-epss-{row['epss']}-cvss-{row['cvss']}"
            ),
        )
        for row in rows
    ]


@pytest.mark.parametrize(
    "in_kev,internet_facing,criticality,epss_percentile,cvss_score,expected_tier",
    _documented_matrix_cases(),
)
def test_scoring_matches_documented_expected_tier_table(
    in_kev,
    internet_facing,
    criticality,
    epss_percentile,
    cvss_score,
    expected_tier,
):
    result = calculate_priority(
        in_kev, internet_facing, criticality, epss_percentile, cvss_score
    )

    assert result["tier"] == expected_tier
    assert result["score"] == TIER_SCORES[expected_tier]
    assert result["explanation"]["inputs"] == {
        "in_kev": in_kev,
        "internet_facing": internet_facing,
        "criticality": criticality,
        "epss_percentile": epss_percentile,
        "cvss_score": cvss_score,
    }
    assert result["explanation"]["summary"]
    assert result["explanation"]["rationale"]


@pytest.mark.parametrize(
    "epss_percentile,expected_tier",
    [
        (None, "Low"),
        (0.199999, "Low"),
        (0.2, "Medium"),
        (0.95, "Medium"),
        (0.950001, "High"),
    ],
)
def test_scoring_epss_boundaries(epss_percentile, expected_tier):
    result = calculate_priority(False, False, 3, epss_percentile, 0.0)
    assert result["tier"] == expected_tier


@pytest.mark.parametrize(
    "cvss_score,expected_tier",
    [
        (0.0, "Low"),
        (3.9, "Low"),
        (4.0, "Low"),
        (6.9, "Low"),
        (7.0, "Medium"),
        (8.9, "Medium"),
        (9.0, "Medium"),
    ],
)
def test_scoring_cvss_boundaries(cvss_score, expected_tier):
    result = calculate_priority(False, False, 3, 0.0, cvss_score)
    assert result["tier"] == expected_tier
