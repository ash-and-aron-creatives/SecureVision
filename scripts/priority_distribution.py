import argparse
import csv
import random
from pathlib import Path

from backend import rules_config
from backend.rules_config import CVE_DATASET_PATH
from backend.scoring_engine import calculate_priority, resolve_final_priority
from backend.ml_inference import predict_exploit_likelihood


SEED = 42
SAMPLE_PER_STRATUM = 20
TIERS = ("Critical", "High", "Medium", "Low")
ASSETS = (
    ("Internet-facing criticality 5", "Internet", 5),
    ("Internal criticality 2", "Internal", 2),
)


def _number(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _is_kev(value: str | None) -> bool:
    return (value or "").strip().casefold() in {"1", "true"}


def _reservoir_add(
    sample: list[dict],
    count: int,
    record: dict,
    rng: random.Random,
) -> None:
    if len(sample) < SAMPLE_PER_STRATUM:
        sample.append(record)
        return
    index = rng.randrange(count)
    if index < SAMPLE_PER_STRATUM:
        sample[index] = record


def select_sample(
    csv_path: Path,
    sample_year: int = 2025,
    allow_test_period: bool = False,
) -> tuple[list[dict], int, int]:
    if sample_year >= 2026 and not allow_test_period:
        raise ValueError(
            "Sampling 2026 or later requires the explicit --allow-test-period flag."
        )
    period_start = f"{sample_year}-01-01"
    period_end = f"{sample_year}-12-31"
    rng = {
        "kev": random.Random(SEED),
        "nonkev": random.Random(SEED + 1),
    }
    samples = {key: [] for key in rng}
    counts = {key: 0 for key in rng}
    with csv_path.open("r", encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            cve_id = (row.get("cve_id") or "").strip().upper()
            if not cve_id:
                continue
            published_date = (row.get("published_date") or "")[:10]
            if not period_start <= published_date <= period_end:
                continue
            in_kev = _is_kev(row.get("in_kev"))
            stratum = "kev" if in_kev else "nonkev"
            record = {
                "cve_id": cve_id,
                "published_date": row.get("published_date") or "",
                "description": row.get("description") or "",
                "cvss_score": _number(row.get("cvss_score")),
                "cvss_vector": row.get("cvss_vector") or None,
                "cwe": row.get("cwe") or None,
                "percentile": _number(row.get("percentile")),
                "in_kev": in_kev,
            }
            counts[stratum] += 1
            _reservoir_add(samples[stratum], counts[stratum], record, rng[stratum])

    selected = []
    for stratum in ("kev", "nonkev"):
        if counts[stratum] < SAMPLE_PER_STRATUM:
            raise ValueError(
                f"CSV has fewer than {SAMPLE_PER_STRATUM} {stratum} CVEs published "
                f"from {period_start} through {period_end}."
            )
        selected.extend(samples[stratum])
    return selected, sum(counts.values()), len(selected)


def run_distribution(
    csv_path: Path,
    sample_year: int = 2025,
    allow_test_period: bool = False,
) -> str:
    sample, eligible_count, sample_count = select_sample(
        csv_path,
        sample_year=sample_year,
        allow_test_period=allow_test_period,
    )
    tier_counts = {
        mode: {tier: 0 for tier in TIERS}
        for mode in ("deterministic", "ml_asset")
    }
    differing_tiers = 0
    floor_raised = 0
    previous_mode = rules_config.PRIORITY_MODE
    try:
        rules_config.PRIORITY_MODE = "ml_asset"
        for cve in sample:
            for _, exposure, criticality in ASSETS:
                rule_result = calculate_priority(
                    cve["in_kev"],
                    exposure.casefold() == "internet",
                    criticality,
                    cve["percentile"],
                    cve["cvss_score"],
                )
                rule_tier = rule_result["tier"]
                assessment = predict_exploit_likelihood(
                    cvss_score=cve["cvss_score"],
                    cvss_vector=cve["cvss_vector"],
                    cwe=cve["cwe"],
                    description=cve["description"],
                    exposure=exposure,
                    criticality=criticality,
                )
                ml_tier, source = resolve_final_priority(
                    rule_tier, assessment["priority"], cve["in_kev"]
                )
                tier_counts["deterministic"][rule_tier] += 1
                tier_counts["ml_asset"][ml_tier] += 1
                differing_tiers += ml_tier != rule_tier
                floor_raised += source == "ml+kev_floor"
    finally:
        rules_config.PRIORITY_MODE = previous_mode

    lines = [
        f"Seed: {SEED}",
        (
            f"Sample: {sample_count} real CVEs (20 KEV, 20 non-KEV) published in "
            f"{sample_year}; {eligible_count} eligible records."
        ),
        (
            f"Selection: independent reservoir sampling within KEV strata, restricted "
            f"to publication dates {sample_year}-01-01 through {sample_year}-12-31."
        ),
        "Hypothetical assets: Internet-facing criticality 5; Internal criticality 2.",
        "Scenarios: 40 CVEs x 2 assets = 80.",
        "",
        "Mode          Critical  High  Medium  Low",
    ]
    for mode in ("deterministic", "ml_asset"):
        counts = tier_counts[mode]
        lines.append(
            f"{mode:<14}{counts['Critical']:>8}{counts['High']:>6}"
            f"{counts['Medium']:>8}{counts['Low']:>5}"
        )
    lines.extend(
        [
            "",
            (
                "Tiers differing between rule matrix and ml_asset: "
                f"{differing_tiers} of 80 scenarios."
            ),
            f"Raised by known-exploited floor: {floor_raised} of 80 scenarios.",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Compare final-tier distributions on a reproducible real-CVE sample."
    )
    parser.add_argument("--csv-path", type=Path, default=CVE_DATASET_PATH)
    parser.add_argument("--sample-year", type=int, default=2025)
    parser.add_argument("--allow-test-period", action="store_true")
    args = parser.parse_args()
    try:
        result = run_distribution(
            args.csv_path,
            sample_year=args.sample_year,
            allow_test_period=args.allow_test_period,
        )
    except ValueError as exc:
        parser.error(str(exc))
    print(result, end="")


if __name__ == "__main__":
    main()
