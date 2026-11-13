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


def select_sample(csv_path: Path) -> tuple[list[dict], int, int]:
    rng = {
        "preferred_kev": random.Random(SEED),
        "preferred_nonkev": random.Random(SEED + 1),
        "all_kev": random.Random(SEED + 2),
        "all_nonkev": random.Random(SEED + 3),
    }
    samples = {key: [] for key in rng}
    counts = {key: 0 for key in rng}
    with csv_path.open("r", encoding="utf-8-sig", newline="") as source:
        for row in csv.DictReader(source):
            cve_id = (row.get("cve_id") or "").strip().upper()
            if not cve_id:
                continue
            in_kev = _is_kev(row.get("in_kev"))
            stratum = "kev" if in_kev else "nonkev"
            is_after_validation = (row.get("published_date") or "")[:4] >= "2026"
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
            all_key = f"all_{stratum}"
            counts[all_key] += 1
            _reservoir_add(samples[all_key], counts[all_key], record, rng[all_key])
            if is_after_validation:
                preferred_key = f"preferred_{stratum}"
                counts[preferred_key] += 1
                _reservoir_add(
                    samples[preferred_key],
                    counts[preferred_key],
                    record,
                    rng[preferred_key],
                )

    selected = []
    selected_after_validation = 0
    for stratum in ("kev", "nonkev"):
        preferred_key = f"preferred_{stratum}"
        all_key = f"all_{stratum}"
        if counts[preferred_key] >= SAMPLE_PER_STRATUM:
            selected.extend(samples[preferred_key])
            selected_after_validation += len(samples[preferred_key])
        elif counts[all_key] >= SAMPLE_PER_STRATUM:
            selected.extend(samples[all_key])
        else:
            raise ValueError(
                f"CSV has fewer than {SAMPLE_PER_STRATUM} CVEs in the {stratum} stratum."
            )
    return selected, selected_after_validation, len(selected)


def run_distribution(csv_path: Path) -> str:
    sample, preferred_count, sample_count = select_sample(csv_path)
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
            f"Sample: {sample_count} real CVEs (20 KEV, 20 non-KEV); "
            f"{preferred_count} selected from published year >= 2026."
        ),
        (
            "Selection: independent reservoir sampling within KEV strata; prefer "
            "published years after the 2025 validation period, falling back per "
            "stratum to all publication years if fewer than 20 are available."
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
    args = parser.parse_args()
    print(run_distribution(args.csv_path), end="")


if __name__ == "__main__":
    main()
