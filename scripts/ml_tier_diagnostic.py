"""Reproduce validation-2025 ML tier parity and weighted tier distributions."""

from __future__ import annotations

import csv
import json
import math
import random
import time
from datetime import date, timedelta
from pathlib import Path
from typing import Any

import numpy as np
from scipy.stats import spearmanr

from backend.ml_inference import _feature_row, _load_bundle
from backend.rules_config import (
    CVE_DATASET_PATH,
    ML_RISK_THRESHOLDS,
    ML_THRESHOLD_PERCENTILES,
    criticality_factor,
    exposure_factor,
    ml_priority,
)

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]

SEED = 42
NEGATIVE_SAMPLE_SIZE = 2_000
TIERS = ("Critical", "High", "Medium", "Low")
PROFILES = (
    ("Internet / criticality 5", "Internet", 5),
    ("Internal / criticality 2", "Internal", 2),
    ("Internal / criticality 3", "Internal", 3),
)
INTENDED_SHARES = {"Critical": 0.01, "High": 0.09, "Medium": 0.40, "Low": 0.50}
SAVED_PREDICTIONS_PATH = (
    REPOSITORY_ROOT
    / "docs"
    / "results_offline"
    / "2026-11-14"
    / "val2025_comparison.json"
)
OUTPUT_DIRECTORY = (
    REPOSITORY_ROOT / "docs" / "results_offline" / "2026-11-24"
)
OUTPUT_JSON_PATH = OUTPUT_DIRECTORY / "ml_tier_diagnostic.json"
OUTPUT_MARKDOWN_PATH = OUTPUT_DIRECTORY / "ml_tier_diagnostic.md"


def _published_date(value: str | None) -> date:
    if not value:
        raise ValueError("A validation row has no published_date.")
    try:
        return date.fromisoformat(value[:10])
    except ValueError as exc:
        raise ValueError(f"Invalid published_date value: {value!r}") from exc


def _kev_date(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError as exc:
        raise ValueError(f"Invalid kev_date_added value: {value!r}") from exc


def _is_true(value: str | None) -> bool:
    return (value or "").strip().casefold() in {"1", "true", "yes"}


def _optional_float(value: str | None) -> float | None:
    if value is None or not value.strip():
        return None
    parsed = float(value)
    if math.isnan(parsed):
        return None
    if not math.isfinite(parsed):
        raise ValueError(f"Non-finite numeric input: {value!r}")
    return parsed


def _record(row: dict[str, str | None]) -> dict[str, Any]:
    cve_id = (row.get("cve_id") or "").strip().upper()
    if not cve_id:
        raise ValueError("A validation row has no cve_id.")
    return {
        "cve_id": cve_id,
        "published_date": row.get("published_date") or "",
        "cvss_score": _optional_float(row.get("cvss_score")),
        "cvss_vector": row.get("cvss_vector") or None,
        "cwe": row.get("cwe") or None,
        "description": row.get("description") or "",
        "label": 0,
    }


def _load_validation_sample(
    csv_path: Path,
) -> tuple[list[dict[str, Any]], int, int]:
    rng = random.Random(SEED)
    positives: list[dict[str, Any]] = []
    negative_reservoir: list[dict[str, Any]] = []
    validation_rows = 0
    validation_negatives = 0

    with csv_path.open("r", encoding="utf-8-sig", newline="") as source:
        reader = csv.DictReader(source)
        required = {
            "cve_id",
            "published_date",
            "description",
            "cvss_score",
            "cvss_vector",
            "cwe",
            "kev_date_added",
            "in_kev",
        }
        missing = required.difference(reader.fieldnames or [])
        if missing:
            raise ValueError(f"Dataset is missing required columns: {sorted(missing)}")

        for row in reader:
            published = _published_date(row.get("published_date"))
            # Do not inspect any other field unless the row is in validation-2025.
            if published < date(2025, 1, 1) or published > date(2025, 12, 31):
                continue

            validation_rows += 1
            added = _kev_date(row.get("kev_date_added"))
            label = int(
                _is_true(row.get("in_kev"))
                and added is not None
                and added <= published + timedelta(days=30)
            )
            record = _record(row)
            record["label"] = label
            if label:
                positives.append(record)
                continue

            validation_negatives += 1
            if len(negative_reservoir) < NEGATIVE_SAMPLE_SIZE:
                negative_reservoir.append(record)
            else:
                replacement = rng.randrange(validation_negatives)
                if replacement < NEGATIVE_SAMPLE_SIZE:
                    negative_reservoir[replacement] = record

    if validation_rows == 0:
        raise ValueError("No validation-2025 rows were found in the configured dataset.")
    if validation_negatives < NEGATIVE_SAMPLE_SIZE:
        raise ValueError(
            f"Found {validation_negatives} validation negatives; "
            f"{NEGATIVE_SAMPLE_SIZE} are required."
        )
    if not positives:
        raise ValueError("No validation-2025 positives were found.")

    sample = positives + negative_reservoir
    sample.sort(key=lambda item: item["cve_id"])
    return sample, validation_rows, validation_negatives


def _saved_prediction_map(
    path: Path,
) -> tuple[dict[str, tuple[int, float]], str | None]:
    data = json.loads(path.read_text(encoding="utf-8"))
    predictions = data.get("validation_predictions")
    if not isinstance(predictions, list):
        raise ValueError("Saved comparison has no validation_predictions list.")

    metadata = data.get("metadata", {})
    split = metadata.get("split", {})
    validation_range = split.get("validation", "")
    if "2025-01-01" not in validation_range or "2025-12-31" not in validation_range:
        raise ValueError("Saved comparison metadata does not identify validation-2025.")

    saved: dict[str, tuple[int, float]] = {}
    for prediction in predictions:
        cve_id = str(prediction.get("cve_id", "")).strip().upper()
        scores = prediction.get("scores", {})
        score = scores.get("XGBoost calibrated")
        if cve_id and score is not None:
            if cve_id in saved:
                raise ValueError(f"Duplicate saved validation prediction for {cve_id}.")
            saved[cve_id] = (int(prediction["label"]), float(score))
    hashes = metadata.get("hashes_sha256", {})
    return saved, hashes.get("frozen_xgboost_model")


def _compute_likelihoods(
    sample: list[dict[str, Any]],
) -> tuple[np.ndarray, str]:
    model, transformer, features, model_version, config = _load_bundle()
    matrices = [
        _feature_row(
            features,
            transformer,
            config,
            record["cvss_score"],
            record["cvss_vector"],
            record["cwe"],
            record["description"],
        )
        for record in sample
    ]
    matrix = np.concatenate(matrices, axis=0)
    likelihoods = np.asarray(model.predict_proba(matrix)[:, 1], dtype=float)
    if likelihoods.shape != (len(sample),) or not np.isfinite(likelihoods).all():
        raise ValueError("Frozen model returned invalid validation likelihoods.")
    return likelihoods, model_version


def _parity(
    sample: list[dict[str, Any]],
    likelihoods: np.ndarray,
    saved_predictions: dict[str, tuple[int, float]],
) -> dict[str, Any]:
    pairs = [
        (record, likelihood, saved_predictions[record["cve_id"]])
        for record, likelihood in zip(sample, likelihoods, strict=True)
        if record["cve_id"] in saved_predictions
    ]
    differences = [
        abs(float(likelihood) - saved_score)
        for _, likelihood, (_, saved_score) in pairs
    ]
    label_mismatches = sum(
        record["label"] != saved_label
        for record, _, (saved_label, _) in pairs
    )
    result: dict[str, Any] = {
        "sample_rows": len(sample),
        "matched_rows": len(pairs),
        "unmatched_rows": len(sample) - len(pairs),
        "label_mismatches": label_mismatches,
        "mean_absolute_difference": None,
        "max_absolute_difference": None,
        "rows_differing_by_more_than_1e-6": None,
        "spearman_correlation": None,
    }
    if not pairs:
        return result

    actual = np.asarray([float(likelihood) for _, likelihood, _ in pairs])
    saved = np.asarray([saved_score for _, _, (_, saved_score) in pairs])
    correlation = float(spearmanr(actual, saved).statistic)
    result.update(
        {
            "mean_absolute_difference": float(np.mean(differences)),
            "max_absolute_difference": float(np.max(differences)),
            "rows_differing_by_more_than_1e-6": int(
                np.count_nonzero(np.asarray(differences) > 1e-6)
            ),
            "spearman_correlation": correlation if math.isfinite(correlation) else None,
        }
    )
    return result


def _profile_results(
    sample: list[dict[str, Any]],
    likelihoods: np.ndarray,
    validation_negatives: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    negative_weight = validation_negatives / NEGATIVE_SAMPLE_SIZE
    profiles: dict[str, Any] = {}
    combined_tier_rows = {tier: {"weighted_rows": 0.0, "positives": 0} for tier in TIERS}
    combined_total_rows = 0.0
    combined_positives = 0

    for profile_name, exposure, criticality in PROFILES:
        tier_rows = {tier: {"weighted_rows": 0.0, "positives": 0} for tier in TIERS}
        total_weight = 0.0
        positive_total = 0
        for record, likelihood in zip(sample, likelihoods, strict=True):
            risk = (
                float(likelihood)
                * exposure_factor(exposure)
                * criticality_factor(criticality)
            )
            tier = ml_priority(risk)
            row_weight = 1.0 if record["label"] else negative_weight
            tier_rows[tier]["weighted_rows"] += row_weight
            tier_rows[tier]["positives"] += record["label"]
            total_weight += row_weight
            positive_total += record["label"]

        tier_summary = {}
        for tier in TIERS:
            weighted_rows = tier_rows[tier]["weighted_rows"]
            positives = tier_rows[tier]["positives"]
            tier_summary[tier] = {
                "estimated_rows": weighted_rows,
                "share": weighted_rows / total_weight,
                "intended_share": INTENDED_SHARES[tier],
                "share_minus_intended_percentage_points": (
                    (weighted_rows / total_weight) - INTENDED_SHARES[tier]
                )
                * 100,
                "positive_rows": positives,
                "positive_share": positives / positive_total,
                "weighted_precision": positives / weighted_rows if weighted_rows else None,
            }
            combined_tier_rows[tier]["weighted_rows"] += weighted_rows
            combined_tier_rows[tier]["positives"] += positives

        profiles[profile_name] = {
            "exposure": exposure,
            "criticality": criticality,
            "negative_sample_weight": negative_weight,
            "estimated_total_rows": total_weight,
            "positive_rows": positive_total,
            "tiers": tier_summary,
        }
        combined_total_rows += total_weight
        combined_positives += positive_total

    combined = {
        "profiles_included": [name for name, _, _ in PROFILES],
        "estimated_total_scenarios": combined_total_rows,
        "positive_scenarios": combined_positives,
        "tiers": {},
    }
    for tier in TIERS:
        weighted_rows = combined_tier_rows[tier]["weighted_rows"]
        positives = combined_tier_rows[tier]["positives"]
        combined["tiers"][tier] = {
            "share": weighted_rows / combined_total_rows,
            "intended_share_reference": INTENDED_SHARES[tier],
            "positive_scenarios": positives,
            "positive_share": positives / combined_positives,
            "weighted_precision": positives / weighted_rows if weighted_rows else None,
        }
    return profiles, combined


def _pct(value: float | None) -> str:
    return "not available" if value is None else f"{value * 100:.4f}%"


def _number(value: float | None) -> str:
    return "not available" if value is None else f"{value:.12g}"


def _markdown_report(data: dict[str, Any]) -> str:
    parity = data["parity"]
    lines = [
        "# Validation-2025 ML tier diagnostic",
        "",
        f"- Dataset: `{data['dataset_path']}`",
        "- Included rows: published 2025-01-01 through 2025-12-31 only.",
        "- Rows published outside 2025 were routed using `published_date` only; no other fields from those rows were inspected or used.",
        f"- Validation rows: {data['validation_rows']}; positives: {data['validation_positives']}; negatives: {data['validation_negatives']}.",
        f"- Sample: all {data['validation_positives']} positives plus {data['negative_sample_size']} randomly selected negatives (seed {SEED}); negative weight: {data['negative_weight']:.8f}.",
        f"- Frozen model: `{data['model_version']}`.",
        f"- Runtime: {data['runtime_seconds']:.3f} seconds.",
        "",
        "## A. Threshold provenance",
        "",
        "- `Decision_Log.md` D-023 records thresholds from Validation 2025 (48,152 CVEs; 481,520 risk values), using all ten exposure/criticality combinations: Internet/Internal crossed with criticality 1-5.",
        "- The recorded formula is `ml_risk = likelihood × exposure_factor × criticality_factor`; thresholds are P99 Critical, P90 High, and P50 Medium, with Low below P50.",
        f"- Runtime constants: Critical `{data['thresholds']['Critical']:.15g}`, High `{data['thresholds']['High']:.15g}`, Medium `{data['thresholds']['Medium']:.15g}`; percentile settings: `{json.dumps(data['threshold_percentiles'], sort_keys=True)}`.",
        "- Threshold-generation script: **unverified**. Repository search found the recorded method in D-023 and runtime constants, but no reproducible script that generated the three values. `scripts/priority_distribution.py` is a distinct 40-CVE sample diagnostic, not the threshold-generation script.",
        "",
        "## B. Prediction parity with saved Validation 2025 predictions",
        "",
        f"- Matched by CVE ID: {parity['matched_rows']} of {parity['sample_rows']} sampled rows; unmatched: {parity['unmatched_rows']}; label mismatches: {parity['label_mismatches']}.",
        f"- Mean absolute difference: {_number(parity['mean_absolute_difference'])}.",
        f"- Maximum absolute difference: {_number(parity['max_absolute_difference'])}.",
        f"- Rows differing by more than 1e-6: {parity['rows_differing_by_more_than_1e-6'] if parity['rows_differing_by_more_than_1e-6'] is not None else 'not available'}.",
        f"- Spearman correlation: {_number(parity['spearman_correlation'])}.",
        "- Runtime path: `backend.ml_inference._feature_row` plus the frozen model's `predict_proba`; SHAP explanations were bypassed. Saved scores are the `XGBoost calibrated` entries from `docs/results_offline/2026-11-14/val2025_comparison.json`.",
        f"- Frozen XGBoost SHA-256 recorded by the saved comparison: `{data['saved_model_sha256'] or 'unavailable'}`; runtime artifact hash prefix: `{data['model_version'].rsplit(':', 1)[-1]}`.",
        "",
        "## C. Weighted tier distribution",
        "",
        "- Table share estimates use all positives and weight each sampled negative by validation negatives / 2,000. Positive distribution is the share of all validation positives. Weighted precision is weighted positives / weighted rows within the raw `ml_priority` tier; no KEV floor is applied.",
        "- The 1/9/40/50 target is the documented pooled target across ten contexts. Individual profile rows are shown for diagnosis and need not independently meet the pooled target.",
        "",
        "| Profile | Tier | Estimated share | Intended reference | Difference (pp) | Positive rows (share) | Weighted precision |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]
    for profile_name, profile in data["profiles"].items():
        for tier in TIERS:
            result = profile["tiers"][tier]
            lines.append(
                f"| {profile_name} | {tier} | {_pct(result['share'])} | "
                f"{_pct(result['intended_share'])} | "
                f"{result['share_minus_intended_percentage_points']:+.4f} | "
                f"{result['positive_rows']} ({_pct(result['positive_share'])}) | "
                f"{_pct(result['weighted_precision'])} |"
            )
    lines.extend(
        [
            "",
            "### Combined three-profile reference",
            "",
            "- This combines only the three requested profiles, not all ten contexts used in the documented threshold derivation.",
            "",
            "| Tier | Estimated share | Intended reference | Positive scenarios (share) | Weighted precision |",
            "|---|---:|---:|---:|---:|",
        ]
    )
    for tier in TIERS:
        result = data["combined_three_profiles"]["tiers"][tier]
        lines.append(
            f"| {tier} | {_pct(result['share'])} | "
            f"{_pct(result['intended_share_reference'])} | "
            f"{result['positive_scenarios']} ({_pct(result['positive_share'])}) | "
            f"{_pct(result['weighted_precision'])} |"
        )
    saved_reference = data["saved_prediction_tier_reference"]
    lines.extend(
        [
            "",
            "### Saved-prediction reference on the same sampled CVE IDs",
            "",
            "- This applies the same risk formula and thresholds to the saved Validation 2025 scores, not to the runtime inference output. It is a useful parity reference only; the reported requested distribution above is from `backend.ml_inference`.",
        ]
    )
    if saved_reference is None:
        lines.append("- Not available because one or more sampled CVE IDs had no saved prediction.")
    else:
        lines.extend(
            [
                "",
                "| Profile | Tier | Saved-score estimated share | Intended reference |",
                "|---|---|---:|---:|",
            ]
        )
        for profile_name, profile in saved_reference["profiles"].items():
            for tier in TIERS:
                lines.append(
                    f"| {profile_name} | {tier} | "
                    f"{_pct(profile['tiers'][tier]['share'])} | "
                    f"{_pct(profile['tiers'][tier]['intended_share'])} |"
                )
        lines.extend(
            [
                "",
                "#### Combined saved-score three-profile reference",
                "",
                "| Tier | Saved-score estimated share | Intended reference |",
                "|---|---:|---:|",
            ]
        )
        for tier in TIERS:
            result = saved_reference["combined_three_profiles"]["tiers"][tier]
            lines.append(
                f"| {tier} | {_pct(result['share'])} | "
                f"{_pct(result['intended_share_reference'])} |"
            )

    lines.extend(["", "## D. Verdict", ""])
    if (
        parity["matched_rows"] == parity["sample_rows"]
        and parity["label_mismatches"] == 0
        and parity["max_absolute_difference"] is not None
        and parity["max_absolute_difference"] <= 1e-6
        and parity["spearman_correlation"] is not None
        and parity["spearman_correlation"] >= 0.999999
    ):
        lines.append(
            "- Evidence supports explanation (1): inference reproduces the saved Validation 2025 likelihoods within 1e-6 on the sampled rows, while D-023 documents thresholds derived with the same risk formula and all ten supported asset contexts. That makes a material train/serve mismatch on this validation sample unlikely."
        )
        lines.append(
            "- The 80-scenario sample's 2026+ composition/distribution shift is a plausible explanation for all raw model tiers being Low, but it is **unverified** here: this diagnostic did not read or calculate from those sample rows."
        )
    elif parity["matched_rows"] == 0:
        lines.append(
            "- No explanation is established: saved validation predictions could not be matched by CVE ID, so inference parity is **unverified**. Threshold-generation implementation is also **unverified**."
        )
    else:
        lines.append(
            "- Evidence supports explanation (2): inference does not reproduce saved Validation 2025 predictions within the 1e-6 tolerance. With the saved and runtime model hashes matching, the most likely area is the train/serve feature path: `backend/ml_inference.py` `_feature_row`'s TF-IDF transform/input (lines 194-198) versus the separately fitted vectorizer in `ml/run_val2025_comparison.py` `_build_features` (lines 160-171). `_load_bundle` checks the TF-IDF vocabulary hash (lines 110-116), but not its IDF values. Vector parsing (lines 173-179), CWE encoding (lines 181-192), missing-value handling, and dense feature ordering (line 198) also warrant comparison. The prediction metrics alone do not isolate the cause; the specific feature mismatch is **unverified**."
        )
        lines.append(
            "- The recorded threshold formula and ten-profile method agree with the documented runtime formula; no evidence here supports explanation (3). The generating script remains **unverified**."
        )

    lines.extend(
        [
            "",
            "## Scope and reproducibility",
            "",
            f"- Run `python -m scripts.ml_tier_diagnostic` from the repository root with the dataset available at `CVE_DATASET_PATH` (default: `{data['dataset_path']}`).",
            "- The script uses a streaming reservoir sample with seed 42, then calls the inference feature builder and frozen model directly so SHAP is not run.",
            "- It does not import or execute `scripts/priority_distribution.py`, modify backend code/configuration, or access the securevision SQLite databases.",
            "",
        ]
    )
    return "\n".join(lines)


def main() -> None:
    started = time.perf_counter()
    sample, validation_rows, validation_negatives = _load_validation_sample(
        CVE_DATASET_PATH
    )
    likelihoods, model_version = _compute_likelihoods(sample)
    saved_predictions, saved_model_sha256 = _saved_prediction_map(
        SAVED_PREDICTIONS_PATH
    )
    parity = _parity(sample, likelihoods, saved_predictions)
    profiles, combined = _profile_results(
        sample, likelihoods, validation_negatives
    )
    saved_reference = None
    if all(record["cve_id"] in saved_predictions for record in sample):
        saved_likelihoods = np.asarray(
            [saved_predictions[record["cve_id"]][1] for record in sample],
            dtype=float,
        )
        saved_profiles, saved_combined = _profile_results(
            sample, saved_likelihoods, validation_negatives
        )
        saved_reference = {
            "profiles": saved_profiles,
            "combined_three_profiles": saved_combined,
        }
    validation_positives = validation_rows - validation_negatives

    result: dict[str, Any] = {
        "analysis": "Validation-only ML tier parity and distribution diagnostic",
        "dataset_path": str(CVE_DATASET_PATH),
        "validation_date_range": ["2025-01-01", "2025-12-31"],
        "validation_rows": validation_rows,
        "validation_positives": validation_positives,
        "validation_negatives": validation_negatives,
        "seed": SEED,
        "negative_sample_size": NEGATIVE_SAMPLE_SIZE,
        "sample_rows": len(sample),
        "negative_weight": validation_negatives / NEGATIVE_SAMPLE_SIZE,
        "model_version": model_version,
        "saved_model_sha256": saved_model_sha256,
        "saved_predictions_path": str(SAVED_PREDICTIONS_PATH),
        "parity": parity,
        "saved_prediction_tier_reference": saved_reference,
        "thresholds": dict(ML_RISK_THRESHOLDS),
        "threshold_percentiles": dict(ML_THRESHOLD_PERCENTILES),
        "threshold_provenance": {
            "documented_source": "Decision_Log.md D-023",
            "generating_script": "unverified",
            "documented_split": "2025-01-01 through 2025-12-31",
            "documented_contexts": [
                f"{exposure} / criticality {criticality}"
                for exposure in ("Internet", "Internal")
                for criticality in range(1, 6)
            ],
            "formula": "likelihood * exposure_factor * criticality_factor",
            "intended_shares": INTENDED_SHARES,
        },
        "profiles": profiles,
        "combined_three_profiles": combined,
        "sample_used_from_priority_distribution": False,
        "rows_outside_validation_used": False,
    }
    result["runtime_seconds"] = time.perf_counter() - started

    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    OUTPUT_JSON_PATH.write_text(
        json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    OUTPUT_MARKDOWN_PATH.write_text(_markdown_report(result), encoding="utf-8")

    print(f"Validation rows: {validation_rows}")
    print(
        f"Validation positives/negatives: "
        f"{validation_positives}/{validation_negatives}"
    )
    print(f"Sample rows: {len(sample)} (seed {SEED})")
    print(
        f"Parity: matched {parity['matched_rows']}/{parity['sample_rows']}; "
        f"mean_abs={_number(parity['mean_absolute_difference'])}; "
        f"max_abs={_number(parity['max_absolute_difference'])}; "
        f">1e-6={parity['rows_differing_by_more_than_1e-6']}; "
        f"Spearman={_number(parity['spearman_correlation'])}"
    )
    for profile_name, profile in profiles.items():
        shares = ", ".join(
            f"{tier}={_pct(profile['tiers'][tier]['share'])}" for tier in TIERS
        )
        print(f"{profile_name}: {shares}")
    print(f"Runtime: {result['runtime_seconds']:.3f} seconds")
    print(f"Wrote {OUTPUT_MARKDOWN_PATH}")
    print(f"Wrote {OUTPUT_JSON_PATH}")


if __name__ == "__main__":
    main()
