"""Compare Validation 2025 training and serving features and predictions."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import numpy as np
import scipy.sparse as sp
from scipy.stats import spearmanr

from backend.ml_inference import (
    _explanation_contributions,
    _feature_row,
    _load_bundle,
)
from ml import run_val2025_comparison as comparison
from scripts import ml_tier_diagnostic as diagnostic


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIRECTORY = ROOT / "docs" / "results_offline" / "2026-11-25"
OUTPUT_JSON_PATH = OUTPUT_DIRECTORY / "ml_feature_parity.json"
OUTPUT_MARKDOWN_PATH = OUTPUT_DIRECTORY / "ml_feature_parity.md"


def _relative(path: Path) -> str:
    return path.relative_to(ROOT).as_posix()


def _prediction_metrics(
    predicted: np.ndarray, saved: np.ndarray
) -> dict[str, float | int]:
    differences = np.abs(predicted - saved)
    correlation = spearmanr(predicted, saved).statistic
    return {
        "mean_absolute_difference": float(np.mean(differences)),
        "max_absolute_difference": float(np.max(differences)),
        "spearman": float(correlation),
        "rows_over_1e-6": int(np.count_nonzero(differences > 1e-6)),
    }


def _markdown(result: dict[str, Any]) -> str:
    lines = [
        "# Validation 2025 ML feature parity",
        "",
        f"- Validation sample rows: {result['sample_rows']}",
        f"- Dataset: `{result['dataset_path']}`",
        f"- Saved predictions: `{result['saved_predictions_path']}`",
        f"- Feature columns differing: {len(result['differing_columns'])}",
        "",
        "## Feature column differences",
        "",
    ]
    if result["differing_columns"]:
        lines.extend(
            [
                "| Feature | Rows differing | Example CVE | Reference | Serving |",
                "| --- | ---: | --- | ---: | ---: |",
            ]
        )
        for column in result["differing_columns"]:
            example = column["example"]
            lines.append(
                f"| {column['name']} | {column['rows_differing']} | "
                f"{example['cve_id']} | {example['reference_value']:.8g} | "
                f"{example['serving_value']:.8g} |"
            )
    else:
        lines.append("No differing feature columns.")
    lines.extend(["", "## Saved-score comparison", ""])
    lines.extend(
        [
            "| Input | Mean absolute difference | Max absolute difference | Spearman | Rows over 1e-6 |",
            "| --- | ---: | ---: | ---: | ---: |",
        ]
    )
    for name, metrics in result["predictions"].items():
        lines.append(
            f"| {name} | {metrics['mean_absolute_difference']:.10g} | "
            f"{metrics['max_absolute_difference']:.10g} | "
            f"{metrics['spearman']:.8f} | {metrics['rows_over_1e-6']} |"
        )
    lines.extend(
        [
            "",
            "## Native XGBoost explanation",
            "",
            "- Feature contributions plus bias matched the booster margin; "
            f"absolute error: `{result['native_contribution_margin_absolute_error']:.10g}`.",
        ]
    )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    config = json.loads(comparison.CONFIG_PATH.read_text(encoding="utf-8-sig"))
    train = comparison._read_split(
        comparison.TRAIN_PATH, config["data_hashes"]["train"], "train"
    )
    validation = comparison._read_split(
        comparison.VALIDATION_PATH, config["data_hashes"]["val"], "validation"
    )
    _, reference_matrix, feature_names = comparison._build_features(
        train, validation, config
    )

    sample, _, _ = diagnostic._load_validation_sample(diagnostic.CVE_DATASET_PATH)
    validation_positions = {
        str(cve_id).strip().upper(): index
        for index, cve_id in enumerate(validation["cve_id"].astype(str))
    }
    positions = [validation_positions[row["cve_id"]] for row in sample]
    reference_sample = reference_matrix[positions]

    model, transformer, serving_features, _, inference_config = _load_bundle()
    if serving_features != feature_names:
        raise ValueError("Reference and serving feature names or order do not match.")
    serving_sparse = sp.vstack(
        [
            _feature_row(
                serving_features,
                transformer,
                inference_config,
                row["cvss_score"],
                row["cvss_vector"],
                row["cwe"],
                row["description"],
            )
            for row in sample
        ],
        format="csr",
    )
    serving_rows = serving_sparse.toarray()

    differing_columns = []
    reference_dense = reference_sample.toarray()
    for index, name in enumerate(feature_names):
        reference_values = reference_dense[:, index]
        serving_values = serving_rows[:, index]
        differing = ~np.isclose(reference_values, serving_values, rtol=0, atol=1e-7)
        if differing.any():
            first = int(np.flatnonzero(differing)[0])
            differing_columns.append(
                {
                    "name": name,
                    "rows_differing": int(np.count_nonzero(differing)),
                    "example": {
                        "cve_id": sample[first]["cve_id"],
                        "reference_value": float(reference_values[first]),
                        "serving_value": float(serving_values[first]),
                    },
                }
            )

    saved_predictions, _ = diagnostic._saved_prediction_map(
        diagnostic.SAVED_PREDICTIONS_PATH
    )
    saved = np.asarray(
        [saved_predictions[row["cve_id"]][1] for row in sample], dtype=float
    )
    dense_scores = np.asarray(model.predict_proba(serving_rows)[:, 1], dtype=float)
    sparse_scores = np.asarray(
        model.predict_proba(sp.csr_matrix(serving_rows))[:, 1], dtype=float
    )
    classifier = model.calibrated_classifiers_[0].estimator
    contribution_features = _explanation_contributions(
        classifier, serving_sparse[0], serving_features
    )
    if contribution_features is None:
        raise RuntimeError("Native XGBoost contributions could not be verified.")
    from xgboost import DMatrix

    booster = classifier.get_booster()
    contribution_matrix = DMatrix(serving_sparse[0], feature_names=serving_features)
    all_contributions = np.asarray(
        booster.predict(contribution_matrix, pred_contribs=True)[0], dtype=float
    )
    margin = float(booster.predict(contribution_matrix, output_margin=True)[0])
    contribution_margin_error = abs(float(np.sum(all_contributions)) - margin)
    if contribution_margin_error > 1e-4:
        raise ValueError("Native contributions do not equal the booster margin.")

    result = {
        "analysis": "Validation-2025-only ML feature and prediction parity check",
        "dataset_path": _relative(diagnostic.CVE_DATASET_PATH),
        "saved_predictions_path": _relative(diagnostic.SAVED_PREDICTIONS_PATH),
        "reference_features_path": _relative(comparison.VALIDATION_PATH),
        "sample_rows": len(sample),
        "feature_count": len(feature_names),
        "differing_columns": differing_columns,
        "fixture_candidates": [
            {
                "cve_id": row["cve_id"],
                "cvss_score": row["cvss_score"],
                "cvss_vector": row["cvss_vector"],
                "cwe": row["cwe"],
                "description": row["description"],
                "expected_likelihood": saved[index].item(),
                "label": row["label"],
            }
            for index, row in enumerate(sample)
            if row["label"] == 1
        ][:1]
        + [
            {
                "cve_id": row["cve_id"],
                "cvss_score": row["cvss_score"],
                "cvss_vector": row["cvss_vector"],
                "cwe": row["cwe"],
                "description": row["description"],
                "expected_likelihood": saved[index].item(),
                "label": row["label"],
            }
            for index, row in enumerate(sample)
            if row["label"] == 0
        ][:4],
        "predictions": {
            "dense serving features": _prediction_metrics(dense_scores, saved),
            "CSR serving features": _prediction_metrics(sparse_scores, saved),
        },
        "native_contribution_margin_absolute_error": contribution_margin_error,
        "rows_outside_validation_used": False,
    }
    OUTPUT_DIRECTORY.mkdir(parents=True, exist_ok=True)
    OUTPUT_JSON_PATH.write_text(
        json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n",
        encoding="utf-8",
    )
    OUTPUT_MARKDOWN_PATH.write_text(_markdown(result), encoding="utf-8")
    print(_markdown(result))
    print(f"Wrote {_relative(OUTPUT_MARKDOWN_PATH)}")
    print(f"Wrote {_relative(OUTPUT_JSON_PATH)}")


if __name__ == "__main__":
    main()
