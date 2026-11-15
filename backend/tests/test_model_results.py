import json

from backend.model_results import (
    HISTORICAL_COMPARISON_PATH,
    OFFLINE_COMPARISON_PATH,
    read_model_results,
)


def test_offline_validation_comparison_exposes_all_models_and_metrics():
    result = read_model_results()
    validation_rows = {
        row["name"]: row
        for row in result["models"]
        if row["dataset"] == "Validation 2025"
    }

    expected_models = {
        "XGBoost calibrated",
        "Logistic Regression (152 features)",
        "Logistic Regression (fixed parameters; 2026-11-14)",
        "Random Forest",
        "CVSS-only baseline",
        "EPSS baseline",
    }
    assert expected_models <= validation_rows.keys()
    assert not any(
        row["name"] == "Random Forest" and row["dataset"] == "not available"
        for row in result["models"]
    )

    for model_name in expected_models:
        row = validation_rows[model_name]
        assert all(
            row[field] is not None
            for field in ("pr_auc", "precision", "recall", "f1", "roc_auc")
        )
        assert set(row["precision_at_k"]) == {"50", "100", "500"}
        assert set(row["recall_at_k"]) == {"50", "100", "500"}

    assert "Tuned with 3-fold stratified training-only CV" in validation_rows[
        "Logistic Regression (152 features)"
    ]["note"]
    assert "Historical fixed-parameter result" in validation_rows[
        "Logistic Regression (fixed parameters; 2026-11-14)"
    ]["note"]

    current_run = json.loads(OFFLINE_COMPARISON_PATH.read_text(encoding="utf-8"))
    historical_run = json.loads(
        HISTORICAL_COMPARISON_PATH.read_text(encoding="utf-8")
    )
    historical_models = {
        model["name"]: model for model in historical_run["models"]
    }
    for model_name in (
        "XGBoost calibrated",
        "Random Forest",
        "CVSS-only baseline",
        "EPSS baseline",
    ):
        current_model = next(
            model for model in current_run["models"] if model["name"] == model_name
        )
        assert current_model["metrics"] == historical_models[model_name]["metrics"]

    assert any(
        source.replace("\\", "/").endswith(
            "docs/results_offline/2026-11-15/val2025_comparison.json"
        )
        for source in result["source_files"]
    )
    assert any(
        source.replace("\\", "/").endswith(
            "docs/results_offline/2026-11-14/val2025_comparison.json"
        )
        for source in result["source_files"]
    )
