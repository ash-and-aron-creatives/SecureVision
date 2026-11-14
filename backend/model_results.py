import json
import re
from pathlib import Path
from typing import Any

from backend.rules_config import (
    DECISION_LOG_PATH,
    MODEL_RESULTS_DIRECTORY,
    REPOSITORY_ROOT,
)


_METRIC_PATTERNS = {
    "xgboost_test": r"XGBoost Calibrated Model \| Test PR-AUC:\s*([\d.]+)",
    "cvss_test": r"CVSS Baseline \(100 tie-breaks\) \| Test PR-AUC:\s*([\d.]+) \+/- ([\d.]+)",
    "epss_test": r"EPSS Hindsight Snapshot\s+\| Test PR-AUC:\s*([\d.]+)",
    "xgboost_validation": r"\[REFERENCE LINE - VAL 2025\] PR-AUC:\s*([\d.]+)",
    "logreg_cvss_validation": r"LogReg 1_CVSS Mean Val PR:\s*([\d.]+) \+/- ([\d.]+)",
    "logreg_text_validation": r"LogReg 4_Text_Masked Mean Val PR:\s*([\d.]+) \+/- ([\d.]+)",
    "xgboost_cvss_validation": r"XGB 1_CVSS Mean Val PR:\s*([\d.]+) \+/- ([\d.]+)",
    "xgboost_text_validation": r"XGB 4_Text_Masked Mean Val PR:\s*([\d.]+) \+/- ([\d.]+)",
}

OFFLINE_COMPARISON_PATH = (
    REPOSITORY_ROOT
    / "docs"
    / "results_offline"
    / "2026-11-14"
    / "val2025_comparison.json"
)


def _find_values(pattern: str, text: str) -> tuple[float | None, ...]:
    match = re.search(pattern, text)
    if not match:
        return (None,)
    return tuple(float(value) for value in match.groups())


def _top_k_metrics(text: str, section: str) -> tuple[dict[str, float | None], dict[str, float | None]]:
    start = text.find(section)
    if start < 0:
        return {}, {}
    section_text = text[start:]
    next_section = re.search(r"\n---\s+\d+[.:]", section_text)
    if next_section:
        section_text = section_text[:next_section.start()]
    precision: dict[str, float | None] = {}
    recall: dict[str, float | None] = {}
    for k in (50, 100, 500):
        match = re.search(
            rf"P@{k}\s*:\s*([\d.]+)\s*(?:\(\s*|\|\s*)R@{k}\s*:\s*([\d.]+)\s*\)?",
            section_text,
        )
        if match:
            precision[str(k)] = float(match.group(1))
            recall[str(k)] = float(match.group(2))
    return precision, recall


def _row(
    name: str,
    dataset: str,
    pr_auc: float | None = None,
    pr_auc_stddev: float | None = None,
    precision_at_k: dict[str, float | None] | None = None,
    recall_at_k: dict[str, float | None] | None = None,
    precision: float | None = None,
    recall: float | None = None,
    f1: float | None = None,
    roc_auc: float | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "dataset": dataset,
        "pr_auc": pr_auc,
        "pr_auc_stddev": pr_auc_stddev,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "roc_auc": roc_auc,
        "precision_at_k": precision_at_k or {},
        "recall_at_k": recall_at_k or {},
        "note": note,
    }


def _offline_row(result: dict[str, Any]) -> dict[str, Any]:
    metrics = result["metrics"]
    threshold = result["threshold"]
    note = f"Validation 2025; training-selected F1 threshold={threshold:.6g}."
    if result.get("feature_count"):
        note = f"{note} {result['feature_count']} model features."
    if result.get("note"):
        note = f"{note} {result['note']}"
    if result.get("calibration_note"):
        note = f"{note} Frozen calibration: {result['calibration_note']}."
    return _row(
        result["name"],
        "Validation 2025",
        pr_auc=metrics["pr_auc"],
        pr_auc_stddev=metrics["pr_auc_stddev"],
        precision=metrics["precision"],
        recall=metrics["recall"],
        f1=metrics["f1"],
        roc_auc=metrics["roc_auc"],
        precision_at_k=metrics["precision_at_k"],
        recall_at_k=metrics["recall_at_k"],
        note=note,
    )


def _decision_conclusion() -> str:
    if not DECISION_LOG_PATH.is_file():
        return "not available"
    contents = DECISION_LOG_PATH.read_text(encoding="utf-8-sig")
    decision = re.search(
        r"### D-033:[\s\S]*?(?=### D-|\Z)",
        contents,
    )
    if not decision:
        return "not available"
    conclusion = re.search(r"\* \*\*Conclusion:\*\*\s*(.+)", decision.group(0))
    return conclusion.group(1).strip() if conclusion else "not available"


def read_model_results() -> dict[str, Any]:
    p5_path = MODEL_RESULTS_DIRECTORY / "p5" / "p5_console.log"
    pipeline_path = MODEL_RESULTS_DIRECTORY / "pipeline_output.txt"
    p5 = p5_path.read_text(encoding="utf-8-sig") if p5_path.is_file() else ""
    pipeline = pipeline_path.read_text(encoding="utf-8-sig") if pipeline_path.is_file() else ""
    offline_results = (
        json.loads(OFFLINE_COMPARISON_PATH.read_text(encoding="utf-8-sig"))
        if OFFLINE_COMPARISON_PATH.is_file()
        else None
    )
    offline_by_name = (
        {result["name"]: result for result in offline_results["models"]}
        if offline_results is not None
        else {}
    )

    xgb_test, = _find_values(_METRIC_PATTERNS["xgboost_test"], p5)
    cvss_test_values = _find_values(_METRIC_PATTERNS["cvss_test"], p5)
    epss_test, = _find_values(_METRIC_PATTERNS["epss_test"], p5)
    xgb_validation, = _find_values(_METRIC_PATTERNS["xgboost_validation"], p5)

    xgb_precision, xgb_recall = _top_k_metrics(p5, "XGBoost Calibrated Model")
    cvss_precision, cvss_recall = _top_k_metrics(p5, "CVSS Baseline (100 tie-breaks)")
    epss_precision, epss_recall = _top_k_metrics(p5, "EPSS Hindsight Snapshot")
    val_precision, val_recall = _top_k_metrics(p5, "[REFERENCE LINE - VAL 2025]")

    logreg_cvss_values = _find_values(_METRIC_PATTERNS["logreg_cvss_validation"], pipeline)
    logreg_text_values = _find_values(_METRIC_PATTERNS["logreg_text_validation"], pipeline)
    xgb_cvss_values = _find_values(_METRIC_PATTERNS["xgboost_cvss_validation"], pipeline)
    xgb_text_values = _find_values(_METRIC_PATTERNS["xgboost_text_validation"], pipeline)

    models = [
        _row("XGBoost calibrated", "Test 2026", xgb_test, precision_at_k=xgb_precision, recall_at_k=xgb_recall),
        _row(
            "CVSS baseline",
            "Test 2026",
            cvss_test_values[0],
            cvss_test_values[1] if len(cvss_test_values) > 1 else None,
            cvss_precision,
            cvss_recall,
        ),
        _row(
            "EPSS hindsight baseline",
            "Test 2026 (hindsight)",
            epss_test,
            precision_at_k=epss_precision,
            recall_at_k=epss_recall,
            note="Hindsight snapshot; not a like-for-like prospective baseline.",
        ),
        _offline_row(offline_by_name["XGBoost calibrated"])
        if "XGBoost calibrated" in offline_by_name
        else _row(
            "XGBoost calibrated",
            "Validation 2025",
            xgb_validation,
            precision_at_k=val_precision,
            recall_at_k=val_recall,
            note="Recorded validation reference line; this is not a test result.",
        ),
        _row(
            "Logistic Regression (CVSS-only)",
            "Validation 2025",
            *logreg_cvss_values,
            note="No corresponding test-split result is recorded.",
        ),
        _row(
            "Logistic Regression (text-masked)",
            "Validation 2025",
            *logreg_text_values,
            note="No corresponding test-split result is recorded.",
        ),
        _row(
            "XGBoost (CVSS-only ablation)",
            "Validation 2025",
            *xgb_cvss_values,
            note="Validation ablation; not a separate test result.",
        ),
        _row(
            "XGBoost (text-masked ablation)",
            "Validation 2025",
            *xgb_text_values,
            note="Validation ablation; not a separate test result.",
        ),
    ]
    for model_name in (
        "Logistic Regression (152 features)",
        "Random Forest",
        "CVSS-only baseline",
        "EPSS baseline",
    ):
        if model_name in offline_by_name:
            models.append(_offline_row(offline_by_name[model_name]))

    return {
        "models": models,
        "conclusion": _decision_conclusion(),
        "source_files": [
            str(path.relative_to(MODEL_RESULTS_DIRECTORY.parent.parent))
            for path in (
                pipeline_path,
                p5_path,
                OFFLINE_COMPARISON_PATH,
                DECISION_LOG_PATH,
            )
            if path.is_file()
        ],
    }
