"""Render static SVG charts from the saved Validation 2025 comparison JSON."""

from __future__ import annotations

import html
import hashlib
import json
import math
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
RESULT_DIRECTORY = ROOT / "docs" / "results_offline" / "2026-11-14"
RESULT_PATH = RESULT_DIRECTORY / "val2025_comparison.json"
REPORT_PATH = RESULT_DIRECTORY / "val2025_comparison.md"
COLORS = ("#2563eb", "#dc2626", "#7c3aed", "#059669", "#d97706")
TOP_K_COLORS = ("#7c3aed", "#2563eb", "#059669")


def _text(value: object) -> str:
    return html.escape(str(value), quote=True)


def _line(x1: float, y1: float, x2: float, y2: float, color: str, width: int = 1) -> str:
    return (
        f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" '
        f'stroke="{color}" stroke-width="{width}"/>'
    )


def _pr_curve_svg(payload: dict[str, Any]) -> str:
    width, height = 960, 560
    left, top, plot_width, plot_height = 90, 55, 670, 410
    right = left + plot_width
    bottom = top + plot_height
    pieces = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "<title>Validation 2025 precision-recall curves</title>",
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="90" y="30" font-family="Arial" font-size="20" font-weight="bold">Validation 2025 precision-recall curves</text>',
    ]
    for tick in range(0, 6):
        value = tick / 5
        x = left + value * plot_width
        y = bottom - value * plot_height
        pieces.append(_line(x, top, x, bottom, "#e5e7eb"))
        pieces.append(_line(left, y, right, y, "#e5e7eb"))
        pieces.append(
            f'<text x="{x:.1f}" y="{bottom + 22}" text-anchor="middle" font-family="Arial" font-size="12">{value:.1f}</text>'
        )
        pieces.append(
            f'<text x="{left - 12}" y="{y + 4:.1f}" text-anchor="end" font-family="Arial" font-size="12">{value:.1f}</text>'
        )
    pieces.extend(
        [
            _line(left, top, left, bottom, "#111827", 2),
            _line(left, bottom, right, bottom, "#111827", 2),
            f'<text x="{left + plot_width / 2}" y="{height - 28}" text-anchor="middle" font-family="Arial" font-size="14">Recall</text>',
            f'<text x="24" y="{top + plot_height / 2}" text-anchor="middle" transform="rotate(-90 24 {top + plot_height / 2})" font-family="Arial" font-size="14">Precision</text>',
        ]
    )

    labels = payload["validation_predictions"]
    names = [model["name"] for model in payload["models"]]
    for model_index, name in enumerate(names):
        ordered = sorted(
            labels,
            key=lambda row: (-row["scores"][name], row["cve_id"]),
        )
        positive_total = sum(int(row["label"]) for row in ordered)
        if not positive_total:
            continue
        true_positive = 0
        curve = [(0.0, 1.0)]
        for index, row in enumerate(ordered, start=1):
            true_positive += int(row["label"])
            curve.append((true_positive / positive_total, true_positive / index))
        max_points = 1000
        stride = max(1, math.ceil(len(curve) / max_points))
        sampled = curve[::stride]
        if sampled[-1] != curve[-1]:
            sampled.append(curve[-1])
        points = " ".join(
            f"{left + recall * plot_width:.1f},{bottom - precision * plot_height:.1f}"
            for recall, precision in sampled
        )
        color = COLORS[model_index % len(COLORS)]
        pieces.append(
            f'<polyline points="{points}" fill="none" stroke="{color}" stroke-width="2" opacity="0.9"/>'
        )

    legend_y = top + 18
    for index, name in enumerate(names):
        y = legend_y + index * 28
        pieces.append(_line(right + 22, y, right + 50, y, COLORS[index % len(COLORS)], 3))
        pieces.append(
            f'<text x="{right + 58}" y="{y + 4}" font-family="Arial" font-size="12">{_text(name)}</text>'
        )
    pieces.append("</svg>")
    return "\n".join(pieces)


def _top_k_svg(payload: dict[str, Any]) -> str:
    width, height = 1080, 540
    left, top, plot_width, plot_height = 85, 65, 940, 365
    bottom = top + plot_height
    maximum = max(
        row["metrics"]["precision_at_k"][str(k)]
        for row in payload["models"]
        for k in (50, 100, 500)
    )
    scale_max = max(0.1, math.ceil(maximum * 10) / 10)
    names = [row["name"] for row in payload["models"]]
    group_width = plot_width / len(names)
    bar_width = min(36, group_width / 5)
    pieces = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        "<title>Validation 2025 precision at K</title>",
        '<rect width="100%" height="100%" fill="white"/>',
        '<text x="85" y="32" font-family="Arial" font-size="20" font-weight="bold">Validation 2025 precision at K</text>',
    ]
    for tick in range(0, 6):
        value = scale_max * tick / 5
        y = bottom - value / scale_max * plot_height
        pieces.append(_line(left, y, left + plot_width, y, "#e5e7eb"))
        pieces.append(
            f'<text x="{left - 12}" y="{y + 4:.1f}" text-anchor="end" font-family="Arial" font-size="12">{value:.2f}</text>'
        )
    pieces.append(_line(left, top, left, bottom, "#111827", 2))
    pieces.append(_line(left, bottom, left + plot_width, bottom, "#111827", 2))
    for model_index, result in enumerate(payload["models"]):
        center = left + group_width * (model_index + 0.5)
        values = result["metrics"]["precision_at_k"]
        for bar_index, k in enumerate((50, 100, 500)):
            value = values[str(k)]
            bar_height = value / scale_max * plot_height
            x = center + (bar_index - 1) * (bar_width + 5) - bar_width / 2
            y = bottom - bar_height
            pieces.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_width:.1f}" height="{bar_height:.1f}" fill="{TOP_K_COLORS[bar_index]}"/>'
            )
        pieces.append(
            f'<text x="{center:.1f}" y="{bottom + 24}" text-anchor="middle" font-family="Arial" font-size="11">{_text(result["name"])}</text>'
        )
    for index, k in enumerate((50, 100, 500)):
        x = left + 10 + index * 125
        pieces.append(
            f'<rect x="{x}" y="{height - 42}" width="14" height="14" fill="{TOP_K_COLORS[index]}"/>'
        )
        pieces.append(
            f'<text x="{x + 20}" y="{height - 30}" font-family="Arial" font-size="12">P@{k}</text>'
        )
    pieces.append("</svg>")
    return "\n".join(pieces)


def _comparison_note(payload: dict[str, Any]) -> str:
    by_name = {model["name"]: model["metrics"] for model in payload["models"]}
    proposal = {
        name: by_name[name]
        for name in (
            "Logistic Regression (152 features)",
            "Random Forest",
            "XGBoost calibrated",
        )
    }
    best_ap = max(proposal, key=lambda name: proposal[name]["pr_auc"])
    best_roc = max(proposal, key=lambda name: proposal[name]["roc_auc"])
    best_f1 = max(proposal, key=lambda name: proposal[name]["f1"])
    best_p500 = max(
        proposal,
        key=lambda name: proposal[name]["precision_at_k"]["500"],
    )
    epss = by_name["EPSS baseline"]
    cvss = by_name["CVSS-only baseline"]
    return (
        f"On this split, **{best_ap}** led the three proposal models in PR-AUC "
        f"({proposal[best_ap]['pr_auc']:.4f}) and **{best_roc}** led them in "
        f"ROC-AUC ({proposal[best_roc]['roc_auc']:.4f}); **{best_f1}** led "
        f"the proposal models at the training-selected threshold in F1 "
        f"({proposal[best_f1]['f1']:.4f}), while **{best_p500}** had the "
        f"highest proposal-model P@500 "
        f"({proposal[best_p500]['precision_at_k']['500']:.4f}). The CVSS-only "
        f"baseline exceeded the proposal models at P@50/P@100 "
        f"({cvss['precision_at_k']['50']:.4f}/{cvss['precision_at_k']['100']:.4f}), "
        f"but had lower PR-AUC and ROC-AUC than the proposal XGBoost and Random "
        f"Forest. EPSS had the highest overall ranking metrics "
        f"(PR-AUC {epss['pr_auc']:.4f}, P@100 "
        f"{epss['precision_at_k']['100']:.4f}); it is a hindsight snapshot and "
        "must not be interpreted as a prospective model or input feature."
    )


def _calibration_diagnostics(payload: dict[str, Any]) -> dict[str, dict[str, Any]]:
    predictions = payload["validation_predictions"]
    count = len(predictions)
    diagnostics: dict[str, dict[str, Any]] = {}
    for model in payload["models"]:
        name = model["name"]
        rows = sorted(
            predictions,
            key=lambda row: (row["scores"][name], row["cve_id"]),
        )
        brier = sum(
            (row["scores"][name] - row["label"]) ** 2 for row in rows
        ) / count
        bins = []
        ece = 0.0
        for bin_index in range(10):
            start = bin_index * count // 10
            end = (bin_index + 1) * count // 10
            group = rows[start:end]
            mean_score = sum(row["scores"][name] for row in group) / len(group)
            observed = sum(row["label"] for row in group) / len(group)
            ece += len(group) / count * abs(mean_score - observed)
            bins.append(
                {
                    "count": len(group),
                    "score_min": group[0]["scores"][name],
                    "score_max": group[-1]["scores"][name],
                    "mean_predicted_probability": mean_score,
                    "observed_positive_rate": observed,
                }
            )
        diagnostics[name] = {
            "brier_score": brier,
            "expected_calibration_error_10_equal_count_bins": ece,
            "bins": bins,
        }
    return diagnostics


def render() -> None:
    payload = json.loads(RESULT_PATH.read_text(encoding="utf-8"))
    payload["calibration_diagnostics"] = _calibration_diagnostics(payload)
    payload["metadata"]["hashes_sha256"]["chart_renderer"] = hashlib.sha256(
        Path(__file__).read_bytes()
    ).hexdigest()
    pr_path = RESULT_DIRECTORY / "val2025_pr_curve.svg"
    top_k_path = RESULT_DIRECTORY / "val2025_top_k.svg"
    pr_path.write_text(_pr_curve_svg(payload) + "\n", encoding="utf-8")
    top_k_path.write_text(_top_k_svg(payload) + "\n", encoding="utf-8")
    RESULT_PATH.write_text(
        json.dumps(payload, indent=2, allow_nan=False) + "\n",
        encoding="utf-8",
    )

    report = REPORT_PATH.read_text(encoding="utf-8")
    marker = "## Curves and comparative notes"
    if marker in report:
        report = report[: report.index(marker)].rstrip()
    report += (
        f"\n\n{marker}\n\n"
        "![Validation 2025 precision-recall curves](./val2025_pr_curve.svg)\n\n"
        "![Validation 2025 precision at K](./val2025_top_k.svg)\n\n"
        f"{_comparison_note(payload)}\n"
        "\n### Calibration diagnostics\n\n"
        "| Model | Brier score | ECE (10 equal-count bins) |\n"
        "|---|---:|---:|\n"
        + "\n".join(
            "| {name} | {brier:.6f} | {ece:.6f} |".format(
                name=name,
                brier=values["brier_score"],
                ece=values["expected_calibration_error_10_equal_count_bins"],
            )
            for name, values in payload["calibration_diagnostics"].items()
        )
        + "\n\n"
        "Bins are descriptive, computed from the validation predictions without "
        "fitting a calibrator. The frozen XGBoost sigmoid calibration was "
        "historically fitted on this same validation split, so its calibration "
        "diagnostics are not an independent calibration assessment.\n"
        "\nRecreate these SVGs from the saved prediction JSON with "
        "`python ml/render_val2025_charts.py`.\n"
    )
    REPORT_PATH.write_text(report, encoding="utf-8")
    print(f"Wrote {pr_path.relative_to(ROOT)}")
    print(f"Wrote {top_k_path.relative_to(ROOT)}")


if __name__ == "__main__":
    render()
