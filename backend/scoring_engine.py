from typing import TypedDict
from backend import rules_config


class ScoringInputs(TypedDict):
    in_kev: bool
    internet_facing: bool
    criticality: int
    epss_percentile: float | None
    cvss_score: float | None


class ScoringExplanation(TypedDict):
    summary: str
    inputs: ScoringInputs
    rationale: list[str]


class ScoringResult(TypedDict):
    tier: str
    score: int
    explanation: ScoringExplanation


TIER_SCORES = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
_TIER_RANK = {tier: rank for rank, tier in enumerate(("Low", "Medium", "High", "Critical"))}


def resolve_final_priority(
    rule_tier: str,
    ml_tier: str | None,
    in_kev: bool,
) -> tuple[str, str]:
    if rules_config.PRIORITY_MODE == "ml_asset" and ml_tier is not None:
        final_tier = ml_tier
        source = "ml"
        floor = rules_config.KNOWN_EXPLOITED_FLOOR
        if in_kev and _TIER_RANK[final_tier] < _TIER_RANK[floor]:
            final_tier = floor
            source = "ml+kev_floor"
        return final_tier, source
    return rule_tier, "rules"


def determine_epss_band(percentile: float | None) -> str:
    if percentile is None:
        return "Missing"
    if percentile > 0.95:
        return "High (>0.95)"
    if percentile >= 0.20:
        return "Med (0.2-0.95)"
    return "Low (<0.2)"


def determine_cvss_band(cvss: float | None) -> str:
    if cvss is None:
        return "Low (0.0-3.9)"
    if cvss >= 9.0:
        return "Crit (9.0+)"
    if cvss >= 7.0:
        return "High (7.0-8.9)"
    if cvss >= 4.0:
        return "Med (4.0-6.9)"
    return "Low (0.0-3.9)"


def calculate_priority(
    in_kev: bool,
    internet_facing: bool,
    criticality: int,
    epss_percentile: float | None,
    cvss_score: float | None,
) -> ScoringResult:
    epss_band = determine_epss_band(epss_percentile)
    cvss_band = determine_cvss_band(cvss_score)
    rationale: list[str] = []

    if in_kev:
        rationale.append("Vulnerability is actively exploited in the wild (CISA KEV).")
        if internet_facing or criticality >= 4:
            tier = "Critical"
            if internet_facing:
                rationale.append("Asset is directly exposed to the Internet.")
            if criticality >= 4:
                rationale.append(f"Asset has high business criticality ({criticality}/5).")
        else:
            tier = "High"
            rationale.append(
                f"Asset is internal with lower criticality ({criticality}/5), preventing Critical tier."
            )
    elif epss_band == "High (>0.95)":
        rationale.append(
            f"High predictive probability of exploitation (EPSS Percentile: {epss_percentile * 100:.1f}%)."
        )
        if internet_facing or criticality >= 4:
            tier = "Critical"
            if internet_facing:
                rationale.append("Asset is directly exposed to the Internet.")
            if criticality >= 4:
                rationale.append(f"Asset has high business criticality ({criticality}/5).")
        else:
            tier = "High"
            rationale.append("Asset is internal, preventing Critical tier.")
    elif cvss_band == "Crit (9.0+)":
        rationale.append(f"Base severity is Critical (CVSS: {cvss_score}).")
        if internet_facing:
            tier = "Critical"
            rationale.append("Asset is exposed to the Internet.")
        elif criticality >= 4:
            tier = "High"
            rationale.append(f"Asset has high business criticality ({criticality}/5).")
        else:
            tier = "Medium"
            rationale.append("Internal asset limits maximum severity.")
    elif epss_band == "Med (0.2-0.95)":
        rationale.append(
            f"Moderate predictive probability of exploitation (EPSS Percentile: {epss_percentile * 100:.1f}%)."
        )
        if criticality >= 4:
            tier = "High"
            rationale.append(f"Escalated due to high asset criticality ({criticality}/5).")
        else:
            tier = "Medium"
    elif cvss_band == "High (7.0-8.9)":
        tier = "Medium"
        rationale.append(
            f"Base severity is High (CVSS: {cvss_score}), but lacks active threat intelligence."
        )
    else:
        tier = "Low"
        rationale.append(f"Low predictive threat and base severity (CVSS: {cvss_score}).")

    explanation: ScoringExplanation = {
        "summary": " ".join(rationale),
        "inputs": {
            "in_kev": in_kev,
            "internet_facing": internet_facing,
            "criticality": criticality,
            "epss_percentile": epss_percentile,
            "cvss_score": cvss_score,
        },
        "rationale": rationale,
    }
    return {"tier": tier, "score": TIER_SCORES[tier], "explanation": explanation}
