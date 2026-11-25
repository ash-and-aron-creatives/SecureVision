import os
from pathlib import Path


PRIORITY_MODES = ("ml_asset", "deterministic")
PRIORITY_MODE = os.environ.get("PRIORITY_MODE", "ml_asset").strip().casefold()
if PRIORITY_MODE not in PRIORITY_MODES:
    raise ValueError(f"PRIORITY_MODE must be one of: {', '.join(PRIORITY_MODES)}.")
KNOWN_EXPLOITED_FLOOR = "High"
EXPOSURE_FACTORS = {"internet": 1.5, "internal": 1.0}
CRITICALITY_FACTORS = {1: 0.6, 2: 0.8, 3: 1.0, 4: 1.2, 5: 1.4}
CVSS_MISSING_IMPUTATION = 6.7
ML_REASON_COUNT = 3
ML_THRESHOLD_PERCENTILES = {"Critical": 99, "High": 90, "Medium": 50}
ASSET_TYPES = ("Server", "Workstation", "Network", "Cloud", "Application", "Other")
ASSET_ENVIRONMENTS = ("Production", "Staging", "Development", "Testing", "Other", "Unknown")
ASSET_EXPOSURES = {"internet": "Internet", "internal": "Internal"}
ASSET_DEFAULT_TYPE = "Other"
ASSET_DEFAULT_IP_OR_DOMAIN = ""
ASSET_DEFAULT_OWNER = ""
ASSET_DEFAULT_ENVIRONMENT = "Unknown"
ASSET_DEFAULT_EXPOSURE = "Internal"
ASSET_DEFAULT_NEEDS_REVIEW = False
LOGIN_MAX_FAILED_ATTEMPTS = 5
LOGIN_ATTEMPT_WINDOW_SECONDS = 15 * 60
LOGIN_RATE_LIMIT_MAX_KEYS = 10_000
LOGIN_USERNAME_MAX_LENGTH = 120
ASSET_NAME_MAX_LENGTH = 200
ASSET_IP_OR_DOMAIN_MAX_LENGTH = 253
ASSET_OWNER_MAX_LENGTH = 120
_DEFAULT_CVE_DATASET_PATH = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "processed"
    / "master_cves_2026-10-08.csv"
)
CVE_DATASET_PATH = Path(
    os.environ.get("CVE_DATASET_PATH", str(_DEFAULT_CVE_DATASET_PATH))
)
CVE_SEARCH_MAX_RESULTS = 100
SYNTHETIC_DEMO_MODE_ENV = "SECUREVISION_DEMO_MODE"
SYNTHETIC_DEMO_SEED_ACTION = "SYNTHETIC_DEMO_SEEDED"
SYNTHETIC_DEMO_ASSETS = (
    {
        "name": "Payment-DB",
        "type": "Server",
        "ip_or_domain": "payment-db.demo.invalid",
        "owner": "Synthetic Demo Team",
        "environment": "Production",
        "exposure": "Internet",
        "criticality": 5,
    },
    {
        "name": "Public-Web",
        "type": "Server",
        "ip_or_domain": "public-web.demo.invalid",
        "owner": "Synthetic Demo Team",
        "environment": "Production",
        "exposure": "Internet",
        "criticality": 4,
    },
    {
        "name": "VPN-Gateway",
        "type": "Network",
        "ip_or_domain": "vpn.demo.invalid",
        "owner": "Synthetic Demo Team",
        "environment": "Production",
        "exposure": "Internet",
        "criticality": 4,
    },
    {
        "name": "Customer-Portal",
        "type": "Application",
        "ip_or_domain": "portal.demo.invalid",
        "owner": "Synthetic Demo Team",
        "environment": "Production",
        "exposure": "Internet",
        "criticality": 3,
    },
    {
        "name": "Internal-API",
        "type": "Application",
        "ip_or_domain": "internal-api.demo.invalid",
        "owner": "Synthetic Demo Team",
        "environment": "Development",
        "exposure": "Internal",
        "criticality": 4,
    },
    {
        "name": "Build-Agent",
        "type": "Server",
        "ip_or_domain": "build-agent.demo.invalid",
        "owner": "Synthetic Demo Team",
        "environment": "Development",
        "exposure": "Internal",
        "criticality": 3,
    },
    {
        "name": "Staff-Workstation",
        "type": "Workstation",
        "ip_or_domain": "workstation.demo.invalid",
        "owner": "Synthetic Demo Team",
        "environment": "Production",
        "exposure": "Internal",
        "criticality": 2,
    },
    {
        "name": "Dev-Cluster",
        "type": "Cloud",
        "ip_or_domain": "dev-cluster.demo.invalid",
        "owner": "Synthetic Demo Team",
        "environment": "Development",
        "exposure": "Internal",
        "criticality": 1,
    },
)
SYNTHETIC_DEMO_CVES = (
    {
        "cve_id": "CVE-2021-44228",
        "cvss_score": 10.0,
        "epss_percentile": 0.99999,
        "in_kev": True,
    },
    {
        "cve_id": "CVE-2021-34527",
        "cvss_score": 8.8,
        "epss_percentile": 0.99792,
        "in_kev": False,
    },
    {
        "cve_id": "CVE-2021-28169",
        "cvss_score": 5.3,
        "epss_percentile": 0.7848,
        "in_kev": False,
    },
    {
        "cve_id": "CVE-2018-0109",
        "cvss_score": 2.7,
        "epss_percentile": 0.01218,
        "in_kev": False,
    },
    {
        "cve_id": "CVE-2020-0796",
        "cvss_score": 10.0,
        "epss_percentile": 0.9981,
        "in_kev": False,
    },
    {
        "cve_id": "CVE-2023-28252",
        "cvss_score": 7.8,
        "epss_percentile": 0.48973,
        "in_kev": True,
    },
    {
        "cve_id": "CVE-2021-26858",
        "cvss_score": 7.8,
        "epss_percentile": 0.93651,
        "in_kev": False,
    },
    {
        "cve_id": "CVE-2019-19781",
        "cvss_score": 9.8,
        "epss_percentile": 0.99999,
        "in_kev": False,
    },
)
SYNTHETIC_DEMO_FINDINGS = tuple(
    {
        "asset_name": asset["name"],
        **SYNTHETIC_DEMO_CVES[(asset_index + finding_index) % len(SYNTHETIC_DEMO_CVES)],
        "status": ("Open", "In Progress", "Resolved")[(asset_index + finding_index) % 3],
        "date_found": f"2026-10-{1 + (asset_index * 5 + finding_index) % 28:02d}",
    }
    for asset_index, asset in enumerate(SYNTHETIC_DEMO_ASSETS)
    for finding_index in range(5)
)
CVSS_VECTOR_PATTERNS = {
    "AV": r"AV:([NALP])",
    "AC": r"AC:([LH])",
    "PR": r"PR:([NLH])",
    "UI": r"UI:([NR])",
    "S": r"S:([UC])",
    "C": r"C:([NLH])",
    "I": r"I:([NLH])",
    "A": r"A:([NLH])",
}

ML_RISK_THRESHOLDS = {
    "Critical": 0.044082497805356974,
    "High": 0.007056011210661384,
    "Medium": 0.0008546133991330863,
}

ML_RECOMMENDED_ACTIONS = {
    "Critical": "Expedite remediation and validate compensating controls.",
    "High": "Prioritize remediation in the next planned change window.",
    "Medium": "Schedule remediation and monitor for updated threat intelligence.",
    "Low": "Address through routine vulnerability maintenance.",
}

RECOMMENDED_ACTION_TEMPLATES = {
    "Critical": "Expedite remediation and validate compensating controls.",
    "High": "Prioritize remediation in the next planned change window.",
    "Medium": "Schedule remediation and monitor for updated threat intelligence.",
    "Low": "Address through routine vulnerability maintenance.",
}


def recommended_action_for_priority(priority: str) -> str:
    try:
        return RECOMMENDED_ACTION_TEMPLATES[priority]
    except KeyError as exc:
        raise ValueError(f"Unknown final priority tier: {priority}") from exc


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
MODEL_DIRECTORY = REPOSITORY_ROOT / "ml" / "models"
MODEL_CONFIG_PATH = REPOSITORY_ROOT / "frozen_config.json"
TFIDF_TRANSFORMER_FILENAME = "headline_tfidf_transformer.joblib"
MODEL_RESULTS_DIRECTORY = REPOSITORY_ROOT / "docs" / "results"
DECISION_LOG_PATH = REPOSITORY_ROOT / "Decision_Log.md"
ML_EVALUATION_NOTE = (
    "Offline evaluation: PR-AUC 0.0114 vs CVSS 0.0117; "
    "this signal does not drive the tier."
)


def exposure_factor(exposure: str) -> float:
    return EXPOSURE_FACTORS["internet" if exposure.strip().casefold() == "internet" else "internal"]


def criticality_factor(criticality: int) -> float:
    try:
        return CRITICALITY_FACTORS[criticality]
    except KeyError as exc:
        raise ValueError("Criticality must be between 1 and 5.") from exc


def ml_priority(ml_risk: float) -> str:
    if ml_risk >= ML_RISK_THRESHOLDS["Critical"]:
        return "Critical"
    if ml_risk >= ML_RISK_THRESHOLDS["High"]:
        return "High"
    if ml_risk >= ML_RISK_THRESHOLDS["Medium"]:
        return "Medium"
    return "Low"
