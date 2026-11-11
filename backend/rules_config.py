from pathlib import Path


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
CVE_DATASET_PATH = Path(__file__).resolve().parents[1] / "data" / "processed" / "master_cves_2026-10-08.csv"
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
        "name": "Internal-API",
        "type": "Application",
        "ip_or_domain": "internal-api.demo.invalid",
        "owner": "Synthetic Demo Team",
        "environment": "Development",
        "exposure": "Internal",
        "criticality": 3,
    },
)
SYNTHETIC_DEMO_FINDINGS = (
    {
        "asset_name": "Payment-DB",
        "cve_id": "CVE-2099-10001",
        "cvss_score": 9.8,
        "epss_percentile": 0.97,
        "in_kev": False,
        "status": "Open",
        "date_found": "2026-10-01",
    },
    {
        "asset_name": "Internal-API",
        "cve_id": "CVE-2099-10002",
        "cvss_score": 6.1,
        "epss_percentile": 0.05,
        "in_kev": False,
        "status": "Open",
        "date_found": "2026-10-01",
    },
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
