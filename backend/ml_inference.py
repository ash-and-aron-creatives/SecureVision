import hashlib
import json
import logging
import re
import time
from functools import lru_cache
from pathlib import Path
from typing import TypedDict

from backend.rules_config import (
    MODEL_CONFIG_PATH,
    MODEL_DIRECTORY,
    CVSS_MISSING_IMPUTATION,
    CVSS_VECTOR_PATTERNS,
    ML_REASON_COUNT,
    TFIDF_TRANSFORMER_FILENAME,
    criticality_factor,
    exposure_factor,
    ml_priority,
    ML_RECOMMENDED_ACTIONS,
)

_LOGGER = logging.getLogger(__name__)


class MLAssessment(TypedDict):
    likelihood: float | None
    risk: float | None
    priority: str | None
    top_reasons: list[str] | None
    model_version: str | None
    recommended_action: str | None
    unavailable_reason: str | None


class _DescriptionPreprocessor:
    def __init__(self, regex_blacklist: str):
        self.regex_blacklist = regex_blacklist

    def __call__(self, value: str) -> str:
        return re.sub(self.regex_blacklist, "", str(value).lower(), flags=re.IGNORECASE)


@lru_cache(maxsize=1)
def _load_bundle() -> tuple[object, object, list[str], str, dict]:
    bundle_started = time.perf_counter()
    try:
        import joblib
        import numpy as np
        from sklearn.feature_extraction.text import TfidfVectorizer
    except ImportError as exc:
        raise ModuleNotFoundError(
            f"Missing inference dependency: {exc.name or str(exc)}"
        ) from exc

    config = json.loads(MODEL_CONFIG_PATH.read_text(encoding="utf-8-sig"))
    model_filename = config.get("saved_model")
    if not isinstance(model_filename, str) or Path(model_filename).name != model_filename:
        raise ValueError("Frozen model filename is missing or unsafe.")
    model_path = MODEL_DIRECTORY / model_filename
    if not model_path.is_file():
        raise FileNotFoundError(f"Frozen model file is missing: {model_filename}")

    model_hash = hashlib.sha256(model_path.read_bytes()).hexdigest()
    expected_hash = config.get("model_sha256")
    if model_hash != expected_hash:
        raise ValueError("Frozen model SHA-256 does not match frozen_config.json.")

    transformer_path = MODEL_DIRECTORY / TFIDF_TRANSFORMER_FILENAME
    if not transformer_path.is_file():
        raise FileNotFoundError(f"Frozen text transformer is missing: {TFIDF_TRANSFORMER_FILENAME}")

    model_started = time.perf_counter()
    model = joblib.load(model_path)
    model_load_ms = (time.perf_counter() - model_started) * 1000
    transformer_started = time.perf_counter()
    transformer = joblib.load(transformer_path)
    transformer_load_ms = (time.perf_counter() - transformer_started) * 1000
    features = config.get("features")
    if not isinstance(features, list) or not all(isinstance(item, str) for item in features):
        raise ValueError("Frozen model feature list is invalid.")
    forbidden = [feature for feature in features if "kev" in feature.casefold() or "epss" in feature.casefold()]
    if forbidden:
        raise ValueError("Frozen feature list contains forbidden KEV or EPSS model inputs.")

    expected_count = config.get("n_features_in")
    if getattr(model, "n_features_in_", None) != expected_count:
        raise ValueError("Frozen model input count does not match frozen_config.json.")
    if list(getattr(model, "feature_names_in_", [])) != features:
        raise ValueError("Frozen model feature order does not match frozen_config.json.")

    settings = config.get("tfidf_settings", {})
    text_features = features[-int(settings.get("max_features", 0)):]
    actual_text_features = transformer.get_feature_names_out().tolist()
    vocabulary_hash = hashlib.sha256("".join(actual_text_features).encode()).hexdigest()
    if actual_text_features != text_features or vocabulary_hash != settings.get("vocab_sha256"):
        raise ValueError("Frozen text transformer does not match frozen_config.json.")

    version = f"{model_filename}:{expected_hash[:12]}"
    _LOGGER.debug(
        "ml.artifact_load model_ms=%.3f tfidf_ms=%.3f total_ms=%.3f",
        model_load_ms,
        transformer_load_ms,
        (time.perf_counter() - bundle_started) * 1000,
    )
    return model, transformer, features, version, config


def _unavailable(reason: str, model_version: str | None = None) -> MLAssessment:
    return {
        "likelihood": None,
        "risk": None,
        "priority": None,
        "top_reasons": None,
        "model_version": model_version,
        "recommended_action": None,
        "unavailable_reason": reason,
    }


def _feature_row(
    features: list[str],
    transformer: object,
    config: dict,
    cvss_score: float | None,
    cvss_vector: str | None,
    cwe: str | None,
    description: str,
):
    import numpy as np

    values = {feature: 0.0 for feature in features}
    values["cvss_score"] = (
        float(cvss_score) if cvss_score is not None else CVSS_MISSING_IMPUTATION
    )
    values["cvss_missing"] = float(cvss_score is None)

    vector_text = cvss_vector or ""
    for metric, pattern in CVSS_VECTOR_PATTERNS.items():
        match = re.search(pattern, vector_text)
        value = match.group(1) if match else "MISSING"
        feature_name = f"{metric}_{value}"
        if feature_name in values:
            values[feature_name] = 1.0

    cwe_value = (cwe or "").strip()
    if cwe_value.casefold().startswith("cwe-"):
        cwe_value = f"cwe_{cwe_value.upper()}"
    elif cwe_value.casefold() == "nvd-cwe-noinfo":
        cwe_value = "cwe_NVD-CWE-noinfo"
    elif cwe_value.casefold() == "nvd-cwe-other":
        cwe_value = "cwe_NVD-CWE-Other"
    elif cwe_value:
        cwe_value = f"cwe_{cwe_value}"
    else:
        cwe_value = "cwe_OTHER"
    values[cwe_value if cwe_value in values else "cwe_OTHER"] = 1.0

    text_vector = transformer.transform([description]).toarray()[0]
    text_features = config["features"][-len(text_vector):]
    for feature, value in zip(text_features, text_vector, strict=True):
        values[feature] = float(value)
    return np.asarray([[values[feature] for feature in features]], dtype=np.float32)


def _feature_label(feature: str) -> str:
    labels = {
        "cvss_score": "the CVSS base score",
        "cvss_missing": "the missing-CVSS indicator",
    }
    if feature in labels:
        return labels[feature]
    if feature.startswith("cwe_"):
        return f"the {feature.removeprefix('cwe_')} weakness category"
    for metric, label in (
        ("AV", "attack vector"),
        ("AC", "attack complexity"),
        ("PR", "privileges required"),
        ("UI", "user interaction"),
        ("S", "security scope"),
        ("C", "confidentiality impact"),
        ("I", "integrity impact"),
        ("A", "availability impact"),
    ):
        prefix = f"{metric}_"
        if feature.startswith(prefix):
            return f"the {label} value {feature[len(prefix):]}"
    return f"the description term '{feature}'"


def _explanation_contributions(classifier: object, matrix: object, features: list[str]):
    import numpy as np

    shap_started = time.perf_counter()
    try:
        import shap

        values = shap.TreeExplainer(classifier).shap_values(matrix)
        if isinstance(values, list):
            values = values[-1]
        values = np.asarray(values)
        if values.ndim == 3:
            values = values[:, :, -1]
        if values.shape != (1, len(features)):
            raise ValueError("SHAP returned an unexpected feature shape.")
        _LOGGER.debug(
            "ml.explanation method=shap elapsed_ms=%.3f",
            (time.perf_counter() - shap_started) * 1000,
        )
        return values[0]
    except Exception:
        _LOGGER.debug(
            "ml.explanation method=shap outcome=failed elapsed_ms=%.3f",
            (time.perf_counter() - shap_started) * 1000,
        )
        _LOGGER.warning("SHAP explanation failed; trying native XGBoost contributions.", exc_info=True)

    native_started = time.perf_counter()
    try:
        from xgboost import DMatrix

        values = classifier.get_booster().predict(
            DMatrix(matrix, feature_names=features), pred_contribs=True
        )[0][:-1]
        if values.shape != (len(features),):
            raise ValueError("XGBoost returned an unexpected contribution shape.")
        _LOGGER.debug(
            "ml.explanation method=native_xgboost elapsed_ms=%.3f",
            (time.perf_counter() - native_started) * 1000,
        )
        return values
    except Exception:
        _LOGGER.debug(
            "ml.explanation method=native_xgboost outcome=failed elapsed_ms=%.3f",
            (time.perf_counter() - native_started) * 1000,
        )
        _LOGGER.warning("Native XGBoost explanation failed; factors are unavailable.", exc_info=True)
        return None


def predict_exploit_likelihood(
    cvss_score: float | None,
    cvss_vector: str | None,
    cwe: str | None,
    description: str | None,
    exposure: str,
    criticality: int,
) -> MLAssessment:
    if not description or not description.strip():
        return _unavailable("CVE description is missing.")
    try:
        model, transformer, features, model_version, config = _load_bundle()
    except FileNotFoundError as exc:
        return _unavailable(str(exc))
    except ModuleNotFoundError as exc:
        return _unavailable(str(exc))
    except (OSError, ValueError, AttributeError, EOFError, json.JSONDecodeError) as exc:
        return _unavailable(f"Frozen model could not be loaded: {exc}")

    try:
        import numpy as np
        matrix = _feature_row(
            features, transformer, config, cvss_score, cvss_vector, cwe, description
        )
        likelihood = float(model.predict_proba(matrix)[0, 1])
        if not np.isfinite(likelihood) or not 0 <= likelihood <= 1:
            return _unavailable("Frozen model returned an invalid likelihood.", model_version)

        risk = likelihood * exposure_factor(exposure) * criticality_factor(criticality)
        priority = ml_priority(risk)
        classifier = model.calibrated_classifiers_[0].estimator
        contribution_values = _explanation_contributions(classifier, matrix, features)
        top_reasons: list[str] | None = None
        if contribution_values is not None:
            ranked = np.argsort(np.abs(contribution_values))[::-1][:ML_REASON_COUNT]
            top_reasons = []
            for index in ranked:
                direction = "increased" if contribution_values[index] >= 0 else "decreased"
                top_reasons.append(
                    f"{_feature_label(features[int(index)])} {direction} the model score."
                )

        return {
            "likelihood": likelihood,
            "risk": risk,
            "priority": priority,
            "top_reasons": top_reasons,
            "model_version": model_version,
            "recommended_action": ML_RECOMMENDED_ACTIONS[priority],
            "unavailable_reason": None,
        }
    except (ImportError, AttributeError, TypeError, ValueError, RuntimeError) as exc:
        return _unavailable(f"Prediction unavailable: {exc}", model_version)


def warm_up_model() -> None:
    started = time.perf_counter()
    try:
        assessment = predict_exploit_likelihood(
            7.5,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "CWE-79",
            "SecureVision startup warm-up description.",
            "Internal",
            3,
        )
    except Exception:
        _LOGGER.exception(
            "ML startup warm-up failed after %.3f ms.",
            (time.perf_counter() - started) * 1000,
        )
        return

    elapsed_ms = (time.perf_counter() - started) * 1000
    if assessment["unavailable_reason"] is not None:
        _LOGGER.warning(
            "ML startup warm-up unavailable after %.3f ms: %s",
            elapsed_ms,
            assessment["unavailable_reason"],
        )
        return
    _LOGGER.info("ML startup warm-up completed in %.3f ms.", elapsed_ms)
