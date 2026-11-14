import json
import sys
from collections import Counter
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

from backend import auth, main, ml_inference
from backend.database import Base, get_db
from backend.models import Asset, User
from backend.rules_config import (
    CRITICALITY_FACTORS,
    ML_RISK_THRESHOLDS,
    SYNTHETIC_DEMO_ASSETS,
    SYNTHETIC_DEMO_FINDINGS,
    criticality_factor,
    exposure_factor,
    ml_priority,
)
from backend import rules_config
from backend.scoring_engine import calculate_priority, resolve_final_priority
from backend.tests.db_helpers import create_test_engine


@pytest.fixture
def api(monkeypatch):
    engine = create_test_engine()
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(autocommit=False, autoflush=False, bind=engine)()
    users = [
        User(username=role, hashed_password="not-used", role=role)
        for role in ("admin", "analyst", "viewer")
    ]
    asset = Asset(name="ML-TEST-ASSET", exposure="Internet", criticality=5)
    db.add_all([*users, asset])
    db.commit()
    asset_id = asset.id

    async def nvd_and_epss(cve_id):
        return {
            "cve_id": cve_id,
            "epss": 0.4,
            "cvss": 9.8,
            "available": True,
            "errors": [],
            "description": "Mock description for advisory tests.",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe": "CWE-79",
            "published_date": "2025-01-01T00:00Z",
        }

    monkeypatch.setattr(main, "fetch_cve_data", nvd_and_epss)

    def override_get_db():
        yield db

    main.app.dependency_overrides[get_db] = override_get_db
    with TestClient(main.app) as client:
        yield {
            "client": client,
            "db": db,
            "asset_id": asset_id,
            "headers_for": lambda role: {
                "Authorization": f"Bearer {auth.create_access_token({'sub': role})}"
            },
        }
    main.app.dependency_overrides.pop(get_db, None)
    db.close()
    engine.dispose()


def test_exposure_criticality_and_threshold_mapping():
    assert exposure_factor("Internet") == 1.5
    assert exposure_factor("Internal") == 1.0
    assert [criticality_factor(level) for level in range(1, 6)] == [
        CRITICALITY_FACTORS[level] for level in range(1, 6)
    ]
    assert criticality_factor(1) == 0.6
    assert criticality_factor(5) == 1.4
    with pytest.raises(ValueError, match="between 1 and 5"):
        criticality_factor(0)

    assert ml_priority(ML_RISK_THRESHOLDS["Critical"]) == "Critical"
    assert ml_priority(ML_RISK_THRESHOLDS["High"]) == "High"
    assert ml_priority(ML_RISK_THRESHOLDS["Medium"]) == "Medium"
    assert ml_priority(ML_RISK_THRESHOLDS["Medium"] - 0.0000001) == "Low"


def test_missing_description_and_missing_model_return_explicit_unavailable(monkeypatch, tmp_path):
    missing_description = ml_inference.predict_exploit_likelihood(
        7.0, None, None, None, "Internal", 3
    )
    assert missing_description["likelihood"] is None
    assert missing_description["unavailable_reason"] == "CVE description is missing."

    ml_inference._load_bundle.cache_clear()
    monkeypatch.setattr(ml_inference, "MODEL_DIRECTORY", tmp_path)
    unavailable = ml_inference.predict_exploit_likelihood(
        7.0, None, None, "Description present.", "Internal", 3
    )
    assert unavailable["likelihood"] is None
    assert "Frozen model file is missing" in unavailable["unavailable_reason"]
    ml_inference._load_bundle.cache_clear()


def test_mocked_prediction_returns_calibrated_assessment_and_reasons(monkeypatch):
    config = json.loads(
        Path("frozen_config.json").read_text(encoding="utf-8-sig")
    )
    features = config["features"]

    class FakeTransformer:
        def transform(self, descriptions):
            assert descriptions == ["Mock description"]
            return SimpleNamespace(toarray=lambda: np.zeros((1, 100)))

    class FakeBooster:
        def predict(self, matrix, pred_contribs):
            assert pred_contribs is True
            contributions = np.zeros((1, len(features) + 1))
            contributions[0, :3] = [1.0, -0.5, 0.25]
            return contributions

    class FakeModel:
        calibrated_classifiers_ = [
            SimpleNamespace(estimator=SimpleNamespace(get_booster=lambda: FakeBooster()))
        ]

        def predict_proba(self, matrix):
            assert matrix.shape == (1, 152)
            return np.array([[0.8, 0.2]])

    class FakeShapExplainer:
        def __init__(self, estimator):
            assert hasattr(estimator, "get_booster")

        def shap_values(self, matrix):
            values = np.zeros((1, len(features)))
            values[0, :3] = [1.0, -0.5, 0.25]
            return values

    monkeypatch.setitem(
        sys.modules,
        "shap",
        SimpleNamespace(TreeExplainer=FakeShapExplainer),
    )
    monkeypatch.setattr(
        ml_inference,
        "_load_bundle",
        lambda: (FakeModel(), FakeTransformer(), features, "mock-model", config),
    )
    result = ml_inference.predict_exploit_likelihood(
        7.5,
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "CWE-79",
        "Mock description",
        "Internal",
        3,
    )

    assert result["likelihood"] == 0.2
    assert result["risk"] == 0.2
    assert result["priority"] == "Critical"
    assert len(result["top_reasons"]) == 3
    assert all(reason.endswith(".") for reason in result["top_reasons"])
    assert result["unavailable_reason"] is None


def test_frozen_feature_list_has_no_kev_or_epss_leakage():
    config = json.loads(
        Path("frozen_config.json").read_text(encoding="utf-8-sig")
    )
    assert not [
        feature for feature in config["features"]
        if "kev" in feature.casefold() or "epss" in feature.casefold()
    ]


def test_priority_mode_selection_and_known_exploited_floor(monkeypatch):
    monkeypatch.setattr(rules_config, "PRIORITY_MODE", "deterministic")
    assert resolve_final_priority("Critical", "Low", False) == ("Critical", "rules")

    monkeypatch.setattr(rules_config, "PRIORITY_MODE", "ml_asset")
    assert resolve_final_priority("Critical", "Low", False) == ("Low", "ml")
    assert resolve_final_priority("Critical", "Low", True) == ("High", "ml+kev_floor")
    assert resolve_final_priority("Low", "High", True) == ("High", "ml")
    assert resolve_final_priority("Critical", None, True) == ("Critical", "rules")


def test_synthetic_demo_final_priority_distribution_by_mode(monkeypatch):
    assets = {asset["name"]: asset for asset in SYNTHETIC_DEMO_ASSETS}
    distributions = {}
    for mode in ("deterministic", "ml_asset"):
        monkeypatch.setattr(rules_config, "PRIORITY_MODE", mode)
        tiers = Counter()
        for finding in SYNTHETIC_DEMO_FINDINGS:
            asset = assets[finding["asset_name"]]
            scoring = calculate_priority(
                finding["in_kev"],
                asset["exposure"].casefold() == "internet",
                asset["criticality"],
                finding["epss_percentile"],
                finding["cvss_score"],
            )
            final_tier, _ = resolve_final_priority(
                scoring["tier"], None, finding["in_kev"]
            )
            tiers[final_tier] += 1
        distributions[mode] = dict(sorted(tiers.items()))

    assert distributions == {
        "deterministic": {"Critical": 1, "Low": 1},
        "ml_asset": {"Critical": 1, "Low": 1},
    }


def test_explanation_uses_shap_then_native_then_unavailable(monkeypatch):
    feature_names = ["cvss_score", "cwe_79", "term"]
    contributions = np.array([[0.7, -0.3, 0.1]])

    class FakeExplainer:
        def __init__(self, classifier):
            assert classifier == "xgb-estimator"

        def shap_values(self, matrix):
            assert matrix == "feature-matrix"
            return contributions

    monkeypatch.setitem(
        __import__("sys").modules,
        "shap",
        SimpleNamespace(TreeExplainer=FakeExplainer),
    )
    result = ml_inference._explanation_contributions(
        "xgb-estimator", "feature-matrix", feature_names
    )
    assert result.shape == (3,)
    assert result.tolist() == [0.7, -0.3, 0.1]

    class BrokenExplainer:
        def __init__(self, classifier):
            raise RuntimeError("unsupported model")

    class FakeBooster:
        def predict(self, matrix, pred_contribs):
            assert pred_contribs is True
            return np.array([[0.4, -0.2, 0.05, 0.0]])

    monkeypatch.setitem(
        __import__("sys").modules,
        "shap",
        SimpleNamespace(TreeExplainer=BrokenExplainer),
    )
    monkeypatch.setitem(
        __import__("sys").modules,
        "xgboost",
        SimpleNamespace(
            DMatrix=lambda matrix, feature_names: matrix,
        ),
    )
    native = ml_inference._explanation_contributions(
        SimpleNamespace(get_booster=lambda: FakeBooster()),
        "feature-matrix",
        feature_names,
    )
    assert native.shape == (3,)
    assert native.tolist() == [0.4, -0.2, 0.05]

    class BrokenBooster:
        def predict(self, matrix, pred_contribs):
            raise RuntimeError("native explanation unavailable")

    unavailable = ml_inference._explanation_contributions(
        SimpleNamespace(get_booster=lambda: BrokenBooster()),
        "feature-matrix",
        feature_names,
    )
    assert unavailable is None


def test_model_results_requires_auth_and_is_available_to_every_role(api):
    client = api["client"]
    assert client.get("/model/results").status_code == 401

    for role in ("admin", "analyst", "viewer"):
        response = client.get(
            "/model/results",
            headers=api["headers_for"](role),
        )
        assert response.status_code == 200
        body = response.json()
        assert {"models", "conclusion", "source_files"} == set(body)
        assert body["conclusion"] != ""
        xgboost_test = next(
            row for row in body["models"]
            if row["name"] == "XGBoost calibrated" and row["dataset"] == "Test 2026"
        )
        assert xgboost_test["pr_auc"] == 0.0114
        assert xgboost_test["f1"] is None
        assert xgboost_test["roc_auc"] is None
        assert any(
            row["name"] == "Logistic Regression (CVSS-only)"
            and row["dataset"] == "Validation 2025"
            and row["pr_auc"] == 0.0148
            for row in body["models"]
        )
        random_forest = next(
            row for row in body["models"]
            if row["name"] == "Random Forest"
            and row["dataset"] == "Validation 2025"
        )
        assert random_forest["pr_auc"] is not None
        assert random_forest["precision"] is not None
        assert random_forest["recall"] is not None
        assert random_forest["f1"] is not None
        assert random_forest["roc_auc"] is not None
        assert set(random_forest["precision_at_k"]) == {"50", "100", "500"}
        assert set(random_forest["recall_at_k"]) == {"50", "100", "500"}
        for model_name in (
            "XGBoost calibrated",
            "Logistic Regression (152 features)",
            "Random Forest",
            "CVSS-only baseline",
            "EPSS baseline",
        ):
            row = next(
                item for item in body["models"]
                if item["name"] == model_name
                and item["dataset"] == "Validation 2025"
            )
            assert all(
                row[field] is not None
                for field in ("pr_auc", "precision", "recall", "f1", "roc_auc")
            )
            assert set(row["precision_at_k"]) == {"50", "100", "500"}
            assert set(row["recall_at_k"]) == {"50", "100", "500"}

    assert client.get("/audit", headers=api["headers_for"]("viewer")).status_code == 403


def test_ml_advisory_never_changes_deterministic_tier_or_score(api, monkeypatch):
    client = api["client"]
    headers = api["headers_for"]("analyst")
    assessments = iter([
        {
            "likelihood": 0.9,
            "risk": 1.89,
            "priority": "Critical",
            "top_reasons": ["A factor increased the model score."],
            "model_version": "mock-model",
            "recommended_action": "Mock advisory action.",
            "unavailable_reason": None,
        },
        {
            "likelihood": None,
            "risk": None,
            "priority": None,
            "top_reasons": None,
            "model_version": None,
            "recommended_action": None,
            "unavailable_reason": "CVE description is missing.",
        },
    ])
    monkeypatch.setattr(
        main,
        "predict_exploit_likelihood",
        lambda **kwargs: next(assessments),
    )
    payload = {
        "asset_id": api["asset_id"],
        "cve_id": "CVE-2025-7001",
        "cvss_score": 9.8,
        "in_kev": False,
        "epss_percentile": 0.0,
    }

    available = client.post("/scan", json=payload, headers=headers)
    unavailable = client.post("/scan", json=payload, headers=headers)
    assert available.status_code == unavailable.status_code == 200
    assert available.json()["priority_tier"] == unavailable.json()["priority_tier"]
    assert available.json()["score"] == unavailable.json()["score"]
    assert available.json()["ml_likelihood"] == 0.9
    assert unavailable.json()["ml_likelihood"] is None
    assert unavailable.json()["ml_unavailable_reason"] == "CVE description is missing."

    detail = client.get(
        f"/findings/{available.json()['finding_id']}",
        headers=headers,
    ).json()
    assert detail["score_history"][0]["ml_likelihood"] is None
    assert detail["score_history"][1]["ml_likelihood"] == 0.9


def test_ml_asset_mode_persists_ml_priority_and_kev_floor(api, monkeypatch):
    monkeypatch.setattr(rules_config, "PRIORITY_MODE", "ml_asset")
    monkeypatch.setattr(
        main,
        "predict_exploit_likelihood",
        lambda **kwargs: {
            "likelihood": 0.1,
            "risk": 0.21,
            "priority": "Low",
            "top_reasons": ["the CVSS base score increased the model score."],
            "model_version": "mock-model",
            "recommended_action": "Mock advisory action.",
            "unavailable_reason": None,
        },
    )
    client = api["client"]
    headers = api["headers_for"]("analyst")
    payload = {
        "asset_id": api["asset_id"],
        "cve_id": "CVE-2025-7002",
        "cvss_score": 9.8,
        "in_kev": False,
        "epss_percentile": 0.0,
    }

    response = client.post("/scan", json=payload, headers=headers)
    assert response.status_code == 200
    finding_id = response.json()["finding_id"]
    assert response.json()["final_priority"] == "Low"
    assert response.json()["rule_priority_tier"] == "Critical"
    assert response.json()["priority_source"] == "ml"

    payload["in_kev"] = True
    floored = client.post("/scan", json=payload, headers=headers)
    assert floored.status_code == 200
    assert floored.json()["final_priority"] == "High"
    assert floored.json()["priority_source"] == "ml+kev_floor"
    assert floored.json()["rule_priority_tier"] == "Critical"

    detail = client.get(f"/findings/{finding_id}", headers=headers).json()
    assert detail["final_priority"] == "High"
    assert detail["priority_source"] == "ml+kev_floor"
    assert detail["rule_priority_tier"] == "Critical"
    assert detail["explanation"]["inputs"]["in_kev"] is True


def test_ml_asset_mode_falls_back_to_rules_when_prediction_is_unavailable(api, monkeypatch):
    monkeypatch.setattr(rules_config, "PRIORITY_MODE", "ml_asset")
    seen = {}

    def unavailable(**kwargs):
        seen.update(kwargs)
        return {
            "likelihood": None,
            "risk": None,
            "priority": None,
            "top_reasons": None,
            "model_version": None,
            "recommended_action": None,
            "unavailable_reason": "Frozen model is unavailable.",
        }

    monkeypatch.setattr(main, "predict_exploit_likelihood", unavailable)
    response = api["client"].post(
        "/scan",
        json={
            "asset_id": api["asset_id"],
            "cve_id": "CVE-2025-7003",
            "cvss_score": 9.8,
            "in_kev": False,
            "epss_percentile": 0.0,
        },
        headers=api["headers_for"]("analyst"),
    )
    assert response.status_code == 200
    assert response.json()["final_priority"] == "Critical"
    assert response.json()["priority_source"] == "rules"
    assert response.json()["ml_unavailable_reason"] == "Frozen model is unavailable."
    assert "in_kev" not in seen and "epss_percentile" not in seen


def test_scan_uses_catalog_description_when_live_lookup_is_offline(api, monkeypatch):
    seen = {}
    monkeypatch.setattr(
        main,
        "lookup_catalog",
        lambda db, cve_id: {
            "cve_id": cve_id,
            "description": "Description from the prepared dataset.",
            "cvss_score": 8.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe": "CWE-79",
            "published_date": "2025-01-01",
            "percentile": 0.4,
            "in_kev": False,
        },
    )

    async def offline_lookup(cve_id):
        return {
            "cve_id": cve_id,
            "cvss": None,
            "epss": None,
            "available": False,
            "errors": ["network unavailable"],
            "description": None,
            "cvss_vector": None,
            "cwe": None,
        }

    def advisory(**kwargs):
        seen.update(kwargs)
        return {
            "likelihood": 0.25,
            "risk": 0.25,
            "priority": "High",
            "top_reasons": [],
            "model_version": "test-model",
            "recommended_action": "test",
            "unavailable_reason": None,
        }

    monkeypatch.setattr(main, "fetch_cve_data", offline_lookup)
    monkeypatch.setattr(main, "predict_exploit_likelihood", advisory)
    response = api["client"].post(
        "/scan",
        json={
            "asset_id": api["asset_id"],
            "cve_id": "CVE-2025-7033",
            "cvss_score": 8.0,
            "epss_percentile": 0.4,
        },
        headers=api["headers_for"]("analyst"),
    )

    assert response.status_code == 200
    assert response.json()["ml_likelihood"] == 0.25
    assert seen["description"] == "Description from the prepared dataset."
