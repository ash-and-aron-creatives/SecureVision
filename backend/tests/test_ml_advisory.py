import json
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
    criticality_factor,
    exposure_factor,
    ml_priority,
)
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


def test_scan_uses_prepared_dataset_description_when_live_lookup_is_offline(api, monkeypatch):
    seen = {}
    monkeypatch.setattr(main, "dataset_available", lambda: True)
    monkeypatch.setattr(
        main,
        "lookup_cve",
        lambda cve_id, dataset_path: {
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
