import pytest

from backend.demo_seed import seed_synthetic_demo
from backend import rules_config
from backend.rules_config import SYNTHETIC_DEMO_ASSETS, SYNTHETIC_DEMO_FINDINGS
from backend.scoring_engine import calculate_priority, resolve_final_priority


def test_synthetic_seed_refuses_non_demo_database(monkeypatch):
    monkeypatch.setenv("SECUREVISION_DEMO_MODE", "false")

    with pytest.raises(RuntimeError, match="SECUREVISION_DEMO_MODE=true"):
        seed_synthetic_demo()


def test_synthetic_seed_has_eight_assets_and_four_rule_matrix_tiers(monkeypatch):
    assert len(SYNTHETIC_DEMO_ASSETS) == 8
    assert len(SYNTHETIC_DEMO_FINDINGS) == 40

    assets = {asset["name"]: asset for asset in SYNTHETIC_DEMO_ASSETS}
    for mode in ("deterministic", "ml_asset"):
        monkeypatch.setattr(rules_config, "PRIORITY_MODE", mode)
        tiers = set()
        for finding in SYNTHETIC_DEMO_FINDINGS:
            asset = assets[finding["asset_name"]]
            score = calculate_priority(
                finding["in_kev"],
                asset["exposure"].casefold() == "internet",
                asset["criticality"],
                finding["epss_percentile"],
                finding["cvss_score"],
            )
            final_tier, _ = resolve_final_priority(score["tier"], None, finding["in_kev"])
            tiers.add(final_tier)
        assert tiers == {"Critical", "High", "Medium", "Low"}
