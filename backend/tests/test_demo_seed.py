import pytest

from backend.demo_seed import seed_synthetic_demo


def test_synthetic_seed_refuses_non_demo_database(monkeypatch):
    monkeypatch.setenv("SECUREVISION_DEMO_MODE", "false")

    with pytest.raises(RuntimeError, match="SECUREVISION_DEMO_MODE=true"):
        seed_synthetic_demo()
