import pytest

from backend.demo_seed import seed_synthetic_demo


def test_synthetic_seed_refuses_non_demo_database(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "sqlite:///./securevision_dev.db")

    with pytest.raises(RuntimeError, match="restricted to /data/securevision_demo.db"):
        seed_synthetic_demo()
