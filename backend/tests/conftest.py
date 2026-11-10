import os
import secrets
import tempfile
from pathlib import Path

import pytest

_TEST_DATABASE_DIR = tempfile.TemporaryDirectory(prefix="securevision-tests-")
_TEST_DATABASE_PATH = Path(_TEST_DATABASE_DIR.name) / "tests.db"
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DATABASE_PATH.as_posix()}"
os.environ["SECRET_KEY"] = secrets.token_urlsafe(48)
os.environ["CORS_ORIGINS"] = "http://testserver"


@pytest.fixture(autouse=True)
def clear_login_rate_limit_state():
    from backend.auth import reset_login_failures

    reset_login_failures()
    yield
    reset_login_failures()


def pytest_unconfigure(config):
    from backend.database import engine

    engine.dispose()
    _TEST_DATABASE_DIR.cleanup()
