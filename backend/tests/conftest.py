import os
import secrets
import tempfile
from pathlib import Path

import pytest

_TEST_DATABASE_DIR = tempfile.TemporaryDirectory(prefix="securevision-tests-")
_TEST_DATABASE_PATH = Path(_TEST_DATABASE_DIR.name) / "tests.db"
if os.getenv("SECUREVISION_POSTGRES_TESTS") == "1":
    if not os.getenv("DATABASE_URL", "").startswith("postgresql"):
        raise RuntimeError(
            "SECUREVISION_POSTGRES_TESTS=1 requires a PostgreSQL DATABASE_URL."
        )
else:
    os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DATABASE_PATH.as_posix()}"
os.environ["SECUREVISION_TESTING"] = "1"
os.environ.setdefault("SECRET_KEY", secrets.token_urlsafe(48))
os.environ.setdefault("CORS_ORIGINS", "http://testserver")


@pytest.fixture(scope="session", autouse=True)
def ensure_postgres_schema():
    if os.getenv("SECUREVISION_POSTGRES_TESTS") == "1":
        from alembic import command
        from alembic.config import Config
        from sqlalchemy.engine import make_url

        if make_url(os.environ["DATABASE_URL"]).get_backend_name() != "postgresql":
            raise RuntimeError("The PostgreSQL test URL must use the PostgreSQL dialect.")
        command.upgrade(Config("alembic.ini"), "head")


@pytest.fixture(autouse=True)
def cleanup_test_engines():
    from backend.tests.db_helpers import _test_engines, dispose_test_engines

    start_index = len(_test_engines)
    yield
    dispose_test_engines(start_index)


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
