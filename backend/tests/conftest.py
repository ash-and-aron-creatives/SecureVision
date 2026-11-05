import os
import secrets
import tempfile
from pathlib import Path


_TEST_DATABASE_DIR = tempfile.TemporaryDirectory(prefix="securevision-tests-")
_TEST_DATABASE_PATH = Path(_TEST_DATABASE_DIR.name) / "tests.db"
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DATABASE_PATH.as_posix()}"
os.environ["SECRET_KEY"] = secrets.token_urlsafe(48)
os.environ["CORS_ORIGINS"] = "http://testserver"


def pytest_unconfigure(config):
    from backend.database import engine

    engine.dispose()
    _TEST_DATABASE_DIR.cleanup()
