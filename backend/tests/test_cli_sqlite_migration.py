import subprocess
import sys
from pathlib import Path


def test_cli_reports_invalid_source_url_without_traceback():
    repository_root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [
            sys.executable,
            "scripts/sqlite_to_postgres.py",
            "postgresql://invalid",
            "sqlite:///not-created.db",
        ],
        cwd=repository_root,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 2
    assert "The source URL must use SQLite." in result.stderr
    assert "Traceback" not in result.stderr
    assert not (repository_root / "not-created.db").exists()
