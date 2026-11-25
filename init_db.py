raise SystemExit("This legacy entry point is disabled. Run `python -m backend.init_db` instead.")

from backend.init_db import seed_database


if __name__ == "__main__":
    seed_database()
