import os

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import declarative_base, sessionmaker


SQLALCHEMY_DATABASE_URL = os.environ.get("DATABASE_URL")
if not SQLALCHEMY_DATABASE_URL:
    raise SystemExit(
        "DATABASE_URL must be set to a PostgreSQL connection URL. "
        "Run .\\setup_dev.ps1 for local development or set DATABASE_URL explicitly."
    )
if (
    make_url(SQLALCHEMY_DATABASE_URL).get_backend_name() != "postgresql"
    and os.getenv("SECUREVISION_TESTING") != "1"
):
    raise SystemExit(
        "SecureVision requires PostgreSQL. Set DATABASE_URL to a "
        "postgresql+psycopg2:// URL or run .\\setup_dev.ps1; SQLite is supported "
        "only by the isolated test suite."
    )

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
