import os

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.orm import declarative_base, sessionmaker


SQLALCHEMY_DATABASE_URL = os.environ.get("DATABASE_URL")
if not SQLALCHEMY_DATABASE_URL:
    raise RuntimeError("DATABASE_URL must be set to a PostgreSQL connection URL.")
if (
    make_url(SQLALCHEMY_DATABASE_URL).get_backend_name() != "postgresql"
    and os.getenv("SECUREVISION_TESTING") != "1"
):
    raise RuntimeError("SecureVision requires PostgreSQL outside its isolated test suite.")

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
