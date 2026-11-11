import os
import uuid

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url
from sqlalchemy.pool import StaticPool


_test_engines = []


def create_test_engine():
    database_url = os.environ["DATABASE_URL"]
    url = make_url(database_url)

    if url.get_backend_name() == "sqlite":
        engine = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
    elif url.get_backend_name() == "postgresql":
        schema = f"sv_test_{uuid.uuid4().hex}"
        admin_engine = create_engine(database_url)
        try:
            with admin_engine.begin() as connection:
                connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        finally:
            admin_engine.dispose()
        engine = create_engine(
            database_url,
            connect_args={"options": f"-csearch_path={schema}"},
        )
        setattr(engine, "_securevision_test_schema", schema)
    else:
        raise RuntimeError("Tests require SQLite or PostgreSQL.")

    _test_engines.append(engine)
    return engine


def dispose_test_engines(start_index):
    database_url = os.environ["DATABASE_URL"]
    for engine in reversed(_test_engines[start_index:]):
        schema = getattr(engine, "_securevision_test_schema", None)
        engine.dispose()
        if schema:
            admin_engine = create_engine(database_url)
            try:
                with admin_engine.begin() as connection:
                    connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
            finally:
                admin_engine.dispose()
    del _test_engines[start_index:]
