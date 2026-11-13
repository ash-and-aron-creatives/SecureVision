import os
import uuid

from sqlalchemy import create_engine
from sqlalchemy.engine import make_url


_test_engines = []


def create_test_engine():
    database_url = os.environ["DATABASE_URL"]
    url = make_url(database_url)
    if url.get_backend_name() != "postgresql":
        raise RuntimeError("Test fixtures require PostgreSQL.")

    schema = f"sv_test_{uuid.uuid4().hex}"
    admin_engine = create_engine(os.environ["MIGRATION_DATABASE_URL"])
    try:
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
            app_role = url.username
            quoted_app_role = connection.dialect.identifier_preparer.quote(app_role)
            connection.exec_driver_sql(
                f'GRANT USAGE, CREATE ON SCHEMA "{schema}" TO {quoted_app_role}'
            )
    finally:
        admin_engine.dispose()
    engine = create_engine(
        database_url,
        connect_args={"options": f"-csearch_path={schema}"},
    )
    setattr(engine, "_securevision_test_schema", schema)

    _test_engines.append(engine)
    return engine


def dispose_test_engines(start_index):
    database_url = os.environ["DATABASE_URL"]
    for engine in reversed(_test_engines[start_index:]):
        schema = getattr(engine, "_securevision_test_schema", None)
        engine.dispose()
        if schema:
            admin_engine = create_engine(os.environ["MIGRATION_DATABASE_URL"])
            try:
                with admin_engine.begin() as connection:
                    connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
            finally:
                admin_engine.dispose()
    del _test_engines[start_index:]
