import os
import subprocess
import sys
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.engine import make_url
from sqlalchemy.orm import sessionmaker

from backend import auth, main
from backend.database import Base, engine, get_db
from backend.models import Asset, Finding, User
from backend.tests.db_helpers import create_test_engine


pytestmark = pytest.mark.skipif(
    engine.dialect.name != "postgresql",
    reason="PostgreSQL migration and trigger integration tests require PostgreSQL.",
)


def test_initial_migration_creates_current_models_and_blueprint_indexes():
    inspector = inspect(engine)
    asset_columns = {column["name"] for column in inspector.get_columns("assets")}
    score_columns = {
        column["name"] for column in inspector.get_columns("finding_scores")
    }
    finding_indexes = {
        index["name"] for index in inspector.get_indexes("findings")
    }
    asset_indexes = {
        index["name"]: index for index in inspector.get_indexes("assets")
    }
    finding_constraints = {
        constraint["name"]
        for constraint in inspector.get_unique_constraints("findings")
    }

    assert {
        "type",
        "ip_or_domain",
        "owner",
        "environment",
        "needs_review",
    } <= asset_columns
    assert {
        "ml_likelihood",
        "ml_risk",
        "ml_priority",
        "ml_top_reasons",
        "ml_model_version",
        "ml_recommended_action",
        "ml_unavailable_reason",
    } <= score_columns
    assert {"final_priority", "priority_source"} <= {
        column["name"] for column in inspector.get_columns("findings")
    }
    assert {
        "ix_findings_asset_id",
        "ix_findings_cve_id",
        "ix_findings_final_priority",
    } <= finding_indexes
    assert asset_indexes["uq_assets_name_ci"]["unique"] is True
    assert "uq_findings_asset_cve" in finding_constraints


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE audit_logs SET action = 'MUTATED' WHERE id = :audit_id",
        "DELETE FROM audit_logs WHERE id = :audit_id",
    ],
)
def test_postgres_audit_trigger_rejects_update_and_delete(statement):
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            audit_id = connection.execute(
                text(
                    "INSERT INTO audit_logs (action, details) "
                    "VALUES ('IMMUTABILITY_TEST', 'rolled back') RETURNING id"
                )
            ).scalar_one()
            savepoint = connection.begin_nested()
            with pytest.raises(DBAPIError, match="immutable|permission denied"):
                connection.execute(text(statement), {"audit_id": audit_id})
            savepoint.rollback()
        finally:
            transaction.rollback()


def test_postgres_audit_trigger_rejects_truncate():
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            with pytest.raises(DBAPIError, match="immutable|permission denied"):
                connection.execute(text("TRUNCATE TABLE audit_logs"))
        finally:
            transaction.rollback()


def test_postgres_app_role_is_not_superuser_and_cannot_change_schema_or_audit():
    with engine.connect() as connection:
        role = connection.execute(
            text(
                "SELECT r.rolsuper, r.rolcreatedb, r.rolcreaterole "
                "FROM pg_roles r WHERE r.rolname = current_user"
            )
        ).one()
        assert role == (False, False, False)
        connection.rollback()

        statements = [
            "UPDATE audit_logs SET action = 'MUTATED'",
            "DELETE FROM audit_logs",
            "TRUNCATE TABLE audit_logs",
            "DROP TRIGGER IF EXISTS prevent_audit_log_mutation ON audit_logs",
            "ALTER TABLE assets ADD COLUMN app_role_forbidden integer",
            "CREATE TABLE app_role_forbidden (id integer)",
            "UPDATE alembic_version SET version_num = '0001_initial'",
        ]
        transaction = connection.begin()
        try:
            for statement in statements:
                savepoint = connection.begin_nested()
                with pytest.raises(DBAPIError, match="permission denied|must be owner|not owner"):
                    connection.execute(text(statement))
                savepoint.rollback()
        finally:
            transaction.rollback()


def test_postgres_default_privileges_restrict_future_tables():
    migration_url = os.environ.get("MIGRATION_DATABASE_URL")
    assert migration_url, "PostgreSQL integration configuration must provide the owner URL."
    table_name = f"sv_default_acl_{uuid.uuid4().hex}"
    owner_engine = create_engine(migration_url)
    try:
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(
                f'CREATE TABLE public."{table_name}" (id serial PRIMARY KEY)'
            )

        with engine.connect() as connection:
            privileges = connection.execute(
                text(
                    "SELECT "
                    "has_table_privilege(current_user, :table_name, 'SELECT'), "
                    "has_table_privilege(current_user, :table_name, 'INSERT'), "
                    "has_table_privilege(current_user, :table_name, 'UPDATE'), "
                    "has_table_privilege(current_user, :table_name, 'DELETE'), "
                    "has_table_privilege(current_user, :table_name, 'TRUNCATE'), "
                    "has_schema_privilege(current_user, 'public', 'CREATE'), "
                    "has_sequence_privilege(current_user, :sequence_name, 'USAGE')"
                ),
                {
                    "table_name": f"public.{table_name}",
                    "sequence_name": f"public.{table_name}_id_seq",
                },
            ).one()
        assert privileges == (True, True, True, True, False, False, True)
    finally:
        with owner_engine.begin() as connection:
            connection.exec_driver_sql(f'DROP TABLE IF EXISTS public."{table_name}"')
        owner_engine.dispose()


def test_postgres_app_role_has_dml_access_to_final_priority_columns():
    with engine.connect() as connection:
        privileges = connection.execute(
            text(
                "SELECT "
                "has_column_privilege(current_user, 'findings', 'final_priority', 'SELECT'), "
                "has_column_privilege(current_user, 'findings', 'final_priority', 'INSERT'), "
                "has_column_privilege(current_user, 'findings', 'final_priority', 'UPDATE'), "
                "has_column_privilege(current_user, 'findings', 'priority_source', 'SELECT'), "
                "has_column_privilege(current_user, 'findings', 'priority_source', 'INSERT'), "
                "has_column_privilege(current_user, 'findings', 'priority_source', 'UPDATE')"
            )
        ).one()
    assert privileges == (True, True, True, True, True, True)


def test_final_priority_migration_backfills_existing_rows(monkeypatch):
    schema = f"sv_migration_{uuid.uuid4().hex}"
    owner_url = make_url(os.environ["MIGRATION_DATABASE_URL"])
    app_url = make_url(os.environ["DATABASE_URL"])
    admin_engine = create_engine(owner_url)
    with admin_engine.begin() as connection:
        connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')

    scoped_owner_url = owner_url.update_query_dict(
        {"options": f"-c search_path={schema}"}
    )
    scoped_app_url = app_url.update_query_dict(
        {"options": f"-c search_path={schema}"}
    )
    monkeypatch.setenv(
        "MIGRATION_DATABASE_URL",
        scoped_owner_url.render_as_string(hide_password=False),
    )
    monkeypatch.setenv(
        "DATABASE_URL",
        scoped_app_url.render_as_string(hide_password=False),
    )
    try:
        command.upgrade(Config("alembic.ini"), "0003_app_constraints")
        scoped_engine = create_engine(scoped_owner_url)
        try:
            with scoped_engine.begin() as connection:
                assert connection.execute(
                    text("SELECT current_schema()")
                ).scalar_one() == schema
                asset_id = connection.execute(
                    text(
                        "INSERT INTO assets "
                        "(name, type, ip_or_domain, owner, environment, needs_review, exposure, criticality) "
                        "VALUES (:name, 'Other', '', '', 'Unknown', false, 'Internet', 5) "
                        "RETURNING id"
                    ),
                    {"name": f"migration-backfill-{uuid.uuid4().hex}"},
                ).scalar_one()
                scored_id = connection.execute(
                    text(
                        "INSERT INTO findings (asset_id, cve_id, status, cvss_score) "
                        "VALUES (:asset_id, 'CVE-2099-8001', 'Open', 6.0) RETURNING id"
                    ),
                    {"asset_id": asset_id},
                ).scalar_one()
                unscored_id = connection.execute(
                    text(
                        "INSERT INTO findings (asset_id, cve_id, status, cvss_score) "
                        "VALUES (:asset_id, 'CVE-2099-8002', 'Open', 9.8) RETURNING id"
                    ),
                    {"asset_id": asset_id},
                ).scalar_one()
                connection.execute(
                    text(
                        "INSERT INTO finding_scores (finding_id, priority_tier) "
                        "VALUES (:finding_id, 'High')"
                    ),
                    {"finding_id": scored_id},
                )
            command.upgrade(Config("alembic.ini"), "head")
            with scoped_engine.connect() as connection:
                rows = connection.execute(
                    text(
                        "SELECT id, final_priority, priority_source "
                        "FROM findings ORDER BY id"
                    )
                ).all()
            assert rows == [
                (scored_id, "High", "rules"),
                (unscored_id, "Critical", "rules"),
            ]
        finally:
            scoped_engine.dispose()
    finally:
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA "{schema}" CASCADE')
            app_role = admin_engine.dialect.identifier_preparer.quote(app_url.username)
            connection.exec_driver_sql(
                f"REVOKE ALL ON TABLE public.cve_catalog FROM {app_role}"
            )
            connection.exec_driver_sql(
                f"GRANT SELECT ON TABLE public.cve_catalog TO {app_role}"
            )
        admin_engine.dispose()


def test_postgres_enforces_case_insensitive_assets_and_finding_pairs():
    name = f"unique-check-{uuid.uuid4().hex}"
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            asset_id = connection.execute(
                text(
                    "INSERT INTO assets "
                    "(name, type, ip_or_domain, owner, environment, needs_review) "
                    "VALUES (:name, 'Other', '', '', 'Unknown', false) RETURNING id"
                ),
                {"name": name},
            ).scalar_one()
            savepoint = connection.begin_nested()
            with pytest.raises(DBAPIError, match="duplicate key|unique"):
                connection.execute(
                    text(
                        "INSERT INTO assets "
                        "(name, type, ip_or_domain, owner, environment, needs_review) "
                        "VALUES (:name, 'Other', '', '', 'Unknown', false)"
                    ),
                    {"name": name.swapcase()},
                )
            savepoint.rollback()

            connection.execute(
                text(
                    "INSERT INTO findings (asset_id, cve_id, status) "
                    "VALUES (:asset_id, 'CVE-2099-90991', 'Open')"
                ),
                {"asset_id": asset_id},
            )
            savepoint = connection.begin_nested()
            with pytest.raises(DBAPIError, match="duplicate key|unique"):
                connection.execute(
                    text(
                        "INSERT INTO findings (asset_id, cve_id, status) "
                        "VALUES (:asset_id, 'CVE-2099-90991', 'Open')"
                    ),
                    {"asset_id": asset_id},
                )
            savepoint.rollback()
        finally:
            transaction.rollback()


@pytest.fixture
def postgres_api():
    test_engine = create_test_engine()
    Base.metadata.create_all(bind=test_engine)
    test_sessions = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)
    with test_sessions() as session:
        user = User(
            username=f"pg-race-{uuid.uuid4().hex}",
            hashed_password=auth.get_password_hash("test-password"),
            role="analyst",
        )
        asset = Asset(
            name=f"pg-race-asset-{uuid.uuid4().hex}",
            exposure="Internal",
            criticality=3,
        )
        session.add_all([user, asset])
        session.commit()
        user_name, asset_id = user.username, asset.id

    def override_get_db():
        session = test_sessions()
        try:
            yield session
        finally:
            session.close()

    previous_overrides = dict(main.app.dependency_overrides)
    main.app.dependency_overrides[get_db] = override_get_db
    headers = {
        "Authorization": f"Bearer {auth.create_access_token({'sub': user_name})}"
    }
    try:
        with TestClient(main.app) as client:
            yield client, test_sessions, asset_id, headers
    finally:
        main.app.dependency_overrides.clear()
        main.app.dependency_overrides.update(previous_overrides)
        test_engine.dispose()


def test_postgres_concurrent_scans_upsert_one_finding(postgres_api, monkeypatch):
    client, test_sessions, asset_id, headers = postgres_api
    barrier = threading.Barrier(2)

    async def synchronized_intel(cve_id):
        import asyncio

        await asyncio.to_thread(barrier.wait, timeout=10)
        return {
            "cve_id": cve_id,
            "epss": 0.4,
            "cvss": 8.0,
            "available": True,
            "errors": [],
            "description": "Concurrent scan description.",
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe": "CWE-79",
            "published_date": "2025-01-01",
        }

    monkeypatch.setattr(main, "fetch_cve_data", synchronized_intel)
    monkeypatch.setattr(
        main,
        "predict_exploit_likelihood",
        lambda **kwargs: {
            "likelihood": None,
            "risk": None,
            "priority": None,
            "top_reasons": None,
            "model_version": None,
            "recommended_action": None,
            "unavailable_reason": "test",
        },
    )
    payload = {
        "asset_id": asset_id,
        "cve_id": "CVE-2099-90992",
        "cvss_score": 8.0,
        "epss_percentile": 0.4,
    }
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(
            pool.map(
                lambda _: client.post("/scan", json=payload, headers=headers),
                range(2),
            )
        )

    assert [response.status_code for response in responses] == [200, 200]
    assert {response.json()["action"] for response in responses} == {"created", "updated"}
    assert len({response.json()["finding_id"] for response in responses}) == 1
    with test_sessions() as session:
        finding = (
            session.query(Finding)
            .filter_by(asset_id=asset_id, cve_id=payload["cve_id"])
            .one()
        )
        assert len(finding.scores) == 2


def test_postgres_csv_import_skips_duplicate_rows_in_one_file(postgres_api, monkeypatch):
    client, test_sessions, asset_id, headers = postgres_api
    with test_sessions() as session:
        asset_name = session.get(Asset, asset_id).name

    async def available_intel(cve_id):
        return {
            "cve_id": cve_id,
            "epss": 0.4,
            "cvss": 8.0,
            "available": True,
            "errors": [],
            "description": "CSV duplicate test description.",
            "cvss_vector": "CVSS:3.1/AV:N",
            "cwe": "CWE-79",
            "published_date": "2025-01-01",
        }

    monkeypatch.setattr(main, "fetch_cve_data", available_intel)
    monkeypatch.setattr(
        main,
        "predict_exploit_likelihood",
        lambda **kwargs: {
            "likelihood": None,
            "risk": None,
            "priority": None,
            "top_reasons": None,
            "model_version": None,
            "recommended_action": None,
            "unavailable_reason": "test",
        },
    )
    csv_content = (
        f"asset_name,cve_id,date_found\n{asset_name},CVE-2099-90993,2026-10-01\n"
        f"{asset_name},CVE-2099-90993,2026-10-02\n"
    ).encode()
    response = client.post(
        "/imports/commit",
        files={"file": ("duplicate.csv", csv_content, "text/csv")},
        headers=headers,
    )
    assert response.status_code == 200
    assert response.json()["imported"] == 1
    assert response.json()["skipped"] == 1
    assert "Repeated in this file." in response.json()["problems_csv"]

    with test_sessions() as session:
        assert session.query(Finding).filter_by(
            asset_id=asset_id, cve_id="CVE-2099-90993"
        ).count() == 1


def test_postgres_concurrent_csv_import_returns_readable_conflict(postgres_api, monkeypatch):
    client, test_sessions, asset_id, headers = postgres_api
    with test_sessions() as session:
        asset_name = session.get(Asset, asset_id).name

    barrier = threading.Barrier(2)

    async def synchronized_intel(cve_id):
        import asyncio

        await asyncio.to_thread(barrier.wait, timeout=10)
        return {
            "cve_id": cve_id,
            "epss": 0.4,
            "cvss": 8.0,
            "available": True,
            "errors": [],
            "description": "Concurrent CSV import description.",
            "cvss_vector": "CVSS:3.1/AV:N",
            "cwe": "CWE-79",
            "published_date": "2025-01-01",
        }

    monkeypatch.setattr(main, "fetch_cve_data", synchronized_intel)
    monkeypatch.setattr(
        main,
        "predict_exploit_likelihood",
        lambda **kwargs: {
            "likelihood": None,
            "risk": None,
            "priority": None,
            "top_reasons": None,
            "model_version": None,
            "recommended_action": None,
            "unavailable_reason": "test",
        },
    )
    csv_content = (
        f"asset_name,cve_id,date_found\n{asset_name},CVE-2099-90995,2026-10-01\n"
    ).encode()

    def commit_import(_):
        return client.post(
            "/imports/commit",
            files={"file": ("race.csv", csv_content, "text/csv")},
            headers=headers,
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        responses = list(pool.map(commit_import, range(2)))

    assert sorted(response.status_code for response in responses) == [200, 409]
    conflict = next(response for response in responses if response.status_code == 409)
    assert "created concurrently" in conflict.json()["detail"]
    with test_sessions() as session:
        assert session.query(Finding).filter_by(
            asset_id=asset_id, cve_id="CVE-2099-90995"
        ).count() == 1


def test_postgres_dedupe_script_defaults_to_dry_run_and_merges_scores():
    migration_url = os.environ.get("MIGRATION_DATABASE_URL")
    assert migration_url, "PostgreSQL integration configuration must provide the owner URL."
    schema = f"sv_dedupe_script_{uuid.uuid4().hex}"
    base_url = make_url(migration_url)
    admin_engine = create_engine(migration_url)
    try:
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        scoped_url = base_url.set(query={"options": f"-csearch_path={schema}"})
        scoped_engine = create_engine(scoped_url)
        try:
            with scoped_engine.begin() as connection:
                connection.exec_driver_sql(
                    "CREATE TABLE findings (id integer PRIMARY KEY, asset_id integer, cve_id text)"
                )
                connection.exec_driver_sql(
                    "CREATE TABLE finding_scores (id integer PRIMARY KEY, "
                    "finding_id integer REFERENCES findings(id), explanation text)"
                )
                connection.exec_driver_sql(
                    "INSERT INTO findings (id, asset_id, cve_id) VALUES "
                    "(1, 7, 'CVE-2099-90996'), (2, 7, 'CVE-2099-90996')"
                )
                connection.exec_driver_sql(
                    "INSERT INTO finding_scores (id, finding_id, explanation) VALUES "
                    "(1, 1, 'old history'), (2, 2, 'new history')"
                )

            repository_root = Path(__file__).resolve().parents[2]
            script = repository_root / "scripts" / "dedupe_postgres.py"
            scoped_database_url = scoped_url.render_as_string(hide_password=False)
            command_args = [sys.executable, str(script), scoped_database_url]
            dry_run = subprocess.run(
                command_args,
                cwd=repository_root,
                check=True,
                capture_output=True,
                text=True,
            )
            assert "DRY RUN: no changes made" in dry_run.stdout
            with scoped_engine.connect() as connection:
                assert connection.exec_driver_sql("SELECT count(*) FROM findings").scalar_one() == 2

            applied = subprocess.run(
                [*command_args, "--apply"],
                cwd=repository_root,
                check=True,
                capture_output=True,
                text=True,
            )
            assert "Applied duplicate finding merges" in applied.stdout
            with scoped_engine.connect() as connection:
                assert connection.exec_driver_sql("SELECT id FROM findings").scalar_one() == 1
                assert connection.exec_driver_sql(
                    "SELECT array_agg(finding_id ORDER BY id) FROM finding_scores"
                ).scalar_one() == [1, 1]
        finally:
            scoped_engine.dispose()
    finally:
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        admin_engine.dispose()


def test_postgres_migration_reports_existing_duplicates():
    migration_url = os.environ.get("MIGRATION_DATABASE_URL")
    assert migration_url, "PostgreSQL integration configuration must provide the owner URL."
    schema = f"sv_migration_duplicates_{uuid.uuid4().hex}"
    base_url = make_url(migration_url)
    admin_engine = create_engine(migration_url)
    try:
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(f'CREATE SCHEMA "{schema}"')
        scoped_url = base_url.set(query={"options": f"-csearch_path={schema}"})
        os.environ["MIGRATION_DATABASE_URL"] = scoped_url.render_as_string(
            hide_password=False
        )
        command.upgrade(Config("alembic.ini"), "0002_audit_truncate")

        scoped_engine = create_engine(scoped_url)
        try:
            with scoped_engine.begin() as connection:
                first_asset = connection.execute(
                    text(
                        "INSERT INTO assets "
                        "(name, type, ip_or_domain, owner, environment, needs_review) "
                        "VALUES ('Migration-duplicate', 'Other', '', '', 'Unknown', false) "
                        "RETURNING id"
                    )
                ).scalar_one()
                connection.execute(
                    text(
                        "INSERT INTO assets "
                        "(name, type, ip_or_domain, owner, environment, needs_review) "
                        "VALUES ('migration-DUPLICATE', 'Other', '', '', 'Unknown', false)"
                    )
                )
                connection.execute(
                    text(
                        "INSERT INTO findings (asset_id, cve_id, status) "
                        "VALUES (:asset_id, 'CVE-2099-90994', 'Open'), "
                        "(:asset_id, 'CVE-2099-90994', 'Open')"
                    ),
                    {"asset_id": first_asset},
                )
        finally:
            scoped_engine.dispose()

        with pytest.raises(RuntimeError, match="Migration 0003 aborted") as error:
            command.upgrade(Config("alembic.ini"), "head")
        message = str(error.value)
        assert "Migration-duplicate" in message
        assert "CVE-2099-90994" in message
        assert "scripts/dedupe_postgres.py" in message
    finally:
        os.environ["MIGRATION_DATABASE_URL"] = migration_url
        with admin_engine.begin() as connection:
            connection.exec_driver_sql(f'DROP SCHEMA IF EXISTS "{schema}" CASCADE')
        admin_engine.dispose()


def test_app_role_can_select_but_cannot_write_cve_catalog():
    with engine.connect() as connection:
        privileges = connection.execute(
            text(
                """
                SELECT has_table_privilege(current_user, 'public.cve_catalog', 'SELECT'),
                       has_table_privilege(current_user, 'public.cve_catalog', 'INSERT'),
                       has_table_privilege(current_user, 'public.cve_catalog', 'UPDATE'),
                       has_table_privilege(current_user, 'public.cve_catalog', 'DELETE')
                """
            )
        ).one()
        assert privileges == (True, False, False, False)
        with pytest.raises(DBAPIError, match="permission denied"):
            connection.execute(
                text(
                    "INSERT INTO public.cve_catalog (cve_id, in_kev) "
                    "VALUES ('CVE-2099-90001', false)"
                )
            )
        connection.rollback()
