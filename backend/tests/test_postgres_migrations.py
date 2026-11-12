import pytest
from sqlalchemy import inspect, text
from sqlalchemy.exc import DBAPIError

from backend.database import engine


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
    assert {"ix_findings_asset_id", "ix_findings_cve_id"} <= finding_indexes


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
            with pytest.raises(DBAPIError, match="immutable"):
                connection.execute(text(statement), {"audit_id": audit_id})
            savepoint.rollback()
        finally:
            transaction.rollback()


def test_postgres_audit_trigger_rejects_truncate():
    with engine.connect() as connection:
        transaction = connection.begin()
        try:
            with pytest.raises(DBAPIError, match="immutable"):
                connection.execute(text("TRUNCATE TABLE audit_logs"))
        finally:
            transaction.rollback()
