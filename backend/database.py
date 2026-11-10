import os

from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import sessionmaker, declarative_base

SQLALCHEMY_DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./securevision.db")
connect_args = {"check_same_thread": False} if SQLALCHEMY_DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args=connect_args)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

from sqlalchemy import event

@event.listens_for(engine, "connect")
def _install_sqlite_audit_triggers(dbapi_conn, connection_record):
    cursor = dbapi_conn.cursor()
    table_exists = cursor.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='audit_logs'"
    ).fetchone()
    if table_exists:
        cursor.execute('''
        CREATE TRIGGER IF NOT EXISTS prevent_audit_update
        BEFORE UPDATE ON audit_logs
        BEGIN
            SELECT RAISE(ABORT, 'Database Trigger: AuditLog records are strictly immutable.');
        END;
        ''')
        cursor.execute('''
        CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
        BEFORE DELETE ON audit_logs
        BEGIN
            SELECT RAISE(ABORT, 'Database Trigger: AuditLog records are strictly immutable.');
        END;
        ''')
    cursor.close()


@event.listens_for(Base.metadata, "after_create")
def _install_new_database_audit_triggers(metadata, connection, **kwargs):
    if connection.dialect.name != "sqlite":
        return
    connection.exec_driver_sql('''
        CREATE TRIGGER IF NOT EXISTS prevent_audit_update
        BEFORE UPDATE ON audit_logs
        BEGIN
            SELECT RAISE(ABORT, 'Database Trigger: AuditLog records are strictly immutable.');
        END;
    ''')
    connection.exec_driver_sql('''
        CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
        BEFORE DELETE ON audit_logs
        BEGIN
            SELECT RAISE(ABORT, 'Database Trigger: AuditLog records are strictly immutable.');
        END;
    ''')


def migrate_finding_score_ml_columns(target_engine=engine) -> None:
    columns = {
        column["name"]
        for column in inspect(target_engine).get_columns("finding_scores")
    }
    additions = {
        "ml_likelihood": "FLOAT",
        "ml_risk": "FLOAT",
        "ml_priority": "VARCHAR",
        "ml_top_reasons": "JSON",
        "ml_model_version": "VARCHAR",
        "ml_recommended_action": "VARCHAR",
        "ml_unavailable_reason": "VARCHAR",
    }
    with target_engine.begin() as connection:
        for name, column_type in additions.items():
            if name not in columns:
                connection.exec_driver_sql(
                    f"ALTER TABLE finding_scores ADD COLUMN {name} {column_type}"
                )
                columns.add(name)


def migrate_asset_columns(target_engine=engine) -> None:
    if "assets" not in inspect(target_engine).get_table_names():
        return
    columns = {
        column["name"]
        for column in inspect(target_engine).get_columns("assets")
    }
    additions = {
        "type": "VARCHAR NOT NULL DEFAULT 'Other'",
        "ip_or_domain": "VARCHAR NOT NULL DEFAULT ''",
        "owner": "VARCHAR NOT NULL DEFAULT ''",
        "environment": "VARCHAR NOT NULL DEFAULT 'Unknown'",
    }
    with target_engine.begin() as connection:
        for name, column_type in additions.items():
            if name not in columns:
                connection.exec_driver_sql(
                    f"ALTER TABLE assets ADD COLUMN {name} {column_type}"
                )
