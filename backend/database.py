from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

SQLALCHEMY_DATABASE_URL = "sqlite:///./securevision.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
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
