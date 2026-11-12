"""Prevent truncation of audit logs.

Revision ID: 0002_audit_truncate
Revises: 0001_initial
"""
from alembic import op


revision = "0002_audit_truncate"
down_revision = "0001_initial"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TRIGGER prevent_audit_log_truncate
        BEFORE TRUNCATE ON audit_logs
        FOR EACH STATEMENT
        EXECUTE FUNCTION securevision_reject_audit_log_mutation()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS prevent_audit_log_truncate ON audit_logs")
