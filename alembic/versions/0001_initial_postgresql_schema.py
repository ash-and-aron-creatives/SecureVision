"""Create the SecureVision PostgreSQL schema.

Revision ID: 0001_initial
Revises:
"""
from alembic import op
import sqlalchemy as sa


revision = "0001_initial"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("username", sa.String(), nullable=True),
        sa.Column("hashed_password", sa.String(), nullable=True),
        sa.Column("role", sa.String(), nullable=True),
    )
    op.create_index("ix_users_id", "users", ["id"])
    op.create_index("ix_users_username", "users", ["username"], unique=True)

    op.create_table(
        "assets",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(), nullable=True),
        sa.Column("type", sa.String(), nullable=False),
        sa.Column("ip_or_domain", sa.String(), nullable=False),
        sa.Column("owner", sa.String(), nullable=False),
        sa.Column("environment", sa.String(), nullable=False),
        sa.Column("exposure", sa.String(), nullable=True),
        sa.Column("criticality", sa.Integer(), nullable=True),
        sa.Column("needs_review", sa.Boolean(), nullable=False),
    )
    op.create_index("ix_assets_id", "assets", ["id"])
    op.create_index("ix_assets_name", "assets", ["name"])

    op.create_table(
        "cves",
        sa.Column("cve_id", sa.String(), primary_key=True),
        sa.Column("data", sa.JSON(), nullable=False),
    )

    op.create_table(
        "findings",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("asset_id", sa.Integer(), sa.ForeignKey("assets.id"), nullable=True),
        sa.Column("cve_id", sa.String(), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("in_kev", sa.Boolean(), nullable=True),
        sa.Column("status", sa.String(), nullable=True),
        sa.Column("date_found", sa.String(), nullable=True),
    )
    op.create_index("ix_findings_id", "findings", ["id"])
    op.create_index("ix_findings_asset_id", "findings", ["asset_id"])
    op.create_index("ix_findings_cve_id", "findings", ["cve_id"])

    op.create_table(
        "finding_scores",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("finding_id", sa.Integer(), sa.ForeignKey("findings.id"), nullable=True),
        sa.Column("provider_id", sa.Integer(), nullable=True),
        sa.Column("likelihood", sa.Float(), nullable=True),
        sa.Column("priority_tier", sa.String(), nullable=True),
        sa.Column("provenance", sa.JSON(), nullable=True),
        sa.Column("explanation", sa.String(), nullable=True),
        sa.Column("ml_likelihood", sa.Float(), nullable=True),
        sa.Column("ml_risk", sa.Float(), nullable=True),
        sa.Column("ml_priority", sa.String(), nullable=True),
        sa.Column("ml_top_reasons", sa.JSON(), nullable=True),
        sa.Column("ml_model_version", sa.String(), nullable=True),
        sa.Column("ml_recommended_action", sa.String(), nullable=True),
        sa.Column("ml_unavailable_reason", sa.String(), nullable=True),
    )
    op.create_index("ix_finding_scores_id", "finding_scores", ["id"])

    op.create_table(
        "audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
        sa.Column("action", sa.String(), nullable=True),
        sa.Column("details", sa.String(), nullable=True),
        sa.Column("timestamp", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_audit_logs_id", "audit_logs", ["id"])

    op.execute(
        """
        CREATE FUNCTION securevision_reject_audit_log_mutation()
        RETURNS trigger
        LANGUAGE plpgsql
        AS $$
        BEGIN
            RAISE EXCEPTION 'AuditLog records are immutable and cannot be changed.';
        END;
        $$
        """
    )
    op.execute(
        """
        CREATE TRIGGER prevent_audit_log_mutation
        BEFORE UPDATE OR DELETE ON audit_logs
        FOR EACH ROW
        EXECUTE FUNCTION securevision_reject_audit_log_mutation()
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS prevent_audit_log_mutation ON audit_logs")
    op.execute("DROP FUNCTION IF EXISTS securevision_reject_audit_log_mutation()")
    op.drop_index("ix_audit_logs_id", table_name="audit_logs")
    op.drop_table("audit_logs")
    op.drop_index("ix_finding_scores_id", table_name="finding_scores")
    op.drop_table("finding_scores")
    op.drop_index("ix_findings_cve_id", table_name="findings")
    op.drop_index("ix_findings_asset_id", table_name="findings")
    op.drop_index("ix_findings_id", table_name="findings")
    op.drop_table("findings")
    op.drop_index("ix_assets_name", table_name="assets")
    op.drop_index("ix_assets_id", table_name="assets")
    op.drop_table("assets")
    op.drop_table("cves")
    op.drop_index("ix_users_username", table_name="users")
    op.drop_index("ix_users_id", table_name="users")
    op.drop_table("users")
