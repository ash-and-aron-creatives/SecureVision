"""Persist final priority and its source.

Revision ID: 0004_final_priority
Revises: 0003_app_constraints
"""
import os

from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine import make_url


revision = "0004_final_priority"
down_revision = "0003_app_constraints"
branch_labels = None
depends_on = None


def upgrade() -> None:
    app_url = os.environ.get("DATABASE_URL")
    if not app_url:
        raise RuntimeError("DATABASE_URL must identify the runtime app role during migration.")
    app_role = make_url(app_url).username
    if not app_role:
        raise RuntimeError("DATABASE_URL must include the runtime app role username.")

    connection = op.get_bind()
    owner_role = connection.execute(sa.text("SELECT current_user")).scalar_one()
    preparer = connection.dialect.identifier_preparer
    quoted_app_role = preparer.quote(app_role)
    quoted_owner_role = preparer.quote(owner_role)

    op.add_column(
        "findings",
        sa.Column("final_priority", sa.String(), nullable=False, server_default="Low"),
    )
    op.add_column(
        "findings",
        sa.Column("priority_source", sa.String(), nullable=False, server_default="rules"),
    )
    op.execute(
        """
        UPDATE findings AS finding
        SET final_priority = COALESCE(
            (
                SELECT score.priority_tier
                FROM finding_scores AS score
                WHERE score.finding_id = finding.id
                ORDER BY score.id DESC
                LIMIT 1
            ),
            CASE
                WHEN COALESCE(finding.in_kev, false) THEN
                    CASE
                        WHEN COALESCE((
                            SELECT lower(asset.exposure)
                            FROM assets AS asset
                            WHERE asset.id = finding.asset_id
                        ), 'internal') = 'internet'
                            OR COALESCE((
                                SELECT asset.criticality
                                FROM assets AS asset
                                WHERE asset.id = finding.asset_id
                            ), 1) >= 4
                        THEN 'Critical'
                        ELSE 'High'
                    END
                WHEN COALESCE((
                    SELECT score.likelihood
                    FROM finding_scores AS score
                    WHERE score.finding_id = finding.id
                    ORDER BY score.id DESC
                    LIMIT 1
                ), 0) > 0.95 THEN
                    CASE
                        WHEN COALESCE((
                            SELECT lower(asset.exposure)
                            FROM assets AS asset
                            WHERE asset.id = finding.asset_id
                        ), 'internal') = 'internet'
                            OR COALESCE((
                                SELECT asset.criticality
                                FROM assets AS asset
                                WHERE asset.id = finding.asset_id
                            ), 1) >= 4
                        THEN 'Critical'
                        ELSE 'High'
                    END
                WHEN finding.cvss_score >= 9.0 THEN
                    CASE
                        WHEN COALESCE((
                            SELECT lower(asset.exposure)
                            FROM assets AS asset
                            WHERE asset.id = finding.asset_id
                        ), 'internal') = 'internet'
                            THEN 'Critical'
                        WHEN COALESCE((
                            SELECT asset.criticality
                            FROM assets AS asset
                            WHERE asset.id = finding.asset_id
                        ), 1) >= 4 THEN 'High'
                        ELSE 'Medium'
                    END
                WHEN COALESCE((
                    SELECT score.likelihood
                    FROM finding_scores AS score
                    WHERE score.finding_id = finding.id
                    ORDER BY score.id DESC
                    LIMIT 1
                ), 0) >= 0.20 THEN
                    CASE
                        WHEN COALESCE((
                            SELECT asset.criticality
                            FROM assets AS asset
                            WHERE asset.id = finding.asset_id
                        ), 1) >= 4 THEN 'High'
                        ELSE 'Medium'
                    END
                WHEN finding.cvss_score >= 7.0 THEN 'Medium'
                ELSE 'Low'
            END
        ),
        priority_source = 'rules'
        """
    )
    op.create_index(
        "ix_findings_final_priority",
        "findings",
        ["final_priority"],
    )
    op.execute(f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {quoted_app_role}")
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public "
        f"TO {quoted_app_role}"
    )
    op.execute(f"REVOKE ALL ON TABLE public.alembic_version FROM {quoted_app_role}")
    op.execute(
        f"REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER "
        f"ON TABLE public.audit_logs FROM {quoted_app_role}"
    )
    op.execute(f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {quoted_app_role}")
    op.execute(
        f"GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {quoted_app_role}"
    )
    op.execute(
        f"ALTER DEFAULT PRIVILEGES FOR ROLE {quoted_owner_role} IN SCHEMA public "
        f"REVOKE ALL ON TABLES FROM {quoted_app_role}"
    )
    op.execute(
        f"ALTER DEFAULT PRIVILEGES FOR ROLE {quoted_owner_role} IN SCHEMA public "
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {quoted_app_role}"
    )
    op.execute(
        f"ALTER DEFAULT PRIVILEGES FOR ROLE {quoted_owner_role} IN SCHEMA public "
        f"REVOKE ALL ON SEQUENCES FROM {quoted_app_role}"
    )
    op.execute(
        f"ALTER DEFAULT PRIVILEGES FOR ROLE {quoted_owner_role} IN SCHEMA public "
        f"GRANT USAGE ON SEQUENCES TO {quoted_app_role}"
    )


def downgrade() -> None:
    op.drop_index("ix_findings_final_priority", table_name="findings")
    op.drop_column("findings", "priority_source")
    op.drop_column("findings", "final_priority")
