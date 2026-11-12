"""Enforce finding uniqueness and least-privilege app access.

Revision ID: 0003_app_constraints
Revises: 0002_audit_truncate
"""
import os

from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine import make_url


revision = "0003_app_constraints"
down_revision = "0002_audit_truncate"
branch_labels = None
depends_on = None


def _duplicate_report(connection) -> list[str]:
    duplicates = []
    asset_rows = connection.execute(
        sa.text(
            """
            SELECT lower(name) AS normalized_name, array_agg(id ORDER BY id) AS ids,
                   array_agg(name ORDER BY id) AS names
            FROM assets
            WHERE name IS NOT NULL
            GROUP BY lower(name)
            HAVING count(*) > 1
            ORDER BY lower(name)
            """
        )
    ).mappings()
    for row in asset_rows:
        duplicates.append(
            f"assets name {row['names']!r} (ids {row['ids']!r}) collide case-insensitively"
        )

    finding_rows = connection.execute(
        sa.text(
            """
            SELECT asset_id, cve_id, array_agg(id ORDER BY id) AS ids
            FROM findings
            WHERE asset_id IS NOT NULL AND cve_id IS NOT NULL
            GROUP BY asset_id, cve_id
            HAVING count(*) > 1
            ORDER BY asset_id, cve_id
            """
        )
    ).mappings()
    for row in finding_rows:
        duplicates.append(
            f"findings asset_id={row['asset_id']}, cve_id={row['cve_id']!r} "
            f"(ids {row['ids']!r})"
        )
    return duplicates


def upgrade() -> None:
    connection = op.get_bind()
    duplicates = _duplicate_report(connection)
    if duplicates:
        detail = "\n".join(f"  - {duplicate}" for duplicate in duplicates)
        raise RuntimeError(
            "Migration 0003 aborted because duplicate records must be resolved first:\n"
            f"{detail}\n"
            "No migration changes were applied. Review scripts/dedupe_postgres.py "
            "(manual only; dry-run by default, requires --apply to write)."
        )

    app_url = os.environ.get("DATABASE_URL")
    if not app_url:
        raise RuntimeError("DATABASE_URL must identify the runtime app role during migration.")
    app_role = make_url(app_url).username
    if not app_role:
        raise RuntimeError("DATABASE_URL must include the runtime app role username.")

    preparer = connection.dialect.identifier_preparer
    quoted_app_role = preparer.quote(app_role)
    owner_role = connection.execute(sa.text("SELECT current_user")).scalar_one()
    quoted_owner_role = preparer.quote(owner_role)

    op.create_index(
        "uq_assets_name_ci",
        "assets",
        [sa.text("lower(name)")],
        unique=True,
    )
    op.create_unique_constraint(
        "uq_findings_asset_cve",
        "findings",
        ["asset_id", "cve_id"],
    )

    op.execute("REVOKE CREATE ON SCHEMA public FROM PUBLIC")
    op.execute("REVOKE ALL ON ALL TABLES IN SCHEMA public FROM PUBLIC")
    op.execute("REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM PUBLIC")
    op.execute(f"REVOKE ALL ON SCHEMA public FROM {quoted_app_role}")
    op.execute(f"GRANT USAGE ON SCHEMA public TO {quoted_app_role}")
    op.execute(f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {quoted_app_role}")
    op.execute(
        f"GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public "
        f"TO {quoted_app_role}"
    )
    op.execute(f"REVOKE ALL ON alembic_version FROM {quoted_app_role}")
    op.execute(
        f"REVOKE UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER ON audit_logs "
        f"FROM {quoted_app_role}"
    )
    op.execute(f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {quoted_app_role}")
    op.execute(
        f"GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO {quoted_app_role}"
    )
    op.execute(f"ALTER DEFAULT PRIVILEGES FOR ROLE {quoted_owner_role} IN SCHEMA public "
               f"GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO {quoted_app_role}")
    op.execute(f"ALTER DEFAULT PRIVILEGES FOR ROLE {quoted_owner_role} IN SCHEMA public "
               f"GRANT USAGE ON SEQUENCES TO {quoted_app_role}")


def downgrade() -> None:
    connection = op.get_bind()
    app_url = os.environ.get("DATABASE_URL")
    app_role = make_url(app_url).username if app_url else None
    if app_role:
        preparer = connection.dialect.identifier_preparer
        quoted_app_role = preparer.quote(app_role)
        owner_role = connection.execute(sa.text("SELECT current_user")).scalar_one()
        quoted_owner_role = preparer.quote(owner_role)
        op.execute(
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {quoted_owner_role} IN SCHEMA public "
            f"REVOKE SELECT, INSERT, UPDATE, DELETE ON TABLES FROM {quoted_app_role}"
        )
        op.execute(
            f"ALTER DEFAULT PRIVILEGES FOR ROLE {quoted_owner_role} IN SCHEMA public "
            f"REVOKE USAGE, SELECT ON SEQUENCES FROM {quoted_app_role}"
        )
        op.execute(f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {quoted_app_role}")
        op.execute(f"REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM {quoted_app_role}")
        op.execute(f"REVOKE USAGE ON SCHEMA public FROM {quoted_app_role}")

    op.drop_constraint("uq_findings_asset_cve", "findings", type_="unique")
    op.drop_index("uq_assets_name_ci", table_name="assets")
