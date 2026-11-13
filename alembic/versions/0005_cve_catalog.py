"""Create a read-only CVE reference catalog.

Revision ID: 0005_cve_catalog
Revises: 0004_final_priority
"""
import os

from alembic import op
import sqlalchemy as sa
from sqlalchemy.engine import make_url


revision = "0005_cve_catalog"
down_revision = "0004_final_priority"
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
    preparer = connection.dialect.identifier_preparer
    quoted_app_role = preparer.quote(app_role)
    schema = connection.execute(sa.text("SELECT current_schema()")).scalar_one()
    qualified_table = (
        f"{preparer.quote(schema)}.{preparer.quote('cve_catalog')}"
    )
    op.create_table(
        "cve_catalog",
        sa.Column("cve_id", sa.String(), primary_key=True),
        sa.Column("published_date", sa.String(), nullable=True),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("cvss_score", sa.Float(), nullable=True),
        sa.Column("cvss_vector", sa.String(), nullable=True),
        sa.Column("cwe", sa.String(), nullable=True),
        sa.Column("kev_date_added", sa.String(), nullable=True),
        sa.Column("epss", sa.Float(), nullable=True),
        sa.Column("percentile", sa.Float(), nullable=True),
        sa.Column("in_kev", sa.Boolean(), nullable=False, server_default=sa.false()),
    )
    op.execute(f"REVOKE ALL ON TABLE {qualified_table} FROM PUBLIC")
    op.execute(f"REVOKE ALL ON TABLE {qualified_table} FROM {quoted_app_role}")
    op.execute(f"GRANT SELECT ON TABLE {qualified_table} TO {quoted_app_role}")
    op.execute(
        f"REVOKE INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER "
        f"ON TABLE {qualified_table} FROM {quoted_app_role}"
    )


def downgrade() -> None:
    op.drop_table("cve_catalog")
