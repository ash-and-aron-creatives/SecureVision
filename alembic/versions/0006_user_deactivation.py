"""Add user activation status.

Revision ID: 0006_user_deactivation
Revises: 0005_cve_catalog
"""
from alembic import op
import sqlalchemy as sa


revision = "0006_user_deactivation"
down_revision = "0005_cve_catalog"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "users",
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.true(),
        ),
    )


def downgrade() -> None:
    op.drop_column("users", "is_active")
