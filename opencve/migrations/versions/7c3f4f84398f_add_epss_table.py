"""Add EPSS scores to CVEs

Revision ID: 7c3f4f84398f
Revises: 1c7aecfc5f6e
Create Date: 2023-10-09 23:18:50.794977

"""

# revision identifiers, used by Alembic.
revision = "7c3f4f84398f"
down_revision = "1c7aecfc5f6e"

from alembic import op
import sqlalchemy as sa
from sqlalchemy_utils import UUIDType


def upgrade():
    op.create_table(
        "epss_scores",
        sa.Column("id", UUIDType(binary=False), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cve_uuid", UUIDType(binary=False), nullable=False),
        sa.Column("cve_id", sa.String(), nullable=False),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("percentile", sa.Float(), nullable=False),
        sa.ForeignKeyConstraint(
            ["cve_uuid"],
            ["cves.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_epss_scores_cve_id"), "epss_scores", ["cve_id"], unique=True
    )


def downgrade():
    op.drop_index(op.f("ix_epss_scores_cve_id"), table_name="epss_scores")
    op.drop_table("epss_scores")
