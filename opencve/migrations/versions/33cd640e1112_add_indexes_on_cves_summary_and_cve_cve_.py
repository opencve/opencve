"""Add indexes on cves.summary and cve.cve_id

Revision ID: 33cd640e1112
Revises: f81abceece3d
Create Date: 2021-05-04 22:42:40.167721

"""

# revision identifiers, used by Alembic.
revision = "33cd640e1112"
down_revision = "f81abceece3d"

from alembic import op
import sqlalchemy as sa


def upgrade():
    """
    This migration introduces a requirement: the ability to enable the pg_trgm
    extension (https://www.postgresql.org/docs/current/pgtrgm.html).
    From PostgreSQL 13 this module is considered as trusted, meaning it can be
    installed by non-superusers with the CREATE privilege.
    """
    op.execute(sa.text("CREATE EXTENSION IF NOT EXISTS pg_trgm;"))
    op.create_index(
        "ix_cves_summary",
        "cves",
        ["summary"],
        unique=False,
        postgresql_using="gin",
        postgresql_ops={"summary": "gin_trgm_ops"},
    )
    op.drop_index("ix_cves_cve_id", table_name="cves")
    op.create_index(
        "ix_cves_cve_id",
        "cves",
        ["cve_id"],
        unique=False,
        postgresql_using="gin",
        postgresql_ops={"cve_id": "gin_trgm_ops"},
    )


def downgrade():
    op.drop_index("ix_cves_summary", table_name="cves")
    op.drop_index("ix_cves_cve_id", table_name="cves")
    op.create_index("ix_cves_cve_id", "cves", ["cve_id"], unique=False)
    op.execute(sa.text("DROP EXTENSION IF EXISTS pg_trgm;"))
