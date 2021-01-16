"""Make Cwe.cwe_id field not nullable

Revision ID: 41ad8e9163d4
Revises: 8bdc527d8d49
Create Date: 2021-01-16 18:08:17.844952

"""

# revision identifiers, used by Alembic.
revision = "41ad8e9163d4"
down_revision = "8bdc527d8d49"

from alembic import op
import sqlalchemy as sa


def upgrade():
    """Make Cwe.cwe_id field not nullable and add an index on it."""
    op.alter_column("cwes", "cwe_id", existing_type=sa.VARCHAR(), nullable=False)
    op.create_index(op.f("ix_cwes_cwe_id"), "cwes", ["cwe_id"], unique=False)


def downgrade():
    """Make Cwe.cwe_id field nullable and remove the index on it."""
    op.drop_index(op.f("ix_cwes_cwe_id"), table_name="cwes")
    op.alter_column("cwes", "cwe_id", existing_type=sa.VARCHAR(), nullable=True)
