"""Add settings columns in users table

Revision ID: 3f755e0484e0
Revises: 2132d05ea0e2
Create Date: 2021-12-23 22:57:59.990718

"""

# revision identifiers, used by Alembic.
revision = "3f755e0484e0"
down_revision = "2132d05ea0e2"

from alembic import op
import sqlalchemy as sa
from sqlalchemy_utils import JSONType


def upgrade():
    op.add_column("users", sa.Column("settings", JSONType(), nullable=True))
    op.execute('UPDATE users SET settings = \'{"activities_view": "subscriptions"}\';')
    op.alter_column("users", "settings", existing_type=JSONType(), nullable=False)


def downgrade():
    op.drop_column("users", "settings")
