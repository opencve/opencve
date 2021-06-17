"""Add tags tables

Revision ID: 4195eeb432e9
Revises: 33cd640e1112
Create Date: 2021-06-16 21:27:51.683602

"""

# revision identifiers, used by Alembic.
revision = "4195eeb432e9"
down_revision = "33cd640e1112"

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
from sqlalchemy_utils import UUIDType


def upgrade():
    op.create_table(
        "cves_tags",
        sa.Column("id", UUIDType(binary=False), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("tags", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("user_id", UUIDType(binary=False), nullable=True),
        sa.Column("cve_id", UUIDType(binary=False), nullable=True),
        sa.ForeignKeyConstraint(
            ["cve_id"],
            ["cves.id"],
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_cves_tags", "cves_tags", ["tags"], unique=False, postgresql_using="gin"
    )
    op.create_index(
        op.f("ix_cves_tags_created_at"), "cves_tags", ["created_at"], unique=False
    )
    op.create_table(
        "users_tags",
        sa.Column("id", UUIDType(binary=False), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("description", sa.String(), nullable=True),
        sa.Column("color", sa.String(), nullable=False),
        sa.Column(
            "user_id",
            UUIDType(binary=False),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name", "user_id", name="ix_userstags_name_userid"),
    )
    op.create_index(
        op.f("ix_users_tags_created_at"), "users_tags", ["created_at"], unique=False
    )


def downgrade():
    op.drop_index(op.f("ix_users_tags_created_at"), table_name="users_tags")
    op.drop_constraint("ix_userstags_name_userid", "users_tags")
    op.drop_table("users_tags")
    op.drop_index(op.f("ix_cves_tags_created_at"), table_name="cves_tags")
    op.drop_index("ix_cves_tags", table_name="cves_tags", postgresql_using="gin")
    op.drop_table("cves_tags")
