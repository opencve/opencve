"""Add first_time value in event_types enum

Revision ID: 2132d05ea0e2
Revises: 4195eeb432e9
Create Date: 2021-12-19 22:59:41.176119

"""

# revision identifiers, used by Alembic.
revision = "2132d05ea0e2"
down_revision = "4195eeb432e9"

from alembic import op


def upgrade():
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE event_types ADD VALUE 'first_time';")


def downgrade():
    with op.get_context().autocommit_block():
        op.execute(
            "CREATE TYPE event_types_new AS ENUM ('new_cve', 'references', 'cpes', 'cvss', 'summary', 'cwes');"
        )
        op.execute(
            "ALTER TABLE events ALTER COLUMN type TYPE event_types_new USING (type::text::event_types_new);"
        )
        op.execute("DROP TYPE event_types;")
        op.execute("ALTER TYPE event_types_new RENAME TO event_types;")
