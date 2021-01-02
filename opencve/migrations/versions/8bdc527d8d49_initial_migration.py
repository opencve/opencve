"""Initial migration

Revision ID: 8bdc527d8d49
Revises: None
Create Date: 2020-03-28 13:06:42.037072

"""

# revision identifiers, used by Alembic.
revision = "8bdc527d8d49"
down_revision = None

from alembic import op
import sqlalchemy as sa
from sqlalchemy_utils import UUIDType, JSONType
from sqlalchemy.dialects import postgresql


def upgrade():
    op.create_table(
        "cves",
        sa.Column("id", UUIDType(binary=False), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cve_id", sa.String(), nullable=False),
        sa.Column("json", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("vendors", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("cwes", postgresql.JSONB(astext_type=sa.Text()), nullable=True),
        sa.Column("summary", sa.String(), nullable=False),
        sa.Column("cvss2", sa.Float(), nullable=True),
        sa.Column("cvss3", sa.Float(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_cves_created_at"), "cves", ["created_at"], unique=False)
    op.create_index(op.f("ix_cves_cve_id"), "cves", ["cve_id"], unique=False)
    op.create_index(op.f("ix_cves_updated_at"), "cves", ["updated_at"], unique=False)
    op.create_index(
        "ix_cves_vendors",
        "cves",
        ["vendors"],
        unique=False,
        postgresql_using="gin",
    )
    op.create_index(
        "ix_cves_cwes", "cves", ["cwes"], unique=False, postgresql_using="gin"
    )
    op.create_table(
        "cwes",
        sa.Column("id", UUIDType(binary=False), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("cwe_id", sa.String(), nullable=True),
        sa.Column("name", sa.String(), nullable=True),
        sa.Column("description", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_cwes_created_at"), "cwes", ["created_at"], unique=False)
    op.create_table(
        "metas",
        sa.Column("id", UUIDType(binary=False), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("value", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_metas_created_at"), "metas", ["created_at"], unique=False)
    op.create_table(
        "tasks",
        sa.Column("id", UUIDType(binary=False), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_tasks_created_at"), "tasks", ["created_at"], unique=False)
    op.create_table(
        "users",
        sa.Column("id", UUIDType(binary=False), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("username", sa.String(length=50), nullable=False),
        sa.Column("password", sa.String(length=255), server_default="", nullable=False),
        sa.Column(
            "reset_password_token",
            sa.String(length=100),
            server_default="",
            nullable=False,
        ),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("email_confirmed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "enable_notifications",
            sa.Boolean(),
            server_default=sa.text("true"),
            nullable=False,
        ),
        sa.Column("filters_notifications", JSONType(), nullable=True),
        sa.Column(
            "frequency_notifications",
            sa.Enum("once", "always", name="notification_frequencies"),
            nullable=True,
        ),
        sa.Column(
            "is_active", sa.Boolean(), server_default=sa.text("false"), nullable=False
        ),
        sa.Column(
            "first_name", sa.String(length=100), server_default="", nullable=False
        ),
        sa.Column(
            "last_name", sa.String(length=100), server_default="", nullable=False
        ),
        sa.Column(
            "admin", sa.Boolean(), server_default=sa.text("false"), nullable=True
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
        sa.UniqueConstraint("username"),
    )
    op.create_index(op.f("ix_users_created_at"), "users", ["created_at"], unique=False)
    op.create_table(
        "vendors",
        sa.Column("id", UUIDType(binary=False), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index(
        op.f("ix_vendors_created_at"), "vendors", ["created_at"], unique=False
    )
    op.create_table(
        "changes",
        sa.Column("id", UUIDType(binary=False), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("json", JSONType(), nullable=True),
        sa.Column("cve_id", UUIDType(binary=False), nullable=True),
        sa.Column("task_id", UUIDType(binary=False), nullable=True),
        sa.ForeignKeyConstraint(
            ["cve_id"],
            ["cves.id"],
        ),
        sa.ForeignKeyConstraint(
            ["task_id"],
            ["tasks.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_changes_created_at"), "changes", ["created_at"], unique=False
    )
    op.create_table(
        "products",
        sa.Column("id", UUIDType(binary=False), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("name", sa.String(), nullable=False),
        sa.Column("vendor_id", UUIDType(binary=False), nullable=True),
        sa.ForeignKeyConstraint(
            ["vendor_id"],
            ["vendors.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_products_created_at"), "products", ["created_at"], unique=False
    )
    op.create_index(op.f("ix_products_name"), "products", ["name"], unique=False)
    op.create_table(
        "reports",
        sa.Column("id", UUIDType(binary=False), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("public_link", sa.String(), nullable=True),
        sa.Column("seen", sa.Boolean(), nullable=True),
        sa.Column("details", JSONType(), nullable=True),
        sa.Column("user_id", UUIDType(binary=False), nullable=True),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_reports_created_at"), "reports", ["created_at"], unique=False
    )
    op.create_table(
        "users_vendors",
        sa.Column("user_id", UUIDType(binary=False), nullable=False),
        sa.Column("vendor_id", UUIDType(binary=False), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
        ),
        sa.ForeignKeyConstraint(
            ["vendor_id"],
            ["vendors.id"],
        ),
        sa.PrimaryKeyConstraint("user_id", "vendor_id"),
    )
    op.create_table(
        "alerts",
        sa.Column("id", UUIDType(binary=False), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("details", JSONType(), nullable=True),
        sa.Column("notify", sa.Boolean(), nullable=True),
        sa.Column("user_id", UUIDType(binary=False), nullable=True),
        sa.Column("cve_id", UUIDType(binary=False), nullable=True),
        sa.Column("report_id", UUIDType(binary=False), nullable=True),
        sa.ForeignKeyConstraint(
            ["cve_id"],
            ["cves.id"],
        ),
        sa.ForeignKeyConstraint(
            ["report_id"],
            ["reports.id"],
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_alerts_created_at"), "alerts", ["created_at"], unique=False
    )
    op.create_table(
        "events",
        sa.Column("id", UUIDType(binary=False), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "type",
            sa.Enum(
                "new_cve",
                "references",
                "cpes",
                "cvss",
                "summary",
                "cwes",
                name="event_types",
            ),
            nullable=True,
        ),
        sa.Column("details", JSONType(), nullable=True),
        sa.Column("review", sa.Boolean(), nullable=True),
        sa.Column("cve_id", UUIDType(binary=False), nullable=True),
        sa.Column("change_id", UUIDType(binary=False), nullable=True),
        sa.ForeignKeyConstraint(
            ["change_id"],
            ["changes.id"],
        ),
        sa.ForeignKeyConstraint(
            ["cve_id"],
            ["cves.id"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_events_created_at"), "events", ["created_at"], unique=False
    )
    op.create_table(
        "users_products",
        sa.Column("user_id", UUIDType(binary=False), nullable=False),
        sa.Column("product_id", UUIDType(binary=False), nullable=False),
        sa.ForeignKeyConstraint(
            ["product_id"],
            ["products.id"],
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
        ),
        sa.PrimaryKeyConstraint("user_id", "product_id"),
    )
    op.create_table(
        "alerts_events",
        sa.Column("alert_id", UUIDType(binary=False), nullable=False),
        sa.Column("event_id", UUIDType(binary=False), nullable=False),
        sa.ForeignKeyConstraint(
            ["alert_id"],
            ["alerts.id"],
        ),
        sa.ForeignKeyConstraint(
            ["event_id"],
            ["events.id"],
        ),
        sa.PrimaryKeyConstraint("alert_id", "event_id"),
    )


def downgrade():
    op.drop_table("alerts_events")
    op.drop_table("users_products")
    op.drop_index(op.f("ix_events_created_at"), table_name="events")
    op.drop_table("events")
    op.execute("DROP TYPE event_types")
    op.drop_index(op.f("ix_alerts_created_at"), table_name="alerts")
    op.drop_table("alerts")
    op.drop_table("users_vendors")
    op.drop_index(op.f("ix_reports_created_at"), table_name="reports")
    op.drop_table("reports")
    op.drop_index(op.f("ix_products_name"), table_name="products")
    op.drop_index(op.f("ix_products_created_at"), table_name="products")
    op.drop_table("products")
    op.drop_index(op.f("ix_changes_created_at"), table_name="changes")
    op.drop_table("changes")
    op.drop_index(op.f("ix_vendors_created_at"), table_name="vendors")
    op.drop_table("vendors")
    op.drop_index(op.f("ix_users_created_at"), table_name="users")
    op.drop_table("users")
    op.execute("DROP TYPE notification_frequencies")
    op.drop_index(op.f("ix_tasks_created_at"), table_name="tasks")
    op.drop_table("tasks")
    op.drop_index(op.f("ix_metas_created_at"), table_name="metas")
    op.drop_table("metas")
    op.drop_index(op.f("ix_cwes_created_at"), table_name="cwes")
    op.drop_table("cwes")
    op.drop_index(op.f("ix_cves_updated_at"), table_name="cves")
    op.drop_index(op.f("ix_cves_cve_id"), table_name="cves")
    op.drop_index(op.f("ix_cves_created_at"), table_name="cves")
    op.drop_index(op.f("ix_cves_vendors"), table_name="cves")
    op.drop_index(op.f("ix_cves_cwes"), table_name="cves")
    op.drop_table("cves")
