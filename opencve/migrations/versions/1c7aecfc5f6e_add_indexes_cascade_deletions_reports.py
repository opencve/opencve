"""Add cascade deletions and indexes for reports and alerts

Revision ID: 1c7aecfc5f6e
Revises: 3f755e0484e0
Create Date: 2022-09-15 23:18:50.794977

"""

# revision identifiers, used by Alembic.
revision = "1c7aecfc5f6e"
down_revision = "3f755e0484e0"

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.drop_constraint("alerts_report_id_fkey", "alerts", type_="foreignkey")
    op.create_foreign_key(
        "alerts_report_id_fkey",
        "alerts",
        "reports",
        ["report_id"],
        ["id"],
        ondelete="CASCADE",
    )
    op.drop_constraint(
        "alerts_events_alert_id_fkey", "alerts_events", type_="foreignkey"
    )
    op.create_foreign_key(
        "alerts_events_alert_id_fkey",
        "alerts_events",
        "alerts",
        ["alert_id"],
        ["id"],
        ondelete="CASCADE",
    )

    op.create_index(op.f("ix_alerts_cve_id"), "alerts", ["cve_id"], unique=False)
    op.create_index(op.f("ix_alerts_user_id"), "alerts", ["user_id"], unique=False)
    op.create_index(op.f("ix_alerts_report_id"), "alerts", ["report_id"], unique=False)
    op.create_index(
        op.f("ix_alerts_events_alert_id"), "alerts_events", ["alert_id"], unique=False
    )


def downgrade():
    op.drop_constraint(
        "alerts_events_alert_id_fkey", "alerts_events", type_="foreignkey"
    )
    op.create_foreign_key(
        "alerts_events_alert_id_fkey", "alerts_events", "alerts", ["alert_id"], ["id"]
    )
    op.drop_constraint("alerts_report_id_fkey", "alerts", type_="foreignkey")
    op.create_foreign_key(
        "alerts_report_id_fkey", "alerts", "reports", ["report_id"], ["id"]
    )

    op.drop_index(op.f("ix_alerts_cve_id"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_user_id"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_report_id"), table_name="alerts")
    op.drop_index(op.f("ix_alerts_events_alert_id"), table_name="alerts_events")
