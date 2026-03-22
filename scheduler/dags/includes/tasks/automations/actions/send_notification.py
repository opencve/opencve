import logging

from includes.tasks.automations.actions.base import ActionExecutor, register_action
from includes.tasks.automations.actions.common import resolve_notifier_class

logger = logging.getLogger(__name__)

SQL_NOTIFICATION_BY_ID = """
SELECT
    notifications.name,
    notifications.type,
    notifications.configuration
FROM opencve_notifications AS notifications
WHERE notifications.id = %(notification_id)s
  AND notifications.is_enabled = 't'
"""


@register_action("send_notification")
class SendNotificationAction(ActionExecutor):
    async def execute(self, action, context):
        notification_id = action.get("value")
        if not notification_id:
            logger.warning("No notification ID specified for send_notification")
            return

        postgres_hook = context["postgres_hook"]
        record = postgres_hook.get_first(
            sql=SQL_NOTIFICATION_BY_ID,
            parameters={"notification_id": notification_id},
        )
        if not record:
            logger.warning("Notification %s not found or disabled", notification_id)
            return

        n_name, n_type, n_conf = record
        automation = context["automation"]

        notification_data = {
            "project_id": automation["project_id"],
            "project_name": automation["project_name"],
            "project_subscriptions": automation["project_subscriptions"],
            "organization_name": automation["organization_name"],
            "notification_name": n_name,
            "notification_type": n_type,
            "notification_conf": n_conf,
        }

        notif_cls = resolve_notifier_class(n_type)
        notifier = notif_cls(
            semaphore=context["semaphore"],
            session=context["session"],
            notification=notification_data,
            changes=context["changes"],
            changes_details=context["item_changes_details"],
            period=context["period"],
            scheduled_report=context.get("scheduled_report"),
        )
        await notifier.execute()
