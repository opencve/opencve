import logging
from abc import ABC, abstractmethod
from typing import Dict

from includes.constants import SQL_NOTIFICATION_BY_ID
from includes.tasks.automations.utils import (
    get_item_cve_ids,
    resolve_notifier_class,
    upsert_tracker_records,
)

logger = logging.getLogger(__name__)

ACTION_REGISTRY = {}


class ActionExecutor(ABC):
    @abstractmethod
    async def execute(self, action: Dict, context: Dict) -> None:
        raise NotImplementedError


def register_action(action_type: str):
    def _decorator(cls):
        ACTION_REGISTRY[action_type] = cls()
        return cls

    return _decorator


async def execute_action(action: Dict, context: Dict) -> None:
    action_type = action.get("type")
    executor = ACTION_REGISTRY.get(action_type)
    if executor is None:
        logger.warning("Unknown automation action type: %s", action_type)
        return
    await executor.execute(action, context)


@register_action("assign_user")
class AssignUserAction(ActionExecutor):
    async def execute(self, action, context):
        assignee_id = action.get("value")
        if not assignee_id:
            logger.warning("No assignee specified for assign_user action")
            return

        cve_id_strings = get_item_cve_ids(
            context["changes"], context["item_changes_details"]
        )
        upsert_tracker_records(
            postgres_hook=context["postgres_hook"],
            project_id=context["automation"]["project_id"],
            cve_id_strings=cve_id_strings,
            assignee_id=assignee_id,
        )


@register_action("change_status")
class ChangeStatusAction(ActionExecutor):
    async def execute(self, action, context):
        status = action.get("value")
        if not status:
            logger.warning("No status specified for change_status action")
            return

        cve_id_strings = get_item_cve_ids(
            context["changes"], context["item_changes_details"]
        )
        upsert_tracker_records(
            postgres_hook=context["postgres_hook"],
            project_id=context["automation"]["project_id"],
            cve_id_strings=cve_id_strings,
            status=status,
        )


@register_action("generate_pdf")
class GeneratePdfAction(ActionExecutor):
    async def execute(self, action, context):
        if not action.get("value", False):
            return
        logger.info(
            "generate_pdf action requested for automation '%s' with %s matched changes",
            context["automation"]["automation_name"],
            len(context["changes"]),
        )


@register_action("generate_report")
class GenerateReportAction(ActionExecutor):
    async def execute(self, action, context):
        if not action.get("value", False):
            return
        logger.info(
            "generate_report action requested for automation '%s' with %s matched changes",
            context["automation"]["automation_name"],
            len(context["changes"]),
        )


@register_action("include_ai_summary")
class IncludeAiSummaryAction(ActionExecutor):
    async def execute(self, action, context):
        if not action.get("value", False):
            return
        logger.info(
            "include_ai_summary action requested for automation '%s' with %s matched changes",
            context["automation"]["automation_name"],
            len(context["changes"]),
        )


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
