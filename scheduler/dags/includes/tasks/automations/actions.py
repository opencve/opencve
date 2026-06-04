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
RESULT_STATUS_SUCCESS = "success"
RESULT_STATUS_SKIPPED = "skipped"
RESULT_STATUS_FAILED = "failed"

ACTION_TYPE_TO_OUTPUT = {
    "send_notification": ("notification_sent", "Notification sent"),
    "generate_report": ("report", "Report"),
    "assign_user": ("assignment", "Assignments"),
    "change_status": ("status_change", "Status changes"),
}


class ActionExecutor(ABC):
    @abstractmethod
    async def execute(self, action: Dict, context: Dict) -> Dict:
        raise NotImplementedError


def register_action(action_type: str):
    def _decorator(cls):
        ACTION_REGISTRY[action_type] = cls()
        return cls

    return _decorator


async def execute_action(action: Dict, context: Dict) -> Dict:
    action_type = action.get("type")
    executor = ACTION_REGISTRY.get(action_type)
    if executor is None:
        logger.warning("Unknown automation action type: %s", action_type)
        return _build_result_payload(
            action_type,
            RESULT_STATUS_SKIPPED,
            {"summary": "Unknown action type"},
        )
    try:
        result = await executor.execute(action, context)
    except Exception as exc:
        logger.exception("Automation action failed: %s", action_type)
        return _build_result_payload(
            action_type,
            RESULT_STATUS_FAILED,
            {"summary": str(exc)},
        )
    if not isinstance(result, dict):
        return _build_result_payload(action_type, RESULT_STATUS_SUCCESS, {})
    if "output_type" not in result or "label" not in result:
        fallback = _build_result_payload(
            action_type,
            result.get("status", RESULT_STATUS_SUCCESS),
            result.get("details", {}),
        )
        result = {**fallback, **result}
    return result


def _default_output_for_action(action_type: str):
    if action_type in ACTION_TYPE_TO_OUTPUT:
        return ACTION_TYPE_TO_OUTPUT[action_type]
    safe = action_type or "unknown"
    return safe, safe.replace("_", " ").title()


def _build_result_payload(action_type: str, status: str, details=None):
    output_type, label = _default_output_for_action(action_type)
    return {
        "output_type": output_type,
        "label": label,
        "status": status,
        "details": details or {},
    }


@register_action("assign_user")
class AssignUserAction(ActionExecutor):
    async def execute(self, action, context):
        assignee_id = action.get("value")
        if not assignee_id:
            logger.warning("No assignee specified for assign_user action")
            return _build_result_payload(
                "assign_user",
                RESULT_STATUS_SKIPPED,
                {"summary": "No assignee specified"},
            )

        assignee_username = action.get("username")
        cve_id_strings = get_item_cve_ids(
            context["changes"], context["item_changes_details"]
        )

        postgres_hook = context["postgres_hook"]
        upsert_tracker_records(
            postgres_hook=postgres_hook,
            project_id=context["automation"]["project_id"],
            cve_id_strings=cve_id_strings,
            assignee_id=assignee_id,
        )
        assigned_count = len(cve_id_strings)
        return _build_result_payload(
            "assign_user",
            RESULT_STATUS_SUCCESS,
            {
                "assigned_count": assigned_count,
                "assignee": assignee_username,
                "summary": f'{assigned_count} CVEs assigned to "{assignee_username}"',
            },
        )


@register_action("change_status")
class ChangeStatusAction(ActionExecutor):
    async def execute(self, action, context):
        status = action.get("value")
        if not status:
            logger.warning("No status specified for change_status action")
            return _build_result_payload(
                "change_status",
                RESULT_STATUS_SKIPPED,
                {"summary": "No status specified"},
            )

        cve_id_strings = get_item_cve_ids(
            context["changes"], context["item_changes_details"]
        )
        upsert_tracker_records(
            postgres_hook=context["postgres_hook"],
            project_id=context["automation"]["project_id"],
            cve_id_strings=cve_id_strings,
            status=status,
        )
        updated_count = len(cve_id_strings)
        status_label = action.get("label", status)
        return _build_result_payload(
            "change_status",
            RESULT_STATUS_SUCCESS,
            {
                "updated_count": updated_count,
                "to_status": status,
                "summary": f'{updated_count} CVEs moved to "{status_label}"',
            },
        )


@register_action("generate_report")
class GenerateReportAction(ActionExecutor):
    async def execute(self, action, context):
        if not action.get("value", False):
            return _build_result_payload(
                "generate_report",
                RESULT_STATUS_SKIPPED,
                {"summary": "Report generation is disabled"},
            )
        logger.info(
            "generate_report action requested for automation '%s' with %s matched changes",
            context["automation"]["automation_name"],
            len(context["changes"]),
        )
        report = context.get("report_content") or {}
        if not report:
            return _build_result_payload(
                "generate_report",
                RESULT_STATUS_SKIPPED,
                {"summary": "No report content available for this run"},
            )
        details = {
            "report_id": report.get("report_id"),
            "report_day": report.get("report_day"),
            "cve_count": report.get("cve_count", len(context.get("changes", []))),
        }
        return _build_result_payload("generate_report", RESULT_STATUS_SUCCESS, details)


@register_action("send_notification")
class SendNotificationAction(ActionExecutor):
    async def execute(self, action, context):
        notification_id = action.get("value")
        if not notification_id:
            logger.warning("No notification ID specified for send_notification")
            return _build_result_payload(
                "send_notification",
                RESULT_STATUS_SKIPPED,
                {"summary": "No notification ID specified"},
            )

        postgres_hook = context["postgres_hook"]
        notifications_cache = context.get("notifications_cache") or {}
        cached = notifications_cache.get(str(notification_id))
        if cached is not None:
            n_name = cached["name"]
            n_type = cached["type"]
            n_conf = cached["configuration"]
        else:
            record = postgres_hook.get_first(
                sql=SQL_NOTIFICATION_BY_ID,
                parameters={"notification_id": notification_id},
            )
            if not record:
                logger.warning("Notification %s not found or disabled", notification_id)
                notification_name = action.get("notification_name") or notification_id
                return _build_result_payload(
                    "send_notification",
                    RESULT_STATUS_SKIPPED,
                    {
                        "summary": (
                            f'Notification "{notification_name}" not found or disabled'
                        )
                    },
                )
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
            report_content=context.get("report_content"),
        )
        notifier_result = await notifier.execute()
        details = notifier_result.get("details", {}) if notifier_result else {}
        details.setdefault("channel", action.get("notification_name") or n_name)
        status = (
            notifier_result.get("status", RESULT_STATUS_SUCCESS)
            if notifier_result
            else RESULT_STATUS_SUCCESS
        )
        return _build_result_payload("send_notification", status, details)
