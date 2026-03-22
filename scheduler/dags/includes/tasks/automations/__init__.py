import asyncio
import logging
import urllib.parse
import uuid

import aiohttp
from airflow.configuration import conf
from airflow.decorators import task
from airflow.exceptions import AirflowSkipException
from airflow.providers.postgres.hooks.postgres import PostgresHook
from airflow.providers.redis.hooks.redis import RedisHook
from includes.constants import (
    REPORT_UPSERT_PROCEDURE,
    SQL_CVE_TRACKER_STATUS,
    SQL_PROJECT_WITH_AUTOMATIONS,
    SQL_REPORT_SUMMARY_BY_ID,
)
from includes.storage import (
    REDIS_PREFIX_AUTOMATIONS,
    REDIS_PREFIX_CHANGES_DETAILS,
    REDIS_PREFIX_SCHEDULED_DUE_WORK_ITEMS,
    REDIS_PREFIX_SCHEDULED_HOURLY_REPORT_ITEMS,
    REDIS_PREFIX_SUBSCRIPTIONS,
    REDIS_PREFIX_VENDOR_CHANGES,
    automation_action_queue_prefix,
    redis_get,
    redis_set,
)
from includes.tasks.automations.actions import execute_action
from includes.tasks.automations.conditions import evaluate_condition_tree
from includes.utils import (
    divide_list,
    get_dates_from_context,
    group_automations_by_project,
    list_changes_by_project,
)
from psycopg2.extras import Json

logger = logging.getLogger(__name__)

TRIGGER_TO_CHANGE_TYPES = {
    "cve_enters_project": {"created"},
    "cvss_increased": {"metrics"},
    "cvss_decreased": {"metrics"},
    "epss_increased": {"metrics"},
    "epss_decreased": {"metrics"},
    # TODO: je pense que kev_added doit tomber dans metrics
    "kev_added": {"kev"},
    "new_vendor": {"vendors"},
    "new_product": {"cpes"},
    "description_changed": {"description"},
    "title_changed": {"title"},
    "new_reference": {"references"},
    "new_weakness": {"weaknesses"},
}

WEEKDAY_TO_INT = {
    "monday": 0,
    "tuesday": 1,
    "wednesday": 2,
    "thursday": 3,
    "friday": 4,
    "saturday": 5,
    "sunday": 6,
}

SQL_REPORT_BY_PERIOD = """
SELECT id
FROM opencve_reports
WHERE project_id = %(project_id)s
  AND automation_id = %(automation_id)s
  AND day = %(period_day)s
  AND period_type = %(period_type)s
LIMIT 1;
"""


def change_matches_triggers(change_details, triggers):
    print("===> change_matches_triggers:")
    print(change_details)
    print(triggers)
    if not triggers:
        return True

    change_types = set(change_details.get("change_types") or [])
    for trigger in triggers:
        mapped = TRIGGER_TO_CHANGE_TYPES.get(trigger)
        if mapped is None:
            logger.warning("Unknown automation trigger: %s", trigger)
            continue
        if change_types.intersection(mapped):
            return True
    return False


def _parse_schedule_time(automation):
    schedule_time = automation.get("schedule_time") or "00:00"
    try:
        hour_str, minute_str = schedule_time.split(":")
        return int(hour_str), int(minute_str)
    except (AttributeError, ValueError):
        logger.warning(
            "Invalid schedule_time '%s' for automation %s",
            schedule_time,
            automation.get("automation_id"),
        )
        return None, None


def _get_timezone_name(automation):
    return automation.get("schedule_timezone") or "UTC"


def is_scheduled_due_now(automation, context):

    # Pas besoin je pense, ça n'est appelé que par des automations scheduled
    if automation.get("trigger_type") != "scheduled":
        return False

    hour, minute = _parse_schedule_time(automation)
    if hour is None:
        return False

    local_run_end = context["data_interval_end"].in_timezone(
        _get_timezone_name(automation)
    )
    if local_run_end.hour != hour or local_run_end.minute != minute:
        return False

    frequency = automation.get("frequency")
    if frequency == "daily":
        return True
    if frequency == "weekly":
        weekday = WEEKDAY_TO_INT.get(automation.get("schedule_weekday") or "")
        return weekday is not None and local_run_end.day_of_week == weekday

    logger.warning(
        "Unsupported scheduled frequency '%s' for automation %s",
        frequency,
        automation.get("automation_id"),
    )
    return False


def get_accumulation_period_bucket(automation, context):
    local_anchor = (
        context["data_interval_end"]
        .in_timezone(_get_timezone_name(automation))
        .subtract(seconds=1)
    )
    frequency = automation.get("frequency")
    if frequency == "weekly":
        period_day = str(local_anchor.start_of("week").date())
        period_type = "weekly"
    else:
        period_day = str(local_anchor.date())
        period_type = "daily"
    return {
        "period_day": period_day,
        "period_type": period_type,
        "period_timezone": _get_timezone_name(automation),
    }


def get_due_period_bucket(automation, context):
    local_run_end = context["data_interval_end"].in_timezone(
        _get_timezone_name(automation)
    )
    frequency = automation.get("frequency")

    # Previous week for weekly automations
    if frequency == "weekly":
        period_day = str(local_run_end.start_of("week").subtract(weeks=1).date())
        period_type = "weekly"

    # Previous day for daily automations
    else:
        period_day = str(local_run_end.subtract(days=1).date())
        period_type = "daily"

    return {
        "period_day": period_day,
        "period_type": period_type,
        "period_timezone": _get_timezone_name(automation),
    }


def filter_changes_for_automation(automation, changes, changes_details, cve_trackers):
    config = automation.get("automation_conf") or {}
    conditions_tree = config.get("conditions")
    triggers = config.get("triggers") or []
    trigger_type = automation.get("trigger_type")

    matching_changes = []
    for change_id in changes:
        change_details = changes_details.get(change_id)
        print("===> change_details:")
        print(change_details)
        if not change_details:
            continue

        if trigger_type == "realtime" and not change_matches_triggers(
            change_details, triggers
        ):
            continue

        if not evaluate_condition_tree(conditions_tree, change_details, cve_trackers):
            continue

        matching_changes.append(change_id)

    return matching_changes


def get_project_changes(redis_conn, start, end):
    vendor_changes = redis_get(redis_conn, REDIS_PREFIX_VENDOR_CHANGES, start, end)
    subscriptions = redis_get(redis_conn, REDIS_PREFIX_SUBSCRIPTIONS, start, end)
    if not vendor_changes or not subscriptions:
        return {}
    return list_changes_by_project(vendor_changes, subscriptions)


def get_trackers_for_project(postgres_hook, project_id, changes, changes_details):
    cve_ids = list(
        set(
            changes_details[change_id]["cve_id"]
            for change_id in changes
            if change_id in changes_details
        )
    )
    if not cve_ids:
        return {}
    tracker_records = postgres_hook.get_records(
        sql=SQL_CVE_TRACKER_STATUS,
        parameters={"project_id": project_id, "cve_ids": tuple(cve_ids)},
    )
    return {
        record[0]: {"status": record[1], "assignee_id": record[2]}
        for record in tracker_records
    }


def chunk_actions(actions_to_execute):
    max_map_length = conf.getint(
        "opencve",
        "max_automations_map_length",
        fallback=conf.getint("opencve", "max_notifications_map_length", fallback=10),
    )
    return divide_list(actions_to_execute, max_map_length)


@task(task_id="LoadEnabledAutomations")
def load_enabled_automations(**context):
    start, end = get_dates_from_context(context)
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()

    subscriptions = redis_get(redis_hook, REDIS_PREFIX_SUBSCRIPTIONS, start, end)
    if not subscriptions:
        raise AirflowSkipException("No subscribed project found")

    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")
    records = postgres_hook.get_records(
        sql=SQL_PROJECT_WITH_AUTOMATIONS,
        parameters={"projects": tuple(subscriptions.keys())},
    )
    automations = group_automations_by_project(records, subscriptions)
    if not automations:
        raise AirflowSkipException("No automation found")

    redis_set(redis_hook, REDIS_PREFIX_AUTOMATIONS, start, end, automations)


@task(task_id="BuildRealtimeWorkItems")
def build_realtime_work_items(**context):
    start, end = get_dates_from_context(context)
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")

    def _empty_queue():
        redis_set(
            redis_hook,
            automation_action_queue_prefix("realtime"),
            start,
            end,
            {"chunks": []},
        )
        return True

    # Group the changes by project
    project_changes = get_project_changes(redis_hook, start, end)
    if not project_changes:
        return _empty_queue()
    logger.debug("List of project changes: %s", project_changes)

    # List the automations by project
    automations = redis_get(redis_hook, REDIS_PREFIX_AUTOMATIONS, start, end)
    if not automations:
        return _empty_queue()

    # List the changes details
    changes_details = redis_get(redis_hook, REDIS_PREFIX_CHANGES_DETAILS, start, end)

    # For each project, build the actions to execute
    actions_to_execute = []
    for project_id, changes in project_changes.items():
        project_automations = automations.get(project_id) or []

        # Only keep the realtime automations
        realtime_automations = [
            a for a in project_automations if a.get("trigger_type") == "realtime"
        ]
        if not realtime_automations:
            continue

        # TODO: j'ai peur qu'on fasse beaucoup de requêtes SQL ici
        cve_trackers = get_trackers_for_project(
            postgres_hook, project_id, changes, changes_details
        )
        for automation in realtime_automations:
            print("===> changes:")
            print(changes)
            filtered_changes = filter_changes_for_automation(
                automation=automation,
                changes=changes,
                changes_details=changes_details,
                cve_trackers=cve_trackers,
            )
            print("===> filtered_changes:")
            print(filtered_changes)
            if not filtered_changes:
                continue

            actions = automation.get("automation_conf", {}).get("actions", [])
            if not actions:
                continue

            actions_to_execute.append(
                {
                    "automation": automation,
                    "changes": filtered_changes,
                    "actions": actions,
                }
            )

    chunks = chunk_actions(actions_to_execute)
    redis_set(
        redis_hook,
        automation_action_queue_prefix("realtime"),
        start,
        end,
        {"chunks": chunks},
    )
    return True


@task(task_id="BuildScheduledReportContentHourly")
def build_scheduled_report_content_hourly(**context):
    start, end = get_dates_from_context(context)
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    changes_details = redis_get(redis_hook, REDIS_PREFIX_CHANGES_DETAILS, start, end)
    automations = redis_get(redis_hook, REDIS_PREFIX_AUTOMATIONS, start, end)
    project_changes = get_project_changes(redis_hook, start, end)
    if not automations:
        redis_set(
            redis_hook, REDIS_PREFIX_SCHEDULED_HOURLY_REPORT_ITEMS, start, end, []
        )
        return True

    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")
    items = []

    for project_id, project_automations in automations.items():

        # Only keep the scheduled automations
        scheduled_automations = [
            a
            for a in (project_automations or [])
            if a.get("trigger_type") == "scheduled"
        ]
        if not scheduled_automations:
            continue

        # TODO: j'ai peur qu'on fasse beaucoup de requêtes SQL ici
        project_hourly_changes = project_changes.get(project_id, [])
        cve_trackers = get_trackers_for_project(
            postgres_hook, project_id, project_hourly_changes, changes_details
        )

        for automation in scheduled_automations:
            filtered_changes = filter_changes_for_automation(
                automation=automation,
                changes=project_hourly_changes,
                changes_details=changes_details,
                cve_trackers=cve_trackers,
            )
            period_bucket = get_accumulation_period_bucket(automation, context)
            items.append(
                {
                    "automation": automation,
                    "changes": filtered_changes,
                    "period_bucket": period_bucket,
                }
            )

    redis_set(redis_hook, REDIS_PREFIX_SCHEDULED_HOURLY_REPORT_ITEMS, start, end, items)
    return True


@task(task_id="UpsertScheduledReportsAndEntries")
def upsert_scheduled_reports_and_entries(**context):
    start, end = get_dates_from_context(context)
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    scheduled_hourly_items = redis_get(
        redis_hook,
        REDIS_PREFIX_SCHEDULED_HOURLY_REPORT_ITEMS,
        start,
        end,
        default=[],
    )

    if not scheduled_hourly_items:
        return {"reports_touched": 0}

    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")
    accumulated = []
    for item in scheduled_hourly_items:
        automation = item["automation"]
        bucket = item["period_bucket"]
        project_id = automation["project_id"]
        automation_id = automation["automation_id"]

        # TODO: ici on fait l'upsert du report, mais avant dans populate_reports
        # on faisait un check de l'exception au cas où un projet aurait été supprimé
        # je pense qu'il faut reprendre ce check ici
        postgres_hook.run(
            sql=REPORT_UPSERT_PROCEDURE,
            parameters={
                "report": str(uuid.uuid4()),
                "project": project_id,
                "automation": automation_id,
                "period_day": bucket["period_day"],
                "period_type": bucket["period_type"],
                "period_timezone": bucket["period_timezone"],
                "changes": Json(item["changes"]),
            },
        )

        report_record = postgres_hook.get_first(
            sql=SQL_REPORT_BY_PERIOD,
            parameters={
                "project_id": project_id,
                "automation_id": automation_id,
                "period_day": bucket["period_day"],
                "period_type": bucket["period_type"],
            },
        )
        if not report_record:
            continue

        accumulated.append(
            {
                "automation_id": automation_id,
                "report_id": str(report_record[0]),
                "period_day": bucket["period_day"],
                "period_type": bucket["period_type"],
                "period_timezone": bucket["period_timezone"],
            }
        )

    return {"reports_touched": len(accumulated)}


@task(task_id="EvaluateScheduledDueInAutomationTimezone")
def evaluate_scheduled_due_in_automation_timezone(**context):
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    start, end = get_dates_from_context(context)
    automations = redis_get(redis_hook, REDIS_PREFIX_AUTOMATIONS, start, end)
    if not automations:
        redis_set(redis_hook, REDIS_PREFIX_SCHEDULED_DUE_WORK_ITEMS, start, end, [])
        return True

    due_work_items = []
    for _, project_automations in automations.items():

        for automation in project_automations or []:
            # TODO: on fera 2 requêtes ici je pense, donc on pourra virer ce check
            if automation.get("trigger_type") != "scheduled":
                continue
            if not is_scheduled_due_now(automation, context):
                continue

            due_work_items.append(
                {
                    "automation": automation,
                    "period_bucket": get_due_period_bucket(automation, context),
                }
            )

    redis_set(
        redis_hook, REDIS_PREFIX_SCHEDULED_DUE_WORK_ITEMS, start, end, due_work_items
    )
    return True


@task(task_id="BuildScheduledReportNotificationPayload")
def build_scheduled_report_notification_payload(**context):
    start, end = get_dates_from_context(context)
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    due_work_items = redis_get(
        redis_hook,
        REDIS_PREFIX_SCHEDULED_DUE_WORK_ITEMS,
        start,
        end,
        default=[],
    )

    if not due_work_items:
        redis_set(
            redis_hook,
            automation_action_queue_prefix("scheduled_due"),
            start,
            end,
            {"chunks": []},
        )
        return True

    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")
    web_base_url = conf.get("opencve", "web_base_url")
    due_action_items = []

    for item in due_work_items:
        automation = item["automation"]
        bucket = item["period_bucket"]

        # Ensure report exists for the due period (idempotent upsert)
        # TODO: c'est vraiment utile ça? On l'a déjà fait dans upsert_scheduled_reports_and_entries
        postgres_hook.run(
            sql=REPORT_UPSERT_PROCEDURE,
            parameters={
                "report": str(uuid.uuid4()),
                "project": automation["project_id"],
                "automation": automation["automation_id"],
                "period_day": bucket["period_day"],
                "period_type": bucket["period_type"],
                "period_timezone": bucket["period_timezone"],
                "changes": Json([]),
            },
        )
        report_record = postgres_hook.get_first(
            sql=SQL_REPORT_BY_PERIOD,
            parameters={
                "project_id": automation["project_id"],
                "automation_id": automation["automation_id"],
                "period_day": bucket["period_day"],
                "period_type": bucket["period_type"],
            },
        )
        if not report_record:
            continue

        # TODO: je ne comprend pas SQL_REPORT_SUMMARY_BY_ID, ça parle de CVSS 3.1 dedans
        report_id = str(report_record[0])
        summary = postgres_hook.get_first(
            sql=SQL_REPORT_SUMMARY_BY_ID, parameters={"report_id": report_id}
        )
        cve_count = int(summary[0]) if summary else 0
        score_distribution = summary[1] if summary else []

        report_url = (
            f"{web_base_url}/org/{urllib.parse.quote(automation['organization_name'])}"
            f"/projects/{urllib.parse.quote(automation['project_name'])}/reports/id/{report_id}"
        )

        actions = automation.get("automation_conf", {}).get("actions", [])
        if not actions:
            continue

        due_action_items.append(
            {
                "automation": automation,
                "changes": [],
                "actions": actions,
                "scheduled_report": {
                    "report_id": report_id,
                    "report_day": bucket["period_day"],
                    "period_type": bucket["period_type"],
                    "period_timezone": bucket["period_timezone"],
                    "cve_count": cve_count,
                    "score_distribution": score_distribution,
                    "report_url": report_url,
                },
            }
        )

    redis_set(
        redis_hook,
        automation_action_queue_prefix("scheduled_due"),
        start,
        end,
        {"chunks": chunk_actions(due_action_items)},
    )
    return True


async def execute_actions_async(action_items, changes_details, period):
    max_notifications_per_task = conf.getint("opencve", "max_notifications_per_task")
    semaphore = asyncio.Semaphore(max_notifications_per_task)
    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")

    async with aiohttp.ClientSession(raise_for_status=True) as session:
        tasks = []
        for item in action_items:
            item_changes_details = {
                change_id: changes_details[change_id]
                for change_id in item.get("changes", [])
                if change_id in changes_details
            }
            action_context = {
                "session": session,
                "semaphore": semaphore,
                "postgres_hook": postgres_hook,
                "automation": item["automation"],
                "changes": item.get("changes", []),
                "item_changes_details": item_changes_details,
                "period": period,
                "scheduled_report": item.get("scheduled_report"),
            }
            for action in item["actions"]:

                # TODO: pourquoi faire un if ici?
                if action.get("type") == "send_notification":
                    tasks.append(
                        asyncio.create_task(execute_action(action, action_context))
                    )
                else:
                    await execute_action(action, action_context)

        if tasks:
            await asyncio.gather(*tasks)


def _execute_automation_actions(queue_name: str, **context):
    """
    Runs notification/actions for one logical queue. Payload lives in Redis under
    ``automation_action_queue_*`` as ``{"chunks": [...]}`` (never large XCom).
    """
    start, end = get_dates_from_context(context)
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    prefix = automation_action_queue_prefix(queue_name)
    payload = redis_get(redis_hook, prefix, start, end)
    chunks = payload.get("chunks") or []
    if not chunks:
        return True

    changes_details = redis_get(redis_hook, REDIS_PREFIX_CHANGES_DETAILS, start, end)

    loop = asyncio.get_event_loop()
    for chunk in chunks:
        if not chunk:
            continue
        loop.run_until_complete(
            execute_actions_async(
                action_items=chunk,
                changes_details=changes_details,
                period={"start": start, "end": end},
            )
        )
    return True


@task(task_id="ExecuteRealtimeActions")
def execute_realtime_automation_actions(**context):
    return _execute_automation_actions("realtime", **context)


@task(task_id="SendScheduledReportNotificationsDailyOrWeekly")
def execute_scheduled_due_automation_actions(**context):
    return _execute_automation_actions("scheduled_due", **context)
