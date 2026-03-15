import asyncio
import logging

import aiohttp
from airflow.configuration import conf
from airflow.decorators import task
from airflow.exceptions import AirflowSkipException
from airflow.providers.postgres.hooks.postgres import PostgresHook
from airflow.providers.redis.hooks.redis import RedisHook
from includes.constants import SQL_CVE_TRACKER_STATUS, SQL_PROJECT_WITH_AUTOMATIONS
from includes.tasks.automations.actions import execute_action
from includes.tasks.automations.conditions import evaluate_condition_tree
from includes.utils import (
    divide_list,
    get_dates_from_context,
    group_automations_by_project,
)

logger = logging.getLogger(__name__)

TRIGGER_TO_CHANGE_TYPES = {
    "cve_enters_project": {"created"},
    "cvss_increased": {"metrics"},
    "cvss_decreased": {"metrics"},
    "epss_increased": {"metrics"},
    "epss_decreased": {"metrics"},
    "kev_added": {"kev"},
    "new_vendor": {"vendors"},
    "new_product": {"cpes"},
    "description_changed": {"description"},
    "title_changed": {"title"},
    "new_reference": {"references"},
    "new_weakness": {"weaknesses"},
}


def change_matches_triggers(change_details, triggers):
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


def is_automation_due(automation, context):
    if automation.get("trigger_type") != "scheduled":
        return True

    run_end = context["data_interval_end"]
    if not (run_end.hour == 0 and run_end.minute == 0):
        return False

    frequency = automation.get("frequency")
    if frequency == "daily":
        return True
    if frequency == "weekly":
        return run_end.weekday() == 0

    logger.warning("Unsupported automation frequency: %s", frequency)
    return False


def filter_changes_for_automation(automation, changes, changes_details, cve_trackers):
    config = automation.get("automation_conf") or {}
    conditions_tree = config.get("conditions")
    triggers = config.get("triggers") or []
    trigger_type = automation.get("trigger_type")

    matching_changes = []
    for change_id in changes:
        change_details = changes_details.get(change_id)
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


@task
def prepare_automations(**context):
    start, end = get_dates_from_context(context)
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()

    subscriptions = redis_hook.json().get(f"subscriptions_{start}_{end}") or {}
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

    automations_key = f"automations_{start}_{end}"
    redis_hook.json().set(automations_key, "$", automations)
    redis_hook.expire(automations_key, 60 * 60 * 24)


@task
def make_automations_chunks(**context):
    start, end = get_dates_from_context(context)
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()

    project_changes = redis_hook.json().get(f"project_changes_{start}_{end}") or {}
    changes_details = redis_hook.json().get(f"changes_details_{start}_{end}") or {}
    automations = redis_hook.json().get(f"automations_{start}_{end}") or {}
    if not project_changes or not automations:
        return []

    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")
    actions_to_execute = []

    for project_id, changes in project_changes.items():
        project_automations = automations.get(project_id) or []
        if not project_automations:
            continue

        cve_ids = list(
            set(
                changes_details[change_id]["cve_id"]
                for change_id in changes
                if change_id in changes_details
            )
        )
        cve_trackers = {}
        if cve_ids:
            tracker_records = postgres_hook.get_records(
                sql=SQL_CVE_TRACKER_STATUS,
                parameters={"project_id": project_id, "cve_ids": tuple(cve_ids)},
            )
            cve_trackers = {
                record[0]: {"status": record[1], "assignee_id": record[2]}
                for record in tracker_records
            }

        for automation in project_automations:
            if not is_automation_due(automation, context):
                continue

            filtered_changes = filter_changes_for_automation(
                automation=automation,
                changes=changes,
                changes_details=changes_details,
                cve_trackers=cve_trackers,
            )
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

    max_map_length = conf.getint(
        "opencve",
        "max_automations_map_length",
        fallback=conf.getint("opencve", "max_notifications_map_length", fallback=10),
    )
    return divide_list(actions_to_execute, max_map_length)


async def execute_actions_async(action_items, changes_details, period):
    max_notifications_per_task = conf.getint("opencve", "max_notifications_per_task")
    semaphore = asyncio.Semaphore(max_notifications_per_task)
    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")

    async with aiohttp.ClientSession(raise_for_status=True) as session:
        tasks = []
        for item in action_items:
            item_changes_details = {
                change_id: changes_details[change_id]
                for change_id in item["changes"]
                if change_id in changes_details
            }
            action_context = {
                "session": session,
                "semaphore": semaphore,
                "postgres_hook": postgres_hook,
                "automation": item["automation"],
                "changes": item["changes"],
                "item_changes_details": item_changes_details,
                "period": period,
            }
            for action in item["actions"]:
                if action.get("type") == "send_notification":
                    tasks.append(
                        asyncio.create_task(execute_action(action, action_context))
                    )
                else:
                    await execute_action(action, action_context)

        if tasks:
            await asyncio.gather(*tasks)


@task
def execute_automation_actions(action_items, **context):
    if not action_items:
        return True

    start, end = get_dates_from_context(context)
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    changes_details = redis_hook.json().get(f"changes_details_{start}_{end}") or {}

    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        execute_actions_async(
            action_items=action_items,
            changes_details=changes_details,
            period={"start": start, "end": end},
        )
    )
    return True
