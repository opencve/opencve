import asyncio
import importlib
import logging
import uuid
from datetime import datetime, timedelta

import aiohttp
from airflow.configuration import conf
from airflow.decorators import task
from airflow.exceptions import AirflowSkipException
from airflow.providers.postgres.hooks.postgres import PostgresHook
from airflow.providers.redis.hooks.redis import RedisHook
from includes.constants import (
    PRODUCT_SEPARATOR,
    SQL_PROJECT_WITH_AUTOMATIONS,
    SQL_CVE_ID_BY_CVE_ID,
    SQL_CVE_TRACKER_STATUS,
    SQL_UPSERT_CVE_TRACKER,
)
from includes.utils import (
    divide_list,
    group_automations_by_project,
    get_dates_from_context,
)

logger = logging.getLogger(__name__)


# Mapping of CVSS version codes to metric keys
CVSS_VERSION_MAP = {
    "v3.0": "cvssV3_0",
    "v3.1": "cvssV3_1",
    "v4.0": "cvssV4_0",
}


@task
def prepare_automations(**context):
    """
    Fetch automations from the database and store them in Redis.
    """
    start, end = get_dates_from_context(context)

    # Get the list of subscriptions
    subscriptions_redis_key = f"subscriptions_{start}_{end}"
    logger.info(
        "Fetching subscriptions between %s and %s using Redis (key: %s)",
        start,
        end,
        subscriptions_redis_key,
    )
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    subscriptions = redis_hook.json().get(subscriptions_redis_key)
    logger.info("Found %s subscriptions", str(len(subscriptions)))

    # Get the automations and group them by project
    logger.info("Listing automations in %s table", "opencve_automations")
    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")
    records = postgres_hook.get_records(
        sql=SQL_PROJECT_WITH_AUTOMATIONS,
        parameters={"projects": tuple(subscriptions.keys())},
    )
    automations = group_automations_by_project(records, subscriptions)
    if not automations:
        raise AirflowSkipException("No automation found")

    # Save the result in redis
    automations_key = f"automations_{start}_{end}"
    logger.info(
        "Found %s projects with automations, saving it in Redis (key: %s)",
        str(len(automations)),
        automations_key,
    )
    redis_hook.json().set(automations_key, "$", automations)
    redis_hook.expire(automations_key, 60 * 60 * 24)


def evaluate_condition(condition, change_details, cve_trackers=None):
    """
    Evaluate a single condition against change details.
    Returns True if condition is met, False otherwise.
    """
    condition_type = condition.get("type")
    condition_value = condition.get("value")

    change_types = change_details.get("change_types", [])
    cve_metrics = change_details.get("cve_metrics", {})
    cve_vendors = change_details.get("cve_vendors", [])
    cve_id = change_details.get("cve_id", "")

    # CVSS score >= value (unified format with version selection)
    if condition_type == "cvss_gte":
        if isinstance(condition_value, dict):
            version = condition_value.get("version", "v3.1")
            threshold = float(condition_value.get("value", 0))
        else:
            # Fallback for old format
            version = "v3.1"
            threshold = float(condition_value)

        metric_key = CVSS_VERSION_MAP.get(version, "cvssV3_1")
        metric_data = cve_metrics.get(metric_key, {}).get("data", {})
        if metric_data and metric_data.get("score"):
            return float(metric_data["score"]) >= threshold
        return False

    # CVSS score has increased (simplified: check if metrics changed)
    if condition_type == "cvss_increased":
        return "metrics" in change_types

    # CVSS score increased by at least X points (simplified: check if metrics changed)
    if condition_type == "cvss_increased_by":
        return "metrics" in change_types

    # EPSS score >= value
    if condition_type == "epss_gte":
        threshold = float(condition_value)
        epss_data = cve_metrics.get("epss", {}).get("data", {})
        if epss_data and epss_data.get("score"):
            return float(epss_data["score"]) >= threshold
        return False

    # CVE added to KEV catalog
    if condition_type == "kev_added":
        kev_data = cve_metrics.get("kev", {}).get("data", {})
        # Check if KEV data is non-empty or if 'kev' is in change_types
        return bool(kev_data) or "kev" in change_types

    # Vendor equals
    if condition_type == "vendor_equals":
        vendor = condition_value.lower()
        return any(
            v.lower() == vendor for v in cve_vendors if PRODUCT_SEPARATOR not in v
        )

    # Product equals
    if condition_type == "product_equals":
        product = condition_value.lower()
        for v in cve_vendors:
            if PRODUCT_SEPARATOR in v:
                _, p = v.split(PRODUCT_SEPARATOR)
                if p.lower() == product:
                    return True
        return False

    # New vendor affected
    if condition_type == "new_vendor":
        return "vendors" in change_types

    # New product affected
    if condition_type == "new_product":
        return "cpes" in change_types

    # New weakness added
    if condition_type == "new_weakness":
        return "weaknesses" in change_types

    # New reference added
    if condition_type == "new_reference":
        return "references" in change_types

    # Description changed
    if condition_type == "description_changed":
        return "description" in change_types

    # Summary changed
    if condition_type == "summary_changed":
        return "summary" in change_types

    # Title changed
    if condition_type == "title_changed":
        return "title" in change_types

    # CVE newer than X days
    if condition_type == "cve_newer_than":
        days = int(condition_value)
        # Extract year from CVE ID (format: CVE-YYYY-XXXXX)
        try:
            cve_year = int(cve_id.split("-")[1])
            current_year = datetime.now().year
            # Simple approximation: if CVE is from current year, consider it "new"
            # For more precise check, we'd need the actual creation date
            if cve_year >= current_year:
                return True
            # If days is large enough (>365), include previous year CVEs
            if days > 365 and cve_year >= current_year - 1:
                return True
        except (IndexError, ValueError):
            pass
        return False

    # CVE is unassigned (requires tracker info)
    if condition_type == "cve_unassigned":
        if cve_trackers is None:
            return True  # No tracker info available, assume unassigned
        tracker = cve_trackers.get(cve_id)
        if tracker is None:
            return True  # No tracker exists
        return tracker.get("assignee_id") is None

    # CVE status matches
    if condition_type == "cve_status":
        if cve_trackers is None:
            return False  # No tracker info available
        tracker = cve_trackers.get(cve_id)
        if tracker is None:
            return False  # No tracker exists
        return tracker.get("status") == condition_value

    # Query match and view match - not implemented in this phase
    if condition_type in ("query_match", "view_match"):
        logger.warning("Condition type %s is not implemented yet", condition_type)
        return True  # Skip these conditions for now

    logger.warning("Unknown condition type: %s", condition_type)
    return False


def evaluate_all_conditions(conditions, change_details, cve_trackers=None):
    """
    Evaluate all conditions for a change (AND logic).
    Returns True if all conditions are met.
    """
    if not conditions:
        return True

    for condition in conditions:
        if not evaluate_condition(condition, change_details, cve_trackers):
            return False
    return True


def evaluate_condition_tree(tree, change_details, cve_trackers=None):
    """
    Evaluate a conditions tree: OR of AND groups (or single condition nodes).
    Tree node: {"operator": "OR"|"AND", "children": [...]}
    Leaf node: {"type": "...", "value": ...}
    """
    if not tree:
        return False
    if "type" in tree:
        return evaluate_condition(tree, change_details, cve_trackers)
    operator = tree.get("operator")
    children = tree.get("children") or []
    if operator == "OR":
        if not children:
            return False
        return any(
            evaluate_condition_tree(c, change_details, cve_trackers) for c in children
        )
    if operator == "AND":
        return all(
            evaluate_condition_tree(c, change_details, cve_trackers) for c in children
        )
    return False


# Map WHEN trigger types (event automations) to change_types from the pipeline
TRIGGER_TO_CHANGE_TYPES = {
    "cve_created": ["created"],
    "cve_updated": None,  # None = match any change
    "cvss_changed": ["metrics"],
    "cvss_increased": ["metrics"],
    "cvss_decreased": ["metrics"],
    "epss_changed": ["metrics"],
    "kev_added": ["kev"],
    "new_vendor": ["vendors"],
    "new_product": ["cpes"],
    "description_changed": ["description"],
    "title_changed": ["title"],
    "summary_changed": ["summary"],
    "new_reference": ["references"],
    "new_weakness": ["weaknesses"],
    "cve_status_changed": ["tracker_status"],
    "cve_assignment_changed": ["tracker_assignee"],
}


def change_matches_triggers(change_details, triggers):
    """
    Return True if the change matches at least one of the automation's WHEN triggers.
    If triggers is empty or None, return True (backward compat: no WHEN = any change).
    """
    if not triggers:
        return True
    change_types = set(change_details.get("change_types") or [])
    for trigger in triggers:
        mapped = TRIGGER_TO_CHANGE_TYPES.get(trigger)
        if mapped is None:
            return True  # e.g. cve_updated = match any
        if any(ct in change_types for ct in mapped):
            return True
    return False


def filter_changes_for_automation(
    automation, changes, changes_details, cve_trackers=None
):
    """
    Filter changes based on automation triggers (WHEN) and conditions (IF tree).
    Returns list of changes that match triggers and the condition tree.
    """
    automation_conf = automation.get("automation_conf", {})
    conditions_tree = automation_conf.get("conditions")
    triggers = automation_conf.get("triggers") or []
    logger.debug(
        "Filtering with triggers: %s, conditions tree: %s", triggers, conditions_tree
    )

    matching_changes = []
    for change_id in changes:
        change_details = changes_details.get(change_id)
        if not change_details:
            continue
        if not change_matches_triggers(change_details, triggers):
            continue
        if not evaluate_condition_tree(conditions_tree, change_details, cve_trackers):
            continue
        matching_changes.append(change_id)

    return matching_changes


@task
def make_automations_chunks(**context):
    """
    Filter changes based on automation conditions and prepare action chunks.
    """
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    start, end = get_dates_from_context(context)
    logger.info("Checking automations to execute between %s and %s", start, end)

    # Get project changes
    project_changes_key = f"project_changes_{start}_{end}"
    project_changes = redis_hook.json().get(project_changes_key)
    logger.debug(f"{project_changes_key}: %s", project_changes)
    logger.info("Found %s projects with changes", str(len(project_changes)))

    # Get change details
    changes_details_key = f"changes_details_{start}_{end}"
    changes_details = redis_hook.json().get(changes_details_key)
    logger.debug(f"{changes_details_key}: %s", changes_details)

    # Get automations
    automations_key = f"automations_{start}_{end}"
    automations = redis_hook.json().get(automations_key)
    logger.debug(f"{automations_key}: %s", automations)

    if not automations:
        logger.info("No automations found")
        return []

    # Get CVE trackers for conditions that need them
    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")

    # Collect all actions to execute
    actions_to_execute = []

    for project_id, changes in project_changes.items():
        if project_id not in automations:
            continue

        project_automations = automations[project_id]
        logger.info(
            "Checking project %s with %s automation(s)",
            project_id,
            str(len(project_automations)),
        )

        # Get CVE IDs for this project's changes
        cve_ids = list(
            set(changes_details[c]["cve_id"] for c in changes if c in changes_details)
        )

        # Get existing trackers for these CVEs
        cve_trackers = {}
        if cve_ids:
            try:
                tracker_records = postgres_hook.get_records(
                    sql=SQL_CVE_TRACKER_STATUS,
                    parameters={"project_id": project_id, "cve_ids": tuple(cve_ids)},
                )
                for record in tracker_records:
                    cve_trackers[record[0]] = {
                        "status": record[1],
                        "assignee_id": record[2],
                    }
            except Exception as e:
                logger.warning("Could not fetch CVE trackers: %s", e)

        for idx, automation in enumerate(project_automations):
            logger.info(
                "[%s] Parsing %s change(s) for automation %s (%s)",
                project_id,
                str(len(changes)),
                str(idx + 1),
                automation.get("automation_name"),
            )

            # Filter changes based on conditions
            filtered_changes = filter_changes_for_automation(
                automation, changes, changes_details, cve_trackers
            )

            logger.info(
                "[%s] Found %s change(s) matching the automation conditions",
                project_id,
                str(len(filtered_changes)),
            )

            if not filtered_changes:
                continue

            # Prepare actions for these changes
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

    logger.info("Found %s automation actions to execute", str(len(actions_to_execute)))

    # Distribute actions between mapped tasks
    max_automations_map_length = conf.getint(
        "opencve", "max_notifications_map_length", fallback=10
    )
    chunks = divide_list(actions_to_execute, max_automations_map_length)
    logger.debug(
        "Built %s chunks with max_automations_map_length of %s",
        str(len(chunks)),
        str(max_automations_map_length),
    )
    return chunks


async def execute_notification_action(
    session,
    semaphore,
    action,
    automation,
    changes,
    changes_details,
    period,
    postgres_hook,
):
    """
    Execute a send_notification action.
    """
    notification_id = action.get("value")
    if not notification_id:
        logger.warning("No notification ID specified for send_notification action")
        return

    # Fetch notification configuration from database
    notification_record = postgres_hook.get_first(
        sql="""
            SELECT
                notifications.name,
                notifications.type,
                notifications.configuration
            FROM opencve_notifications AS notifications
            WHERE notifications.id = %(notification_id)s
              AND notifications.is_enabled = 't'
        """,
        parameters={"notification_id": notification_id},
    )

    if not notification_record:
        logger.warning("Notification %s not found or disabled", notification_id)
        return

    n_name, n_type, n_conf = notification_record

    # Build notification data structure compatible with existing notifiers
    notification_data = {
        "project_id": automation["project_id"],
        "project_name": automation["project_name"],
        "project_subscriptions": automation["project_subscriptions"],
        "organization_name": automation["organization_name"],
        "notification_name": n_name,
        "notification_type": n_type,
        "notification_conf": n_conf,
    }

    # Get the notifier class
    try:
        notif_cls = getattr(
            importlib.import_module("includes.notifiers"),
            f"{n_type.capitalize()}Notifier",
        )
    except AttributeError:
        logger.error("Unknown notification type: %s", n_type)
        return

    # Execute the notification
    logger.info(
        "Sending notification '%s' (%s) for automation '%s' with %s changes",
        n_name,
        n_type,
        automation["automation_name"],
        len(changes),
    )

    notifier = notif_cls(
        semaphore=semaphore,
        session=session,
        notification=notification_data,
        changes=changes,
        changes_details=changes_details,
        period=period,
    )
    await notifier.execute()


def execute_tracker_action(action, automation, changes, changes_details, postgres_hook):
    """
    Execute assign_user or change_status actions.
    """
    action_type = action.get("type")
    action_value = action.get("value")

    if not action_value:
        logger.warning("No value specified for %s action", action_type)
        return

    project_id = automation["project_id"]

    # Get the internal CVE IDs (UUIDs) from CVE IDs (e.g., CVE-2024-1234)
    cve_id_strings = list(
        set(changes_details[c]["cve_id"] for c in changes if c in changes_details)
    )

    if not cve_id_strings:
        return

    # Fetch internal CVE IDs
    cve_records = postgres_hook.get_records(
        sql=SQL_CVE_ID_BY_CVE_ID,
        parameters={"cve_ids": tuple(cve_id_strings)},
    )

    cve_uuid_map = {record[1]: record[0] for record in cve_records}

    for cve_id_str in cve_id_strings:
        cve_uuid = cve_uuid_map.get(cve_id_str)
        if not cve_uuid:
            logger.warning("Could not find internal ID for CVE %s", cve_id_str)
            continue

        params = {
            "id": str(uuid.uuid4()),
            "cve_id": cve_uuid,
            "project_id": project_id,
            "assignee_id": None,
            "status": None,
        }

        if action_type == "assign_user":
            params["assignee_id"] = action_value
            logger.info(
                "Assigning CVE %s to user %s in project %s",
                cve_id_str,
                action_value,
                project_id,
            )
        elif action_type == "change_status":
            params["status"] = action_value
            logger.info(
                "Changing status of CVE %s to '%s' in project %s",
                cve_id_str,
                action_value,
                project_id,
            )

        try:
            postgres_hook.run(sql=SQL_UPSERT_CVE_TRACKER, parameters=params)
        except Exception as e:
            logger.error(
                "Failed to update tracker for CVE %s: %s",
                cve_id_str,
                e,
            )


async def execute_actions_async(action_items, changes_details, period):
    """
    Execute all actions asynchronously.
    """
    max_notifications_per_task = conf.getint("opencve", "max_notifications_per_task")
    semaphore = asyncio.Semaphore(max_notifications_per_task)

    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")

    tasks = []
    async with aiohttp.ClientSession(raise_for_status=True) as session:
        for item in action_items:
            automation = item["automation"]
            changes = item["changes"]
            actions = item["actions"]

            # Get full change details for these changes
            item_changes_details = {
                c: changes_details[c] for c in changes if c in changes_details
            }

            for action in actions:
                action_type = action.get("type")

                if action_type == "send_notification":
                    tasks.append(
                        asyncio.ensure_future(
                            execute_notification_action(
                                session,
                                semaphore,
                                action,
                                automation,
                                changes,
                                item_changes_details,
                                period,
                                postgres_hook,
                            )
                        )
                    )
                elif action_type in ("assign_user", "change_status"):
                    # Execute tracker actions synchronously (they're fast DB operations)
                    execute_tracker_action(
                        action,
                        automation,
                        changes,
                        item_changes_details,
                        postgres_hook,
                    )

        if tasks:
            await asyncio.gather(*tasks)


@task
def execute_automation_actions(action_items, **context):
    """
    Execute automation actions for a chunk of items.
    """
    logger.info("Executing %s automation action items", str(len(action_items)))
    logger.debug("Action items: %s", action_items)

    if not action_items:
        return True

    # Retrieve change details
    start, end = get_dates_from_context(context)
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    changes_details_key = f"changes_details_{start}_{end}"
    changes_details = redis_hook.json().get(changes_details_key)

    loop = asyncio.get_event_loop()
    loop.run_until_complete(
        execute_actions_async(
            action_items,
            changes_details,
            {"start": start, "end": end},
        )
    )

    logger.info("Automation actions executed successfully")
    return True
