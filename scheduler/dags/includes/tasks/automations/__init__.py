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
    SQL_INSERT_AUTOMATION_EXECUTION,
    SQL_INSERT_AUTOMATION_EXECUTION_RESULT,
    SQL_CVE_TRACKER_STATUS,
    SQL_PROJECT_WITH_AUTOMATIONS,
    SQL_REPORT_CVES_DETAILS_BY_ID,
    SQL_REPORT_SUMMARY_BY_ID,
    SQL_REPORT_DUE_AUTOMATIONS,
    SQL_UPDATE_AUTOMATION_LAST_EXECUTION_AT,
)
from includes.storage import (
    REDIS_PREFIX_AUTOMATIONS,
    REDIS_PREFIX_CHANGES_DETAILS,
    REDIS_PREFIX_REPORT_DUE_WORK_ITEMS,
    REDIS_PREFIX_REPORT_HOURLY_CONTENT_ITEMS,
    REDIS_PREFIX_SUBSCRIPTIONS,
    REDIS_PREFIX_VENDOR_CHANGES,
    automation_action_queue_prefix,
    redis_get,
    redis_set,
)
from includes.tasks.automations.actions import (
    ACTION_TYPE_TO_OUTPUT,
    RESULT_STATUS_FAILED,
    execute_action,
)
from includes.tasks.automations.conditions import evaluate_condition_tree
from includes.tasks.automations.triggers import evaluate_triggers
from includes.tasks.automations.utils import as_number
from includes.utils import (
    divide_list,
    get_dates_from_context,
    group_automations_by_project,
    list_changes_by_project,
)
from psycopg2.extras import Json

logger = logging.getLogger(__name__)

SQL_REPORT_BY_PERIOD = """
SELECT id
FROM opencve_reports
WHERE project_id = %(project_id)s
  AND automation_id = %(automation_id)s
  AND day = %(period_day)s
  AND period_type = %(period_type)s
LIMIT 1;
"""


def _cvss_score_to_severity(score):
    if score is None:
        return None
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    return "Low"


def _all_matching_subscriptions(automation, cve_vendors):
    subscriptions = automation.get("project_subscriptions") or []
    vendors = cve_vendors or []
    matched = []
    for sub in subscriptions:
        if sub in vendors:
            label = sub.split("$PRODUCT$", 1)[1] if "$PRODUCT$" in sub else sub
            if label not in matched:
                matched.append(label)
    if not matched:
        for vendor in vendors:
            label = vendor.split("$PRODUCT$", 1)[1] if "$PRODUCT$" in vendor else vendor
            if label not in matched:
                matched.append(label)
    return matched


def build_cves_table_data(automation, item_changes_details):
    cve_rows = {}
    for _, change_details in item_changes_details.items():
        cve_id = change_details.get("cve_id")
        if not cve_id:
            continue
        metrics = change_details.get("cve_metrics") or {}
        cvss_31 = as_number(
            (metrics.get("cvssV3_1") or {}).get("data", {}).get("score")
        )
        cvss_30 = as_number(
            (metrics.get("cvssV3_0") or {}).get("data", {}).get("score")
        )
        cvss_20 = as_number(
            (metrics.get("cvssV2_0") or {}).get("data", {}).get("score")
        )
        cvss_40 = as_number(
            (metrics.get("cvssV4_0") or {}).get("data", {}).get("score")
        )
        epss = as_number((metrics.get("epss") or {}).get("data", {}).get("score"))
        kev = bool((metrics.get("kev") or {}).get("data"))
        matched_vendors_or_products = _all_matching_subscriptions(
            automation, change_details.get("cve_vendors") or []
        )
        cve_rows[cve_id] = {
            "cve_id": cve_id,
            "cvss_31": cvss_31,
            "cvss_30": cvss_30,
            "cvss_20": cvss_20,
            "cvss_40": cvss_40,
            "epss": epss,
            "kev": kev,
            "matched_vendors_or_products": matched_vendors_or_products,
        }
    return list(cve_rows.values())


def build_report_item_changes_details(postgres_hook, report_id):
    rows = postgres_hook.get_records(
        sql=SQL_REPORT_CVES_DETAILS_BY_ID,
        parameters={"report_id": report_id},
    )
    return {
        row[0]: {"cve_id": row[0], "cve_metrics": row[1], "cve_vendors": row[2]}
        for row in (rows or [])
    }


def build_impact_summary_from_cves_table(cves_table_data):
    if not cves_table_data:
        return None
    distribution = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    highest_cvss = None
    highest_cvss_version = None
    cvss_scores = []
    epss_values = []
    epss_distribution = {"high": 0, "medium": 0, "low": 0}
    kev_count = 0
    vendor_counts = {}
    for row in cves_table_data:
        scores = {
            "cvss_40": as_number(row.get("cvss_40")),
            "cvss_31": as_number(row.get("cvss_31")),
            "cvss_30": as_number(row.get("cvss_30")),
            "cvss_20": as_number(row.get("cvss_20")),
        }
        filtered_scores = {k: v for k, v in scores.items() if v is not None}
        if filtered_scores:
            version, score = max(filtered_scores.items(), key=lambda item: item[1])
            severity = _cvss_score_to_severity(score)
            if severity:
                distribution[severity] += 1
            cvss_scores.append(score)
            if highest_cvss is None or score > highest_cvss:
                highest_cvss = score
                highest_cvss_version = version
        epss = as_number(row.get("epss"))
        if epss is not None:
            epss_values.append(epss)
            if epss > 0.9:
                epss_distribution["high"] += 1
            elif epss >= 0.7:
                epss_distribution["medium"] += 1
            else:
                epss_distribution["low"] += 1
        if row.get("kev"):
            kev_count += 1
        for vp in row.get("matched_vendors_or_products") or []:
            if vp:
                vendor_counts[vp] = vendor_counts.get(vp, 0) + 1
    cves_count = len(cves_table_data)
    return {
        "cvss_distribution": distribution,
        "highest_cvss": round(highest_cvss, 1) if highest_cvss is not None else None,
        "highest_cvss_version": highest_cvss_version,
        "average_cvss": (
            round(sum(cvss_scores) / len(cvss_scores), 1) if cvss_scores else None
        ),
        "epss_distribution": epss_distribution,
        "epss_avg": (
            round(sum(epss_values) / len(epss_values), 2) if epss_values else None
        ),
        "epss_max": round(max(epss_values), 2) if epss_values else None,
        "kev_count": kev_count,
        "cves_count": cves_count,
        "kev_percent": int(round(100 * kev_count / cves_count)) if cves_count else 0,
        "top_vendors_products": [
            {"name": name, "count": count}
            for name, count in sorted(vendor_counts.items(), key=lambda item: -item[1])[
                :5
            ]
        ],
    }


def update_automations_last_execution(postgres_hook, automation_ids, executed_at):
    if not automation_ids:
        return
    postgres_hook.run(
        sql=SQL_UPDATE_AUTOMATION_LAST_EXECUTION_AT,
        parameters={
            "automation_ids": tuple(automation_ids),
            "executed_at": executed_at,
        },
    )


def insert_automation_execution(postgres_hook, item, period, item_changes_details):
    execution_id = str(uuid.uuid4())
    automation = item["automation"]
    report_content = item.get("report_content") or {}
    cves_table_data = build_cves_table_data(automation, item_changes_details)
    impact_summary = build_impact_summary_from_cves_table(cves_table_data)
    postgres_hook.run(
        sql=SQL_INSERT_AUTOMATION_EXECUTION,
        parameters={
            "id": execution_id,
            "executed_at": period["end"],
            "window_start": period["start"],
            "window_end": period["end"],
            "matched_cves_count": len(cves_table_data),
            "automation_id": automation["automation_id"],
            "report_id": report_content.get("report_id"),
            "impact_summary": Json(impact_summary),
            "cves_table_data": Json(cves_table_data),
        },
    )
    return execution_id


def insert_automation_execution_result(
    postgres_hook, execution_id, action, action_result
):
    action_type = action.get("type")
    output_type, label = ACTION_TYPE_TO_OUTPUT.get(
        action_type,
        (
            action_type or "unknown",
            (action_type or "unknown").replace("_", " ").title(),
        ),
    )
    result_status = (action_result or {}).get("status") or RESULT_STATUS_FAILED
    details = (action_result or {}).get("details") or {}
    output_type = (action_result or {}).get("output_type", output_type)
    label = (action_result or {}).get("label", label)
    postgres_hook.run(
        sql=SQL_INSERT_AUTOMATION_EXECUTION_RESULT,
        parameters={
            "id": str(uuid.uuid4()),
            "automation_execution_id": execution_id,
            "output_type": output_type,
            "label": label,
            "status": result_status,
            "details": Json(details),
        },
    )


def _get_timezone_name(automation):
    return automation.get("schedule_timezone") or "UTC"


def get_accumulation_period_bucket(automation, context):
    local_anchor = (
        context["data_interval_end"]
        .in_timezone(_get_timezone_name(automation))
        .subtract(seconds=1)
    )
    frequency = automation.get("frequency")

    # BACKLOG: weekly accumulation currently anchors to the ISO start-of-week (Monday).
    # The intended behaviour is to anchor to the day before the scheduled send time
    # (e.g. user picks Wednesday 09:00 → window covers Wednesday-7d 00:00 to Tuesday 23:59).
    # Changing the anchor requires migrating existing report rows and adjusting the unique
    # constraint; defer until the report bucketing strategy is finalized.
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
    conditions_tree = automation.get("automation_conf", {}).get("conditions")
    triggers = automation.get("automation_conf", {}).get("triggers") or []
    trigger_type = automation.get("trigger_type")

    matching_changes = []
    for change_id in changes:
        change_details = changes_details.get(change_id)
        if not change_details:
            continue

        if trigger_type == "alert" and not evaluate_triggers(
            triggers=triggers, change_details=change_details, automation=automation
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
    max_map_length = conf.getint("opencve", "max_automations_map_length")
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


@task(task_id="BuildAlertWorkItems")
def build_alert_work_items(**context):
    start, end = get_dates_from_context(context)
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")

    def _empty_queue():
        redis_set(
            redis_hook,
            automation_action_queue_prefix("alert"),
            start,
            end,
            {"chunks": []},
        )
        return True

    # List the automations by project
    automations = redis_get(redis_hook, REDIS_PREFIX_AUTOMATIONS, start, end)
    if not automations:
        return _empty_queue()

    # Update last_execution_at for every alert automation evaluated this run.
    alert_automation_ids = []
    for project_automations in automations.values():
        for automation in project_automations or []:
            if automation.get("trigger_type") == "alert":
                alert_automation_ids.append(automation["automation_id"])
    update_automations_last_execution(postgres_hook, alert_automation_ids, end)

    # Group the changes by project
    project_changes = get_project_changes(redis_hook, start, end)
    if not project_changes:
        return _empty_queue()
    logger.debug("List of project changes: %s", project_changes)

    # List the changes details
    changes_details = redis_get(redis_hook, REDIS_PREFIX_CHANGES_DETAILS, start, end)

    # For each project, build the actions to execute
    actions_to_execute = []
    for project_id, changes in project_changes.items():
        project_automations = automations.get(project_id) or []

        # Only keep the alert automations
        alert_automations = [
            a for a in project_automations if a.get("trigger_type") == "alert"
        ]
        if not alert_automations:
            continue

        # PERF: one SQL query per project per hourly run. For users with many projects
        # this can become a bottleneck. Consider batching all CVE-ID lookups across
        # projects in a single query before this loop, then filtering in-memory.
        cve_trackers = get_trackers_for_project(
            postgres_hook, project_id, changes, changes_details
        )
        for automation in alert_automations:
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

    logger.info("Found %s actions to execute", len(actions_to_execute))
    chunks = chunk_actions(actions_to_execute)
    redis_set(
        redis_hook,
        automation_action_queue_prefix("alert"),
        start,
        end,
        {"chunks": chunks},
    )
    return True


@task(task_id="BuildReportContentHourly")
def build_report_content_hourly(**context):
    start, end = get_dates_from_context(context)
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    changes_details = redis_get(redis_hook, REDIS_PREFIX_CHANGES_DETAILS, start, end)
    automations = redis_get(redis_hook, REDIS_PREFIX_AUTOMATIONS, start, end)
    project_changes = get_project_changes(redis_hook, start, end)
    if not automations:
        redis_set(redis_hook, REDIS_PREFIX_REPORT_HOURLY_CONTENT_ITEMS, start, end, [])
        return True

    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")
    report_automation_ids = []
    for project_automations in automations.values():
        for automation in project_automations or []:
            if automation.get("trigger_type") == "report":
                report_automation_ids.append(automation["automation_id"])
    update_automations_last_execution(postgres_hook, report_automation_ids, end)
    items = []

    for project_id, project_automations in automations.items():

        # Only keep the report automations
        report_automations = [
            a for a in (project_automations or []) if a.get("trigger_type") == "report"
        ]
        if not report_automations:
            continue

        # PERF: same N+1 pattern as in build_alert_work_items — see note there.
        project_hourly_changes = project_changes.get(project_id, [])
        cve_trackers = get_trackers_for_project(
            postgres_hook, project_id, project_hourly_changes, changes_details
        )

        for automation in report_automations:
            filtered_changes = filter_changes_for_automation(
                automation=automation,
                changes=project_hourly_changes,
                changes_details=changes_details,
                cve_trackers=cve_trackers,
            )

            # If no changes were found, skip the report
            if not filtered_changes:
                continue

            period_bucket = get_accumulation_period_bucket(automation, context)
            items.append(
                {
                    "automation": automation,
                    "changes": filtered_changes,
                    "period_bucket": period_bucket,
                }
            )

    redis_set(redis_hook, REDIS_PREFIX_REPORT_HOURLY_CONTENT_ITEMS, start, end, items)
    return True


@task(task_id="UpsertReportContentAndEntries")
def upsert_report_content_and_entries(**context):
    start, end = get_dates_from_context(context)
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    scheduled_hourly_items = redis_get(
        redis_hook,
        REDIS_PREFIX_REPORT_HOURLY_CONTENT_ITEMS,
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

        # BACKLOG: the old populate_reports task caught IntegrityError/DataError in case
        # a project was deleted between the subscription resolution and this upsert.
        # The UPSERT procedure is idempotent so concurrent deletions should be harmless,
        # but consider wrapping in a try/except if orphan-row errors occur in production.
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


@task(task_id="EvaluateReportDueInAutomationTimezone", trigger_rule="none_failed")
def evaluate_report_due_in_automation_timezone(**context):
    start, end = get_dates_from_context(context)
    data_interval_end = context["data_interval_end"]

    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    postgres_hook = PostgresHook(postgres_conn_id="opencve_postgres")

    records = postgres_hook.get_records(
        sql=SQL_REPORT_DUE_AUTOMATIONS,
        parameters={"data_interval_end": data_interval_end},
    )

    if not records:
        redis_set(redis_hook, REDIS_PREFIX_REPORT_DUE_WORK_ITEMS, start, end, [])
        return True

    due_work_items = []
    due_automation_ids = []

    for record in records:
        (
            p_id,
            p_name,
            o_name,
            a_id,
            a_name,
            a_trigger,
            a_frequency,
            a_timezone,
            a_time,
            a_weekday,
            a_conf,
            p_subscriptions,
        ) = record

        project_subscriptions = (
            (
                (p_subscriptions.get("vendors") or [])
                + (p_subscriptions.get("products") or [])
            )
            if p_subscriptions
            else []
        )

        automation = {
            "project_id": p_id,
            "project_name": p_name,
            "project_subscriptions": project_subscriptions,
            "organization_name": o_name,
            "automation_id": a_id,
            "automation_name": a_name,
            "trigger_type": a_trigger,
            "frequency": a_frequency,
            "schedule_timezone": a_timezone,
            "schedule_time": (
                a_time.strftime("%H:%M") if hasattr(a_time, "strftime") else None
            ),
            "schedule_weekday": a_weekday,
            "automation_conf": a_conf,
        }

        due_automation_ids.append(a_id)
        due_work_items.append(
            {
                "automation": automation,
                "period_bucket": get_due_period_bucket(automation, context),
            }
        )

    update_automations_last_execution(postgres_hook, due_automation_ids, end)
    redis_set(
        redis_hook, REDIS_PREFIX_REPORT_DUE_WORK_ITEMS, start, end, due_work_items
    )
    return True


@task(task_id="BuildReportNotificationPayload")
def build_report_notification_payload(**context):
    start, end = get_dates_from_context(context)
    redis_hook = RedisHook(redis_conn_id="opencve_redis").get_conn()
    due_work_items = redis_get(
        redis_hook,
        REDIS_PREFIX_REPORT_DUE_WORK_ITEMS,
        start,
        end,
        default=[],
    )

    if not due_work_items:
        redis_set(
            redis_hook,
            automation_action_queue_prefix("report_due"),
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

        # NOTE: SQL_REPORT_SUMMARY_BY_ID computes score_distribution using cvssV3_1 only.
        # This is intentional for the email summary (CVSS 3.1 is the most widely reported
        # version). The execution impact_summary stored by the scheduler uses all CVSS
        # versions via build_cves_table_data / build_impact_summary_from_cves_table.
        # If multi-version score distribution in emails becomes a requirement, replace
        # SQL_REPORT_SUMMARY_BY_ID with the richer pre-computed impact_summary JSON.
        report_id = str(report_record[0])
        summary = postgres_hook.get_first(
            sql=SQL_REPORT_SUMMARY_BY_ID, parameters={"report_id": report_id}
        )

        # If no CVEs were found, skip the report
        cve_count = int(summary[0]) if summary else 0
        if cve_count == 0:
            continue

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
                "report_content": {
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
        automation_action_queue_prefix("report_due"),
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
        for item in action_items:
            item_changes_details = {
                change_id: changes_details[change_id]
                for change_id in item.get("changes", [])
                if change_id in changes_details
            }
            report_id = (item.get("report_content") or {}).get("report_id")
            if not item_changes_details and report_id:
                item_changes_details = build_report_item_changes_details(
                    postgres_hook, report_id
                )
            execution_id = insert_automation_execution(
                postgres_hook=postgres_hook,
                item=item,
                period=period,
                item_changes_details=item_changes_details,
            )
            action_context = {
                "session": session,
                "semaphore": semaphore,
                "postgres_hook": postgres_hook,
                "automation": item["automation"],
                "changes": item.get("changes", []),
                "item_changes_details": item_changes_details,
                "period": period,
                "report_content": item.get("report_content"),
            }
            notification_tasks = []
            for action in item["actions"]:

                # send_notification actions are dispatched concurrently via asyncio.gather
                # (collected below) to parallelise HTTP calls. All other action types
                # (assign_user, change_status, …) are awaited inline because they are
                # short database writes that don't benefit from concurrency.
                if action.get("type") == "send_notification":
                    notification_tasks.append(
                        (
                            action,
                            asyncio.create_task(execute_action(action, action_context)),
                        )
                    )
                else:
                    action_result = await execute_action(action, action_context)
                    insert_automation_execution_result(
                        postgres_hook=postgres_hook,
                        execution_id=execution_id,
                        action=action,
                        action_result=action_result,
                    )

            if notification_tasks:
                task_outputs = await asyncio.gather(
                    *[task for _, task in notification_tasks], return_exceptions=True
                )
                for (action, _), action_result in zip(notification_tasks, task_outputs):
                    if isinstance(action_result, Exception):
                        action_result = {
                            "status": RESULT_STATUS_FAILED,
                            "details": {"summary": str(action_result)},
                        }
                    insert_automation_execution_result(
                        postgres_hook=postgres_hook,
                        execution_id=execution_id,
                        action=action,
                        action_result=action_result,
                    )


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


@task(task_id="ExecuteAlertActions")
def execute_alert_automation_actions(**context):
    return _execute_automation_actions("alert", **context)


@task(task_id="SendReportNotificationsDailyOrWeekly", trigger_rule="none_failed")
def execute_report_due_automation_actions(**context):
    return _execute_automation_actions("report_due", **context)
