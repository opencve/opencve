"""
End-to-end lifecycle tests for the full automation pipeline.

Each test sets up realistic DB state (org, project, subscriptions, automations),
ingests CVEs via ProcessKbOperator, then runs every downstream Airflow task in
sequence and asserts the expected side-effects in PostgreSQL and Redis.
"""

import json
from unittest.mock import patch

import pendulum
import pytest

from includes.operators.process_kb_operator import ProcessKbOperator
from includes.tasks.reports import collect_hourly_changes, resolve_subscriptions
from includes.tasks.automations import (
    load_enabled_automations,
    build_alert_work_items,
    execute_alert_automation_actions,
    build_report_content_hourly,
    upsert_report_content_and_entries,
    evaluate_report_due_in_automation_timezone,
    build_report_notification_payload,
    execute_report_due_automation_actions,
    get_report_period_window,
)
from includes.storage import (
    REDIS_PREFIX_AUTOMATION_ACTION_QUEUE_ALERT,
    REDIS_PREFIX_AUTOMATION_ACTION_QUEUE_REPORT_DUE,
    REDIS_PREFIX_AUTOMATIONS,
    REDIS_PREFIX_CHANGES_DETAILS,
    REDIS_PREFIX_REPORT_DUE_WORK_ITEMS,
    REDIS_PREFIX_REPORT_HOURLY_CONTENT_ITEMS,
    REDIS_PREFIX_SUBSCRIPTIONS,
    REDIS_PREFIX_VENDOR_CHANGES,
    redis_get,
)
from utils import TestRepo


ORG_ID = "16674ce5-ef22-4b27-8368-6d2d0ec7191e"
PROJECT_ID = "0439aa01-62b3-465c-ba7b-bd07c961c778"
AUTOMATION_ALERT_ID = "aaaa0001-0001-0001-0001-000000000001"
AUTOMATION_REPORT_ID = "aaaa0002-0002-0002-0002-000000000002"
NOTIFICATION_ID = "bbbb0001-0001-0001-0001-000000000001"
USER_ID = "cccc0001-0001-0001-0001-000000000001"


def _ctx(start, end):
    """Build an Airflow-like context dict."""
    return {"data_interval_start": start, "data_interval_end": end}


def _setup_org_and_project(web_pg_hook):
    """Insert organization, project subscribed to vendor 'foo', and a test user."""
    web_pg_hook.run(
        f"""
        INSERT INTO opencve_organizations (id, created_at, updated_at, name)
        VALUES ('{ORG_ID}', now(), now(), 'test-org');

        INSERT INTO opencve_projects (
            id, created_at, updated_at, name, description,
            subscriptions, organization_id, active
        )
        VALUES (
            '{PROJECT_ID}', now(), now(), 'test-project', '',
            '{{"vendors": ["foo"], "products": ["foo$PRODUCT$bar"]}}'::jsonb,
            '{ORG_ID}', 't'
        );

        INSERT INTO opencve_users (id, created_at, updated_at, password, last_login,
            is_superuser, username, first_name, last_name, email, is_staff,
            is_active, date_joined, settings)
        VALUES (
            '{USER_ID}', now(), now(), '', NULL,
            false, 'testuser', '', '', 'test@example.com', false,
            true, now(), '{{}}'::jsonb
        );
        """
    )


def _setup_alert_automation(web_pg_hook, cvss_threshold=7.0):
    """Insert an alert automation with cvss_gte condition and change_status + assign_user actions."""
    config = {
        "triggers": [],
        "conditions": {"type": "cvss_gte", "value": cvss_threshold},
        "actions": [
            {"type": "change_status", "value": "in_triage", "label": "In Triage"},
            {"type": "assign_user", "value": USER_ID, "username": "testuser"},
        ],
    }
    web_pg_hook.run(
        f"""
        INSERT INTO opencve_automations (
            id, created_at, updated_at, name, trigger_type,
            frequency, schedule_timezone, schedule_time, schedule_weekday,
            configuration, project_id, is_enabled
        )
        VALUES (
            '{AUTOMATION_ALERT_ID}', now(), now(), 'my-alert', 'alert',
            'daily', 'UTC', '00:00:00', NULL,
            '{json.dumps(config)}'::jsonb, '{PROJECT_ID}', true
        );
        """
    )


def _setup_report_automation(web_pg_hook, schedule_time="09:00:00", frequency="daily"):
    """Insert a report automation with daily schedule at the given time."""
    config = {
        "triggers": [],
        "conditions": {"type": "cvss_gte", "value": 0},
        "actions": [
            {"type": "generate_report", "value": True},
        ],
    }
    web_pg_hook.run(
        f"""
        INSERT INTO opencve_automations (
            id, created_at, updated_at, name, trigger_type,
            frequency, schedule_timezone, schedule_time, schedule_weekday,
            configuration, project_id, is_enabled
        )
        VALUES (
            '{AUTOMATION_REPORT_ID}', now(), now(), 'my-report', 'report',
            '{frequency}', 'UTC', '{schedule_time}', NULL,
            '{json.dumps(config)}'::jsonb, '{PROJECT_ID}', true
        );
        """
    )


def _ingest_cve(repo, context):
    """Run ProcessKbOperator against our test KB repo."""
    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path):
        operator = ProcessKbOperator(task_id="process_kb_test")
        operator.execute(context)


def _run_pipeline_until_automations_loaded(repo, context, web_redis_hook):
    """Run CollectHourlyChanges, ResolveSubscriptions, LoadEnabledAutomations."""
    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path), patch(
        "includes.tasks.reports.KB_LOCAL_REPO", repo.repo_path
    ):
        collect_hourly_changes.function(**context)

    resolve_subscriptions.function(**context)
    load_enabled_automations.function(**context)

    start = context["data_interval_start"]
    end = context["data_interval_end"].subtract(seconds=1)
    return redis_get(web_redis_hook, REDIS_PREFIX_CHANGES_DETAILS, start, end)


# ---------------------------------------------------------------------------
# Alert lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.web_db
@pytest.mark.web_redis
def test_alert_automation_full_lifecycle(
    tests_path, tmp_path_factory, web_pg_hook, web_redis_hook, override_conf
):
    """Complete alert pipeline: ingest CVE, match conditions, execute actions."""
    override_conf("opencve", "max_automations_map_length", "10")
    override_conf("opencve", "max_notifications_per_task", "5")

    start = pendulum.datetime(2024, 1, 1, 1, 0, tz="UTC")
    end = pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC")
    context = _ctx(start, end)
    end_adj = end.subtract(seconds=1)

    # 1. Setup
    _setup_org_and_project(web_pg_hook)
    _setup_alert_automation(web_pg_hook, cvss_threshold=7.0)

    # 2. Ingest CVE (CVSS 8.8 -> above threshold)
    repo = TestRepo("changes", tests_path, tmp_path_factory)
    repo.commit(["0001/CVE-2024-6962.v1.json"], hour=1, minute=0)
    _ingest_cve(repo, context)

    # 3-5. CollectHourlyChanges -> ResolveSubscriptions -> LoadEnabledAutomations
    changes_details = _run_pipeline_until_automations_loaded(
        repo, context, web_redis_hook
    )
    assert len(changes_details) == 1
    change_id = list(changes_details.keys())[0]

    vendor_changes = redis_get(
        web_redis_hook, REDIS_PREFIX_VENDOR_CHANGES, start, end_adj
    )
    assert "foo" in vendor_changes

    subscriptions = redis_get(
        web_redis_hook, REDIS_PREFIX_SUBSCRIPTIONS, start, end_adj
    )
    assert PROJECT_ID in subscriptions

    automations = redis_get(web_redis_hook, REDIS_PREFIX_AUTOMATIONS, start, end_adj)
    assert PROJECT_ID in automations
    assert automations[PROJECT_ID][0]["automation_id"] == AUTOMATION_ALERT_ID

    # 6. BuildAlertWorkItems
    build_alert_work_items.function(**context)

    action_queue = redis_get(
        web_redis_hook,
        REDIS_PREFIX_AUTOMATION_ACTION_QUEUE_ALERT,
        start,
        end_adj,
    )
    chunks = action_queue.get("chunks", [])
    assert len(chunks) >= 1
    first_batch = chunks[0]
    assert len(first_batch) >= 1
    assert first_batch[0]["automation"]["automation_id"] == AUTOMATION_ALERT_ID
    assert change_id in first_batch[0]["changes"]

    # 7. ExecuteAlertActions
    execute_alert_automation_actions.function(**context)

    # Verify automation execution was recorded
    executions = web_pg_hook.get_records(
        "SELECT automation_id, matched_cves_count FROM opencve_automation_executions;"
    )
    assert len(executions) >= 1
    assert executions[0][0] == AUTOMATION_ALERT_ID
    assert executions[0][1] >= 1

    # Verify execution results (change_status + assign_user)
    results = web_pg_hook.get_records(
        "SELECT output_type, status FROM opencve_automation_execution_results ORDER BY output_type;"
    )
    output_types = {r[0] for r in results}
    assert "assignment" in output_types
    assert "status_change" in output_types
    for r in results:
        assert r[1] == "success"

    # Verify CVE tracker was created
    trackers = web_pg_hook.get_records(
        f"SELECT status, assignee_id FROM opencve_cve_trackers WHERE project_id = '{PROJECT_ID}';"
    )
    assert len(trackers) >= 1
    assert trackers[0][0] == "in_triage"
    assert trackers[0][1] == USER_ID


@pytest.mark.web_db
@pytest.mark.web_redis
def test_alert_automation_no_match(
    tests_path, tmp_path_factory, web_pg_hook, web_redis_hook, override_conf
):
    """Alert pipeline where CVE does not meet the CVSS threshold."""
    override_conf("opencve", "max_automations_map_length", "10")
    override_conf("opencve", "max_notifications_per_task", "5")

    start = pendulum.datetime(2024, 1, 1, 1, 0, tz="UTC")
    end = pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC")
    context = _ctx(start, end)
    end_adj = end.subtract(seconds=1)

    _setup_org_and_project(web_pg_hook)
    _setup_alert_automation(web_pg_hook, cvss_threshold=9.5)

    repo = TestRepo("changes", tests_path, tmp_path_factory)
    repo.commit(["0001/CVE-2024-6962.v1.json"], hour=1, minute=0)
    _ingest_cve(repo, context)
    _run_pipeline_until_automations_loaded(repo, context, web_redis_hook)

    build_alert_work_items.function(**context)

    action_queue = redis_get(
        web_redis_hook,
        REDIS_PREFIX_AUTOMATION_ACTION_QUEUE_ALERT,
        start,
        end_adj,
    )
    chunks = action_queue.get("chunks", [])
    has_items = any(len(batch) > 0 for batch in chunks) if chunks else False
    assert not has_items, "No actions should be queued when CVSS is below threshold"

    executions = web_pg_hook.get_records(
        "SELECT id FROM opencve_automation_executions;"
    )
    assert len(executions) == 0

    trackers = web_pg_hook.get_records(
        f"SELECT id FROM opencve_cve_trackers WHERE project_id = '{PROJECT_ID}';"
    )
    assert len(trackers) == 0


# ---------------------------------------------------------------------------
# Report lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.web_db
@pytest.mark.web_redis
def test_report_automation_daily_lifecycle(
    tests_path, tmp_path_factory, web_pg_hook, web_redis_hook, override_conf
):
    """Report pipeline: hourly accumulation, then check report DB rows."""
    override_conf("opencve", "max_automations_map_length", "10")
    override_conf("opencve", "max_notifications_per_task", "5")

    _setup_org_and_project(web_pg_hook)
    _setup_report_automation(web_pg_hook, schedule_time="09:00:00", frequency="daily")

    # Use hour=1 (01:00-02:00) to match the change created_at from ProcessKbOperator
    hour1_start = pendulum.datetime(2024, 1, 1, 1, 0, tz="UTC")
    hour1_end = pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC")
    hour1_ctx = _ctx(hour1_start, hour1_end)
    hour1_end_adj = hour1_end.subtract(seconds=1)

    repo = TestRepo("changes", tests_path, tmp_path_factory)
    repo.commit(["0001/CVE-2024-6962.v1.json"], hour=1, minute=0)

    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path):
        ProcessKbOperator(task_id="kb1").execute(hour1_ctx)

    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path), patch(
        "includes.tasks.reports.KB_LOCAL_REPO", repo.repo_path
    ):
        collect_hourly_changes.function(**hour1_ctx)

    resolve_subscriptions.function(**hour1_ctx)
    load_enabled_automations.function(**hour1_ctx)

    # BuildReportContentHourly
    build_report_content_hourly.function(**hour1_ctx)
    hourly_items = redis_get(
        web_redis_hook,
        REDIS_PREFIX_REPORT_HOURLY_CONTENT_ITEMS,
        hour1_start,
        hour1_end_adj,
    )
    assert len(hourly_items) >= 1

    # UpsertReportContentAndEntries
    upsert_report_content_and_entries.function(**hour1_ctx)

    # Verify report row created
    reports = web_pg_hook.get_records(
        f"""
        SELECT id, day, period_type, period_timezone
        FROM opencve_reports
        WHERE project_id = '{PROJECT_ID}' AND automation_id = '{AUTOMATION_REPORT_ID}';
        """
    )
    assert len(reports) == 1
    report_id = reports[0][0]
    assert str(reports[0][1]) == "2024-01-01"
    assert reports[0][2] == "daily"
    assert reports[0][3] == "UTC"

    # Verify report_changes linked
    rc_count = web_pg_hook.get_records(
        f"SELECT count(*) FROM opencve_reports_changes WHERE report_id = '{report_id}';"
    )
    assert rc_count[0][0] >= 1


@pytest.mark.web_db
@pytest.mark.web_redis
def test_report_automation_not_yet_due(web_pg_hook, web_redis_hook, override_conf):
    """Report pipeline at 07:00 (not the scheduled 09:00): no actions should fire."""
    override_conf("opencve", "max_automations_map_length", "10")
    override_conf("opencve", "max_notifications_per_task", "5")

    _setup_org_and_project(web_pg_hook)
    _setup_report_automation(web_pg_hook, schedule_time="09:00:00", frequency="daily")

    hour_start = pendulum.datetime(2024, 1, 1, 6, 0, tz="UTC")
    hour_end = pendulum.datetime(2024, 1, 1, 7, 0, tz="UTC")
    ctx = _ctx(hour_start, hour_end)
    hour_end_adj = hour_end.subtract(seconds=1)

    evaluate_report_due_in_automation_timezone.function(**ctx)

    due_items = redis_get(
        web_redis_hook,
        REDIS_PREFIX_REPORT_DUE_WORK_ITEMS,
        hour_start,
        hour_end_adj,
    )
    assert due_items == []


@pytest.mark.web_db
@pytest.mark.web_redis
def test_report_automation_due_at_scheduled_time(
    tests_path, tmp_path_factory, web_pg_hook, web_redis_hook, override_conf
):
    """Report pipeline at 09:00: automation is due and report payload is built."""
    override_conf("opencve", "max_automations_map_length", "10")
    override_conf("opencve", "max_notifications_per_task", "5")

    _setup_org_and_project(web_pg_hook)
    _setup_report_automation(web_pg_hook, schedule_time="09:00:00", frequency="daily")

    # Accumulate data: ingest CVE in hour 01:00-02:00
    hour1_start = pendulum.datetime(2024, 1, 1, 1, 0, tz="UTC")
    hour1_end = pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC")
    hour1_ctx = _ctx(hour1_start, hour1_end)

    repo = TestRepo("changes", tests_path, tmp_path_factory)
    repo.commit(["0001/CVE-2024-6962.v1.json"], hour=1, minute=0)

    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path):
        ProcessKbOperator(task_id="kb1").execute(hour1_ctx)

    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path), patch(
        "includes.tasks.reports.KB_LOCAL_REPO", repo.repo_path
    ):
        collect_hourly_changes.function(**hour1_ctx)

    resolve_subscriptions.function(**hour1_ctx)
    load_enabled_automations.function(**hour1_ctx)
    build_report_content_hourly.function(**hour1_ctx)
    upsert_report_content_and_entries.function(**hour1_ctx)

    # Verify report exists
    reports = web_pg_hook.get_records(
        f"""
        SELECT id FROM opencve_reports
        WHERE project_id = '{PROJECT_ID}' AND automation_id = '{AUTOMATION_REPORT_ID}';
        """
    )
    assert len(reports) == 1

    # Evaluate at 09:00 on the *next* day (daily report for Jan 1 is due at Jan 2 09:00)
    due_start = pendulum.datetime(2024, 1, 2, 8, 0, tz="UTC")
    due_end = pendulum.datetime(2024, 1, 2, 9, 0, tz="UTC")
    due_ctx = _ctx(due_start, due_end)
    due_end_adj = due_end.subtract(seconds=1)

    evaluate_report_due_in_automation_timezone.function(**due_ctx)

    due_items = redis_get(
        web_redis_hook,
        REDIS_PREFIX_REPORT_DUE_WORK_ITEMS,
        due_start,
        due_end_adj,
    )
    assert len(due_items) >= 1
    assert due_items[0]["automation"]["automation_id"] == AUTOMATION_REPORT_ID

    # BuildReportNotificationPayload
    build_report_notification_payload.function(**due_ctx)

    report_queue = redis_get(
        web_redis_hook,
        REDIS_PREFIX_AUTOMATION_ACTION_QUEUE_REPORT_DUE,
        due_start,
        due_end_adj,
    )
    chunks = report_queue.get("chunks", [])
    assert len(chunks) >= 1
    first_batch = chunks[0]
    assert len(first_batch) >= 1
    report_content = first_batch[0].get("report_content", {})
    assert report_content.get("cve_count", 0) >= 1

    # ExecuteReportDueActions
    execute_report_due_automation_actions.function(**due_ctx)

    executions = web_pg_hook.get_records(
        f"""
        SELECT automation_id, matched_cves_count, window_start, window_end, executed_at
        FROM opencve_automation_executions
        WHERE automation_id = '{AUTOMATION_REPORT_ID}';
        """
    )
    assert len(executions) >= 1
    _, _, window_start, window_end, executed_at = executions[0]
    period_window = get_report_period_window(
        {
            "period_day": "2024-01-01",
            "period_type": "daily",
            "period_timezone": "UTC",
        }
    )
    assert pendulum.instance(window_start) == period_window["start"]
    assert pendulum.instance(window_end) == period_window["end"]
    assert pendulum.instance(executed_at) == due_end_adj

    results = web_pg_hook.get_records(
        "SELECT output_type, status FROM opencve_automation_execution_results;"
    )
    assert len(results) >= 1
