from unittest.mock import patch, mock_open
import importlib

import pytest
import pendulum
from airflow.exceptions import AirflowConfigException, AirflowSkipException
from airflow.utils.state import TaskInstanceState

from includes.constants import (
    SQL_DAILY_REPORTS_CVES_TO_SUMMARIZE,
    SQL_WEEKLY_REPORTS_CVES_TO_SUMMARIZE,
)
from includes.operators.process_kb_operator import ProcessKbOperator
from includes.tasks.reports import (
    collect_hourly_changes,
    resolve_subscriptions,
    summarize_reports,
    summarize_weekly_reports,
)
from utils import TestRepo


@pytest.mark.airflow_db
def test_collect_hourly_changes_no_change(
    caplog, run_dag_task, tests_path, tmp_path_factory
):
    repo = TestRepo("changes", tests_path, tmp_path_factory)

    # One commit found, but no change in DB
    repo.commit(["0001/CVE-2024-6962.v1.json"], hour=2, minute=00)
    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path):
        task = run_dag_task(
            task_fn=collect_hourly_changes,
            start=pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC"),
            end=pendulum.datetime(2024, 1, 1, 3, 0, tz="UTC"),
        )
    assert task.state == TaskInstanceState.SKIPPED
    assert "No change found" in caplog.text


@pytest.mark.airflow_db
@pytest.mark.web_db
def test_collect_hourly_changes_no_vendor(
    caplog, run_dag_task, tests_path, tmp_path_factory
):
    repo = TestRepo("changes", tests_path, tmp_path_factory)

    # One commit found with change in KB but no vendor
    repo.commit(["0002/CVE-2024-0001.json"], hour=2, minute=00)
    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path):
        operator = ProcessKbOperator(task_id="process_kb_test")
        operator.execute(
            {
                "data_interval_start": pendulum.datetime(2024, 1, 1, 2, tz="UTC"),
                "data_interval_end": pendulum.datetime(2024, 1, 1, 3, tz="UTC"),
            }
        )
        task = run_dag_task(
            task_fn=collect_hourly_changes,
            start=pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC"),
            end=pendulum.datetime(2024, 1, 1, 3, 0, tz="UTC"),
        )
    assert task.state == TaskInstanceState.SKIPPED
    assert "No vendor with change found" in caplog.text


@pytest.mark.airflow_db
@pytest.mark.web_db
def test_collect_hourly_changes_write_in_redis(
    run_dag_task, tests_path, tmp_path_factory
):
    repo = TestRepo("changes", tests_path, tmp_path_factory)

    # One commit found with change in DB
    repo.commit(["0001/CVE-2024-6962.v2.json"], hour=3, minute=00)
    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path):
        operator = ProcessKbOperator(task_id="process_kb_test")
        operator.execute(
            {
                "data_interval_start": pendulum.datetime(2024, 1, 1, 3, tz="UTC"),
                "data_interval_end": pendulum.datetime(2024, 1, 1, 4, tz="UTC"),
            }
        )

        task = run_dag_task(
            task_fn=collect_hourly_changes,
            start=pendulum.datetime(2024, 1, 1, 3, 0, tz="UTC"),
            end=pendulum.datetime(2024, 1, 1, 4, 0, tz="UTC"),
        )
        assert task.state == TaskInstanceState.SUCCESS


@pytest.mark.airflow_db
@pytest.mark.web_db
@pytest.mark.web_redis
def test_collect_hourly_changes(
    run_dag_task, tests_path, tmp_path_factory, web_redis_hook
):
    repo = TestRepo("changes", tests_path, tmp_path_factory)
    repo.commit(["0001/CVE-2024-6962.v1.json"], hour=1, minute=00)
    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path):
        operator = ProcessKbOperator(task_id="process_kb_test")
        operator.execute(
            {
                "data_interval_start": pendulum.datetime(2024, 1, 1, 1, tz="UTC"),
                "data_interval_end": pendulum.datetime(2024, 1, 1, 2, tz="UTC"),
            }
        )
        run_dag_task(
            task_fn=collect_hourly_changes,
            start=pendulum.datetime(2024, 1, 1, 1, 0, tz="UTC"),
            end=pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC"),
        )

        changes_details_key = (
            "changes_details_2024-01-01 01:00:00+00:00_2024-01-01 01:59:59+00:00"
        )
        result = web_redis_hook.json().get(changes_details_key)
        change = result["114e2218-49c5-43fe-bcd7-18a1adc17a25"]

        assert change["change_id"] == "114e2218-49c5-43fe-bcd7-18a1adc17a25"
        assert change["change_types"] == [
            "description",
            "title",
            "weaknesses",
            "references",
            "metrics",
        ]
        assert change["change_path"] == "0001/CVE-2024-6962.v1.json"
        assert change["cve_vendors"] == ["foo", "foo$PRODUCT$bar"]
        assert change["cve_id"] == "CVE-2024-6962"
        assert change["cve_metrics"] == {
            "kev": {"data": {}, "provider": None},
            "ssvc": {"data": {}, "provider": None},
            "cvssV2_0": {
                "data": {"score": 9, "vector": "AV:N/AC:L/Au:S/C:C/I:C/A:C"},
                "provider": "mitre",
            },
            "cvssV3_0": {
                "data": {
                    "score": 8.8,
                    "vector": "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                },
                "provider": "mitre",
            },
            "cvssV3_1": {
                "data": {
                    "score": 8.8,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                },
                "provider": "mitre",
            },
            "cvssV4_0": {"data": {}, "provider": None},
            "threat_severity": {"data": None, "provider": None},
        }
        assert change["cve_created_at"] is not None
        assert change["cve_title"] == "Tenda O3 formQosSet stack-based overflow"
        assert "Tenda O3 1.0.0.10" in change["cve_description"]

        vendor_changes_key = (
            "vendor_changes_2024-01-01 01:00:00+00:00_2024-01-01 01:59:59+00:00"
        )
        assert web_redis_hook.json().get(vendor_changes_key) == {
            "foo": ["114e2218-49c5-43fe-bcd7-18a1adc17a25"],
            "foo$PRODUCT$bar": ["114e2218-49c5-43fe-bcd7-18a1adc17a25"],
        }


@pytest.mark.airflow_db
@pytest.mark.web_db
@pytest.mark.web_redis
def test_resolve_subscriptions(run_dag_task, web_redis_hook, web_pg_hook):
    web_redis_hook.json().set(
        "vendor_changes_2024-01-01 01:00:00+00:00_2024-01-01 01:59:59+00:00",
        "$",
        {
            "foo": ["114e2218-49c5-43fe-bcd7-18a1adc17a25"],
            "foo$PRODUCT$bar": ["114e2218-49c5-43fe-bcd7-18a1adc17a25"],
        },
    )

    web_pg_hook.run(
        """
        INSERT INTO opencve_organizations
        VALUES
          (
            '16674ce5-ef22-4b27-8368-6d2d0ec7191e',
            '2024-01-01 00:00:00+00',
            '2024-01-01 00:00:00+00',
            'orga1'
        );
        """
    )

    web_pg_hook.run(
        """
        INSERT INTO opencve_projects
        VALUES
          (
            '0439aa01-62b3-465c-ba7b-bd07c961c778',
            '2024-01-01 00:00:00+00',
            '2024-01-01 00:00:00+00',
            'orga1-project1',
            '',
            '{"vendors": ["foo"], "products": []}',
            '16674ce5-ef22-4b27-8368-6d2d0ec7191e',
            't'
          );
      """
    )

    web_pg_hook.run(
        """
        INSERT INTO opencve_projects
        VALUES
          (
            '235fb6c2-adad-499f-b7e2-4a005fc31809',
            '2024-01-01 00:00:00+00',
            '2024-01-01 00:00:00+00',
            'orga1-project2',
            '',
            '{"vendors": [], "products": ["foo$PRODUCT$bar"]}',
            '16674ce5-ef22-4b27-8368-6d2d0ec7191e',
            't'
          );
    """
    )

    task = run_dag_task(
        task_fn=resolve_subscriptions,
        start=pendulum.datetime(2024, 1, 1, 1, 0, tz="UTC"),
        end=pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC"),
    )
    assert task.state == TaskInstanceState.SUCCESS

    subscriptions = web_redis_hook.json().get(
        "subscriptions_2024-01-01 01:00:00+00:00_2024-01-01 01:59:59+00:00"
    )
    assert subscriptions == {
        "0439aa01-62b3-465c-ba7b-bd07c961c778": ["foo"],
        "235fb6c2-adad-499f-b7e2-4a005fc31809": ["foo$PRODUCT$bar"],
    }


@pytest.mark.airflow_db
@pytest.mark.web_db
@pytest.mark.web_redis
def test_resolve_subscriptions_no_subscription(
    caplog, run_dag_task, web_redis_hook, web_pg_hook
):
    web_redis_hook.json().set(
        "vendor_changes_2024-01-01 01:00:00+00:00_2024-01-01 01:59:59+00:00",
        "$",
        {
            "foo": ["114e2218-49c5-43fe-bcd7-18a1adc17a25"],
            "foo$PRODUCT$bar": ["114e2218-49c5-43fe-bcd7-18a1adc17a25"],
        },
    )

    task = run_dag_task(
        task_fn=resolve_subscriptions,
        start=pendulum.datetime(2024, 1, 1, 1, 0, tz="UTC"),
        end=pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC"),
    )
    assert task.state == TaskInstanceState.SKIPPED
    assert "No subscription found" in caplog.text


def test_summarize_reports_missing_api_key():
    """Test summarize_reports with missing LLM API key"""
    mock_context = {
        "data_interval_start": pendulum.datetime(2025, 1, 1, 2, 0, tz="UTC")
    }

    with patch(
        "includes.tasks.reports.conf.get",
        side_effect=AirflowConfigException("Configuration not found"),
    ):
        with pytest.raises(AirflowSkipException, match="LLM API key is not configured"):
            summarize_reports.function(**mock_context)


def test_summarize_reports_missing_api_url():
    """Test summarize_reports with missing LLM API URL"""
    mock_context = {
        "data_interval_start": pendulum.datetime(2025, 1, 1, 2, 0, tz="UTC")
    }

    def mock_get(section, key, **kwargs):
        if key == "llm_api_key":
            return "test-api-key"
        else:
            raise AirflowConfigException("Configuration not found")

    with patch("includes.tasks.reports.conf.get", side_effect=mock_get):
        with pytest.raises(AirflowSkipException, match="LLM API URL is not configured"):
            summarize_reports.function(**mock_context)


def test_summarize_reports_no_reports():
    """Test summarize_reports with no reports to process"""
    mock_context = {
        "data_interval_start": pendulum.datetime(2025, 1, 1, 2, 0, tz="UTC")
    }

    def mock_get(section, key, **kwargs):
        if key == "llm_api_key":
            return "test-api-key"
        elif key == "llm_api_url":
            return "https://api.test.com"
        elif key == "llm_model":
            return "test-model"
        else:
            raise AirflowConfigException("Configuration not found")

    with patch("includes.tasks.reports.conf.get", side_effect=mock_get):
        with patch("includes.tasks.reports.PostgresHook") as mock_hook:
            mock_hook_instance = mock_hook.return_value
            mock_hook_instance.get_records.return_value = []

            result = summarize_reports.function(**mock_context)
            assert result is None


def test_summarize_reports_success(tests_path, tmp_path_factory):
    """Test successful summarize_reports execution"""
    repo = TestRepo("llm", tests_path, tmp_path_factory)
    repo.commit(["2025/CVE-2025-1000.json"], hour=1, minute=0)

    context = {"data_interval_start": pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC")}

    def mock_get(section, key, **kwargs):
        values = {
            "llm_api_key": "test-api-key",
            "llm_api_url": "https://api.test.com",
            "llm_model": "Mistral-7B-Instruct-v0.3",
        }
        if key in values:
            return values[key]
        raise AirflowConfigException("Configuration not found")

    mock_records = [
        (
            "report-123",
            ["CVE-2025-1000"],
            1,
            [{"score": "HIGH", "count": 1}],
        )
    ]
    llm_response = "Critical vulnerability in IBM Db2"

    with (
        patch("includes.tasks.reports.conf.get", side_effect=mock_get),
        patch(
            "includes.tasks.reports.open",
            mock_open(read_data="You are a CVE report analyzer."),
        ),
        patch("includes.tasks.reports.PostgresHook") as mock_hook,
        patch("includes.utils.KB_LOCAL_REPO", repo.repo_path),
        patch(
            "includes.tasks.reports.call_llm", return_value=llm_response
        ) as mock_call_llm,
    ):
        mock_hook_instance = mock_hook.return_value
        mock_hook_instance.get_records.return_value = mock_records

        summarize_reports.function(**context)

        # Check LLM call
        mock_call_llm.assert_called_once()
        api_key, api_url, model, messages, logger = mock_call_llm.call_args[0]
        assert api_key == "test-api-key"
        assert api_url == "https://api.test.com"
        assert model == "Mistral-7B-Instruct-v0.3"
        assert len(messages) == 2  # system + user messages

        # Check DB update
        mock_hook_instance.run.assert_called_once()
        params = mock_hook_instance.run.call_args[1]["parameters"]
        assert params["report_id"] == "report-123"
        assert params["ai_summary"] == llm_response


def test_summarize_reports_none_response(tests_path, tmp_path_factory):
    """Test summarize_reports when LLM returns None (report should be skipped)"""
    repo = TestRepo("llm", tests_path, tmp_path_factory)
    repo.commit(["2025/CVE-2025-1000.json"], hour=1, minute=0)

    context = {"data_interval_start": pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC")}

    def mock_get(section, key, **kwargs):
        values = {
            "llm_api_key": "test-api-key",
            "llm_api_url": "https://api.test.com",
            "llm_model": "Mistral-7B-Instruct-v0.3",
        }
        if key in values:
            return values[key]
        raise AirflowConfigException("Configuration not found")

    mock_records = [
        (
            "report-123",
            ["CVE-2025-1000"],
            1,
            [{"score": "HIGH", "count": 1}],
        )
    ]

    with (
        patch("includes.tasks.reports.conf.get", side_effect=mock_get),
        patch(
            "includes.tasks.reports.open",
            mock_open(read_data="You are a CVE report analyzer."),
        ),
        patch("includes.tasks.reports.PostgresHook") as mock_hook,
        patch("includes.utils.KB_LOCAL_REPO", repo.repo_path),
        patch("includes.tasks.reports.call_llm", return_value=None) as mock_call_llm,
    ):
        mock_hook_instance = mock_hook.return_value
        mock_hook_instance.get_records.return_value = mock_records

        summarize_reports.function(**context)

        # Check LLM call was made
        mock_call_llm.assert_called_once()
        api_key, api_url, model, messages, logger = mock_call_llm.call_args[0]
        assert api_key == "test-api-key"
        assert api_url == "https://api.test.com"
        assert model == "Mistral-7B-Instruct-v0.3"
        assert len(messages) == 2  # system + user messages

        # Check DB update was NOT called (report skipped)
        mock_hook_instance.run.assert_not_called()


@pytest.mark.web_db
def test_clean_reports_deletes_expired(web_pg_hook, override_conf):
    override_conf("opencve", "reports_retention", "1")

    import includes.constants as constants
    import includes.tasks.reports as reports_module

    importlib.reload(constants)
    importlib.reload(reports_module)

    org_id = "11111111-1111-1111-1111-111111111111"
    project_id = "22222222-2222-2222-2222-222222222222"
    cve_uuid = "33333333-3333-3333-3333-333333333333"
    old_change_id = "44444444-4444-4444-4444-444444444444"
    new_change_id = "55555555-5555-5555-5555-555555555555"
    old_report_id = "66666666-6666-6666-6666-666666666666"
    new_report_id = "77777777-7777-7777-7777-777777777777"

    # Create the organization, project, CVE, change, report and report_change
    # An old report from 2 months ago and a new report from 10 days ago
    # The old report should be deleted and the new report should be kept
    web_pg_hook.run(
        f"""
        INSERT INTO opencve_organizations (id, created_at, updated_at, name)
        VALUES ('{org_id}', now(), now(), 'orga1');

        INSERT INTO opencve_projects (
            id, created_at, updated_at, name, description, subscriptions, organization_id, active
        )
        VALUES (
            '{project_id}', now(), now(), 'orga1-project1', '',
            '{{"vendors": [], "products": []}}'::jsonb, '{org_id}', 't'
        );

        INSERT INTO opencve_cves (
            id, created_at, updated_at, cve_id, title, description, vendors, weaknesses, metrics
        )
        VALUES (
            '{cve_uuid}', now(), now(), 'CVE-2024-0001', NULL, NULL,
            '[]'::jsonb, '[]'::jsonb, '{{}}'::jsonb
        );

        INSERT INTO opencve_changes (
            id, created_at, updated_at, path, commit, types, cve_id
        )
        VALUES
            (
                '{old_change_id}', now() - interval '2 months',
                now() - interval '2 months', '0001/CVE-2024-0001.json',
                '0000000000000000000000000000000000000000', '[]'::jsonb, '{cve_uuid}'
            ),
            (
                '{new_change_id}', now() - interval '10 days',
                now() - interval '10 days', '0001/CVE-2024-0001.json',
                '1111111111111111111111111111111111111111', '[]'::jsonb, '{cve_uuid}'
            );

        INSERT INTO opencve_reports (
            id, created_at, updated_at, seen, day, project_id, ai_summary,
            period_type, period_timezone
        )
        VALUES
            (
                '{old_report_id}', now() - interval '2 months',
                now() - interval '2 months', 'f', (now() - interval '2 months')::date,
                '{project_id}', NULL, 'daily', 'UTC'
            ),
            (
                '{new_report_id}', now() - interval '10 days',
                now() - interval '10 days', 'f', (now() - interval '10 days')::date,
                '{project_id}', NULL, 'daily', 'UTC'
            );

        INSERT INTO opencve_reports_changes (report_id, change_id)
        VALUES
            ('{old_report_id}', '{old_change_id}'),
            ('{new_report_id}', '{new_change_id}');
        """
    )

    # Check that the old and new reports are present
    remaining_reports = web_pg_hook.get_records(
        "SELECT id FROM opencve_reports ORDER BY id;"
    )
    assert remaining_reports == [(old_report_id,), (new_report_id,)]

    # Clean the reports
    reports_module.clean_reports()

    # Check that the old report has been deleted and the new report has been kept
    remaining_reports = web_pg_hook.get_records(
        "SELECT id FROM opencve_reports ORDER BY id;"
    )
    assert remaining_reports == [(new_report_id,)]

    remaining_links = web_pg_hook.get_records(
        "SELECT report_id FROM opencve_reports_changes ORDER BY report_id;"
    )
    assert remaining_links == [(new_report_id,)]


@pytest.mark.web_db
def test_clean_reports_clears_automation_execution_report_links(
    web_pg_hook, override_conf
):
    """Expired reports linked to automation executions must be cleaned without FK errors."""
    override_conf("opencve", "reports_retention", "1")

    import includes.constants as constants
    import includes.tasks.reports as reports_module

    importlib.reload(constants)
    importlib.reload(reports_module)

    org_id = "11111111-1111-1111-1111-111111111111"
    project_id = "22222222-2222-2222-2222-222222222222"
    automation_id = "33333333-3333-3333-3333-333333333333"
    expired_report_id = "44444444-4444-4444-4444-444444444444"
    recent_report_id = "55555555-5555-5555-5555-555555555555"
    expired_execution_id = "66666666-6666-6666-6666-666666666666"
    recent_execution_id = "77777777-7777-7777-7777-777777777777"

    web_pg_hook.run(
        f"""
        INSERT INTO opencve_organizations (id, created_at, updated_at, name)
        VALUES ('{org_id}', now(), now(), 'orga1');

        INSERT INTO opencve_projects (
            id, created_at, updated_at, name, description, subscriptions, organization_id, active
        )
        VALUES (
            '{project_id}', now(), now(), 'orga1-project1', '',
            '{{"vendors": [], "products": []}}'::jsonb, '{org_id}', 't'
        );
        """
    )
    web_pg_hook.run(
        f"""
        INSERT INTO opencve_automations (
            id, created_at, updated_at, name, trigger_type, frequency,
            schedule_timezone, schedule_time, schedule_weekday,
            configuration, project_id, is_enabled
        )
        VALUES (
            '{automation_id}', now(), now(), 'Daily report', 'report', 'daily',
            'UTC', '09:00:00', NULL, '{{}}'::jsonb, '{project_id}', true
        );
        """
    )
    web_pg_hook.run(
        f"""
        INSERT INTO opencve_reports (
            id, created_at, updated_at, seen, day, project_id, ai_summary,
            period_type, period_timezone, automation_id
        )
        VALUES
            (
                '{expired_report_id}', now() - interval '2 months',
                now() - interval '2 months', 'f', (now() - interval '2 months')::date,
                '{project_id}', NULL, 'daily', 'UTC', '{automation_id}'
            ),
            (
                '{recent_report_id}', now() - interval '20 days',
                now() - interval '20 days', 'f', (now() - interval '20 days')::date,
                '{project_id}', NULL, 'daily', 'UTC', '{automation_id}'
            );
        """
    )
    web_pg_hook.run(
        f"""
        INSERT INTO opencve_automation_executions (
            id, created_at, updated_at, executed_at, window_start, window_end,
            matched_cves_count, automation_id, report_id
        )
        VALUES
            (
                '{expired_execution_id}', now(), now(),
                now() - interval '2 months', now() - interval '2 months',
                now() - interval '2 months' + interval '1 day', 0,
                '{automation_id}', '{expired_report_id}'
            ),
            (
                '{recent_execution_id}', now(), now(),
                now() - interval '20 days', now() - interval '20 days',
                now() - interval '20 days' + interval '1 day', 0,
                '{automation_id}', '{recent_report_id}'
            );
        """
    )

    reports_module.clean_reports()

    remaining_reports = {
        str(row[0])
        for row in web_pg_hook.get_records("SELECT id FROM opencve_reports;")
    }
    assert expired_report_id not in remaining_reports
    assert recent_report_id in remaining_reports

    execution_links = web_pg_hook.get_records(
        """
        SELECT id::text, report_id::text
        FROM opencve_automation_executions
        ORDER BY id;
        """
    )
    assert execution_links == [
        (expired_execution_id, None),
        (recent_execution_id, recent_report_id),
    ]


def test_summarize_weekly_reports_missing_api_key():
    """Test summarize_weekly_reports with missing LLM API key"""
    mock_context = {
        "data_interval_start": pendulum.datetime(2025, 1, 13, 2, 0, tz="UTC")
    }

    with patch(
        "includes.tasks.reports.conf.get",
        side_effect=AirflowConfigException("Configuration not found"),
    ):
        with pytest.raises(AirflowSkipException, match="LLM API key is not configured"):
            summarize_weekly_reports.function(**mock_context)


def test_summarize_weekly_reports_missing_api_url():
    """Test summarize_weekly_reports with missing LLM API URL"""
    mock_context = {
        "data_interval_start": pendulum.datetime(2025, 1, 13, 2, 0, tz="UTC")
    }

    def mock_get(section, key, **kwargs):
        if key == "llm_api_key":
            return "test-api-key"
        else:
            raise AirflowConfigException("Configuration not found")

    with patch("includes.tasks.reports.conf.get", side_effect=mock_get):
        with pytest.raises(AirflowSkipException, match="LLM API URL is not configured"):
            summarize_weekly_reports.function(**mock_context)


def test_summarize_weekly_reports_no_reports():
    """Test summarize_weekly_reports with no completed weekly reports"""
    mock_context = {
        "data_interval_start": pendulum.datetime(2025, 1, 13, 2, 0, tz="UTC")
    }

    def mock_get(section, key, **kwargs):
        if key == "llm_api_key":
            return "test-api-key"
        elif key == "llm_api_url":
            return "https://api.test.com"
        elif key == "llm_model":
            return "test-model"
        else:
            raise AirflowConfigException("Configuration not found")

    with patch("includes.tasks.reports.conf.get", side_effect=mock_get):
        with patch("includes.tasks.reports.PostgresHook") as mock_hook:
            mock_hook_instance = mock_hook.return_value
            mock_hook_instance.get_records.return_value = []

            result = summarize_weekly_reports.function(**mock_context)
            assert result is None

            mock_hook_instance.get_records.assert_called_once()
            call_kwargs = mock_hook_instance.get_records.call_args[1]
            assert call_kwargs["parameters"] == {
                "current_ts": pendulum.datetime(2025, 1, 13, 2, 0, tz="UTC")
            }


def test_summarize_weekly_reports_success(tests_path, tmp_path_factory):
    """Test successful summarize_weekly_reports execution"""
    repo = TestRepo("llm", tests_path, tmp_path_factory)
    repo.commit(["2025/CVE-2025-1000.json"], hour=1, minute=0)

    context = {"data_interval_start": pendulum.datetime(2025, 1, 13, 2, 0, tz="UTC")}

    def mock_get(section, key, **kwargs):
        values = {
            "llm_api_key": "test-api-key",
            "llm_api_url": "https://api.test.com",
            "llm_model": "Mistral-7B-Instruct-v0.3",
        }
        if key in values:
            return values[key]
        raise AirflowConfigException("Configuration not found")

    mock_records = [
        (
            "weekly-report-456",
            ["CVE-2025-1000"],
            1,
            [{"score": 9.8, "count": 1}],
        )
    ]
    llm_response = "Weekly summary: 1 critical vulnerability detected"

    with (
        patch("includes.tasks.reports.conf.get", side_effect=mock_get),
        patch(
            "includes.tasks.reports.open",
            mock_open(read_data="You are a CVE report analyzer."),
        ),
        patch("includes.tasks.reports.PostgresHook") as mock_hook,
        patch("includes.utils.KB_LOCAL_REPO", repo.repo_path),
        patch(
            "includes.tasks.reports.call_llm", return_value=llm_response
        ) as mock_call_llm,
    ):
        mock_hook_instance = mock_hook.return_value
        mock_hook_instance.get_records.return_value = mock_records

        summarize_weekly_reports.function(**context)

        # Check the query was called with the correct parameter
        call_kwargs = mock_hook_instance.get_records.call_args[1]
        assert call_kwargs["parameters"] == {
            "current_ts": pendulum.datetime(2025, 1, 13, 2, 0, tz="UTC")
        }

        # Check LLM call
        mock_call_llm.assert_called_once()
        api_key, api_url, model, messages, logger = mock_call_llm.call_args[0]
        assert api_key == "test-api-key"
        assert api_url == "https://api.test.com"
        assert model == "Mistral-7B-Instruct-v0.3"
        assert len(messages) == 2

        # Check DB update
        mock_hook_instance.run.assert_called_once()
        params = mock_hook_instance.run.call_args[1]["parameters"]
        assert params["report_id"] == "weekly-report-456"
        assert params["ai_summary"] == llm_response


def test_summarize_weekly_reports_none_response(tests_path, tmp_path_factory):
    """Test summarize_weekly_reports when LLM returns None (report should be skipped)"""
    repo = TestRepo("llm", tests_path, tmp_path_factory)
    repo.commit(["2025/CVE-2025-1000.json"], hour=1, minute=0)

    context = {"data_interval_start": pendulum.datetime(2025, 1, 13, 2, 0, tz="UTC")}

    def mock_get(section, key, **kwargs):
        values = {
            "llm_api_key": "test-api-key",
            "llm_api_url": "https://api.test.com",
            "llm_model": "Mistral-7B-Instruct-v0.3",
        }
        if key in values:
            return values[key]
        raise AirflowConfigException("Configuration not found")

    mock_records = [
        (
            "weekly-report-456",
            ["CVE-2025-1000"],
            1,
            [{"score": 9.8, "count": 1}],
        )
    ]

    with (
        patch("includes.tasks.reports.conf.get", side_effect=mock_get),
        patch(
            "includes.tasks.reports.open",
            mock_open(read_data="You are a CVE report analyzer."),
        ),
        patch("includes.tasks.reports.PostgresHook") as mock_hook,
        patch("includes.utils.KB_LOCAL_REPO", repo.repo_path),
        patch("includes.tasks.reports.call_llm", return_value=None) as mock_call_llm,
    ):
        mock_hook_instance = mock_hook.return_value
        mock_hook_instance.get_records.return_value = mock_records

        summarize_weekly_reports.function(**context)

        # Check LLM call was made
        mock_call_llm.assert_called_once()

        # Check DB update was NOT called (report skipped)
        mock_hook_instance.run.assert_not_called()


def test_summarize_weekly_reports_multiple_reports(tests_path, tmp_path_factory):
    """Test summarize_weekly_reports processes multiple completed weekly reports"""
    repo = TestRepo("llm", tests_path, tmp_path_factory)
    repo.commit(
        ["2025/CVE-2025-1000.json", "2025/CVE-2025-9999.json"], hour=1, minute=0
    )

    context = {"data_interval_start": pendulum.datetime(2025, 1, 20, 2, 0, tz="UTC")}

    def mock_get(section, key, **kwargs):
        values = {
            "llm_api_key": "test-api-key",
            "llm_api_url": "https://api.test.com",
            "llm_model": "Mistral-7B-Instruct-v0.3",
        }
        if key in values:
            return values[key]
        raise AirflowConfigException("Configuration not found")

    mock_records = [
        (
            "weekly-report-001",
            ["CVE-2025-1000"],
            1,
            [{"score": 9.8, "count": 1}],
        ),
        (
            "weekly-report-002",
            ["CVE-2025-9999"],
            1,
            [{"score": 7.5, "count": 1}],
        ),
    ]

    with (
        patch("includes.tasks.reports.conf.get", side_effect=mock_get),
        patch(
            "includes.tasks.reports.open",
            mock_open(read_data="You are a CVE report analyzer."),
        ),
        patch("includes.tasks.reports.PostgresHook") as mock_hook,
        patch("includes.utils.KB_LOCAL_REPO", repo.repo_path),
        patch(
            "includes.tasks.reports.call_llm", return_value="Summary"
        ) as mock_call_llm,
    ):
        mock_hook_instance = mock_hook.return_value
        mock_hook_instance.get_records.return_value = mock_records

        summarize_weekly_reports.function(**context)

        # Both reports should have been processed
        assert mock_call_llm.call_count == 2
        assert mock_hook_instance.run.call_count == 2

        # Verify each report was updated
        calls = mock_hook_instance.run.call_args_list
        assert calls[0][1]["parameters"]["report_id"] == "weekly-report-001"
        assert calls[1][1]["parameters"]["report_id"] == "weekly-report-002"


@pytest.mark.web_db
def test_summarize_weekly_reports_filters_by_date(web_pg_hook):
    """Only weekly reports whose 7-day period has fully elapsed should be returned."""
    org_id = "aaa00000-0000-0000-0000-000000000001"
    project_id = "bbb00000-0000-0000-0000-000000000001"
    cve_id_1 = "ccc00000-0000-0000-0000-000000000001"
    cve_id_2 = "ccc00000-0000-0000-0000-000000000002"
    change_id_1 = "ddd00000-0000-0000-0000-000000000001"
    change_id_2 = "ddd00000-0000-0000-0000-000000000002"
    recent_report_id = "eee00000-0000-0000-0000-000000000001"
    old_report_id = "eee00000-0000-0000-0000-000000000002"

    web_pg_hook.run(
        f"""
        INSERT INTO opencve_organizations (id, created_at, updated_at, name)
        VALUES ('{org_id}', now(), now(), 'test-org');

        INSERT INTO opencve_projects (
            id, created_at, updated_at, name, description, subscriptions, organization_id, active
        )
        VALUES (
            '{project_id}', now(), now(), 'test-project', '',
            '{{"vendors": [], "products": []}}'::jsonb, '{org_id}', 't'
        );

        INSERT INTO opencve_cves (
            id, created_at, updated_at, cve_id, title, description, vendors, weaknesses, metrics
        )
        VALUES
            (
                '{cve_id_1}', now(), now(), 'CVE-2025-0001', 'Title 1', 'Desc 1',
                '[]'::jsonb, '[]'::jsonb,
                '{{"cvssV3_1": {{"data": {{"score": 8.5}}, "provider": "nvd"}}}}'::jsonb
            ),
            (
                '{cve_id_2}', now(), now(), 'CVE-2025-0002', 'Title 2', 'Desc 2',
                '[]'::jsonb, '[]'::jsonb,
                '{{"cvssV3_1": {{"data": {{"score": 6.0}}, "provider": "nvd"}}}}'::jsonb
            );

        INSERT INTO opencve_changes (
            id, created_at, updated_at, path, commit, types, cve_id
        )
        VALUES
            (
                '{change_id_1}', now(), now(), '2025/CVE-2025-0001.json',
                'aaaa000000000000000000000000000000000000', '[]'::jsonb, '{cve_id_1}'
            ),
            (
                '{change_id_2}', now(), now(), '2025/CVE-2025-0002.json',
                'bbbb000000000000000000000000000000000000', '[]'::jsonb, '{cve_id_2}'
            );

        -- Weekly report started 3 days ago (period NOT finished yet)
        INSERT INTO opencve_reports (
            id, created_at, updated_at, seen, day, project_id, ai_summary,
            period_type, period_timezone
        )
        VALUES (
            '{recent_report_id}', now(), now(), 'f', '2025-01-17',
            '{project_id}', NULL, 'weekly', 'UTC'
        );

        -- Weekly report started 8 days ago (period finished: 8 >= 7)
        INSERT INTO opencve_reports (
            id, created_at, updated_at, seen, day, project_id, ai_summary,
            period_type, period_timezone
        )
        VALUES (
            '{old_report_id}', now(), now(), 'f', '2025-01-12',
            '{project_id}', NULL, 'weekly', 'UTC'
        );

        INSERT INTO opencve_reports_changes (report_id, change_id)
        VALUES
            ('{recent_report_id}', '{change_id_1}'),
            ('{old_report_id}', '{change_id_2}');
        """
    )

    # Query as if we are running on 2025-01-20 (period ending Jan 18 is complete; Jan 23 is not)
    results = web_pg_hook.get_records(
        sql=SQL_WEEKLY_REPORTS_CVES_TO_SUMMARIZE,
        parameters={"current_ts": "2025-01-20T00:00:00+00:00"},
    )

    returned_report_ids = [r[0] for r in results]
    assert old_report_id in returned_report_ids
    assert recent_report_id not in returned_report_ids


@pytest.mark.web_db
def test_summarize_weekly_reports_skips_already_summarized(web_pg_hook):
    """Weekly reports that already have an ai_summary should not be returned."""
    org_id = "aaa00000-0000-0000-0000-000000000002"
    project_id = "bbb00000-0000-0000-0000-000000000002"
    cve_id = "ccc00000-0000-0000-0000-000000000003"
    change_id = "ddd00000-0000-0000-0000-000000000003"
    report_id = "eee00000-0000-0000-0000-000000000003"

    web_pg_hook.run(
        f"""
        INSERT INTO opencve_organizations (id, created_at, updated_at, name)
        VALUES ('{org_id}', now(), now(), 'test-org-2');

        INSERT INTO opencve_projects (
            id, created_at, updated_at, name, description, subscriptions, organization_id, active
        )
        VALUES (
            '{project_id}', now(), now(), 'test-project-2', '',
            '{{"vendors": [], "products": []}}'::jsonb, '{org_id}', 't'
        );

        INSERT INTO opencve_cves (
            id, created_at, updated_at, cve_id, title, description, vendors, weaknesses, metrics
        )
        VALUES (
            '{cve_id}', now(), now(), 'CVE-2025-0003', 'Title 3', 'Desc 3',
            '[]'::jsonb, '[]'::jsonb,
            '{{"cvssV3_1": {{"data": {{"score": 7.0}}, "provider": "nvd"}}}}'::jsonb
        );

        INSERT INTO opencve_changes (
            id, created_at, updated_at, path, commit, types, cve_id
        )
        VALUES (
            '{change_id}', now(), now(), '2025/CVE-2025-0003.json',
            'cccc000000000000000000000000000000000000', '[]'::jsonb, '{cve_id}'
        );

        -- Weekly report from 10 days ago, but already summarized
        INSERT INTO opencve_reports (
            id, created_at, updated_at, seen, day, project_id, ai_summary,
            period_type, period_timezone
        )
        VALUES (
            '{report_id}', now(), now(), 'f', '2025-01-10',
            '{project_id}', 'Already summarized', 'weekly', 'UTC'
        );

        INSERT INTO opencve_reports_changes (report_id, change_id)
        VALUES ('{report_id}', '{change_id}');
        """
    )

    results = web_pg_hook.get_records(
        sql=SQL_WEEKLY_REPORTS_CVES_TO_SUMMARIZE,
        parameters={"current_ts": "2025-01-20T00:00:00+00:00"},
    )

    returned_report_ids = [r[0] for r in results]
    assert report_id not in returned_report_ids


@pytest.mark.web_db
def test_summarize_daily_reports_filters_by_date(web_pg_hook):
    """Only daily reports matching the exact day should be returned."""
    org_id = "aaa00000-0000-0000-0000-000000000003"
    project_id = "bbb00000-0000-0000-0000-000000000003"
    cve_id_1 = "ccc00000-0000-0000-0000-000000000004"
    cve_id_2 = "ccc00000-0000-0000-0000-000000000005"
    change_id_1 = "ddd00000-0000-0000-0000-000000000004"
    change_id_2 = "ddd00000-0000-0000-0000-000000000005"
    yesterday_report_id = "eee00000-0000-0000-0000-000000000004"
    older_report_id = "eee00000-0000-0000-0000-000000000005"
    weekly_report_id = "eee00000-0000-0000-0000-000000000006"

    web_pg_hook.run(
        f"""
        INSERT INTO opencve_organizations (id, created_at, updated_at, name)
        VALUES ('{org_id}', now(), now(), 'test-org-3');

        INSERT INTO opencve_projects (
            id, created_at, updated_at, name, description, subscriptions, organization_id, active
        )
        VALUES (
            '{project_id}', now(), now(), 'test-project-3', '',
            '{{"vendors": [], "products": []}}'::jsonb, '{org_id}', 't'
        );

        INSERT INTO opencve_cves (
            id, created_at, updated_at, cve_id, title, description, vendors, weaknesses, metrics
        )
        VALUES
            (
                '{cve_id_1}', now(), now(), 'CVE-2025-0004', 'Title 4', 'Desc 4',
                '[]'::jsonb, '[]'::jsonb,
                '{{"cvssV3_1": {{"data": {{"score": 9.1}}, "provider": "nvd"}}}}'::jsonb
            ),
            (
                '{cve_id_2}', now(), now(), 'CVE-2025-0005', 'Title 5', 'Desc 5',
                '[]'::jsonb, '[]'::jsonb,
                '{{"cvssV3_1": {{"data": {{"score": 5.5}}, "provider": "nvd"}}}}'::jsonb
            );

        INSERT INTO opencve_changes (
            id, created_at, updated_at, path, commit, types, cve_id
        )
        VALUES
            (
                '{change_id_1}', now(), now(), '2025/CVE-2025-0004.json',
                'dddd000000000000000000000000000000000000', '[]'::jsonb, '{cve_id_1}'
            ),
            (
                '{change_id_2}', now(), now(), '2025/CVE-2025-0005.json',
                'eeee000000000000000000000000000000000000', '[]'::jsonb, '{cve_id_2}'
            );

        -- Daily report for 2025-01-19 (the day we query)
        INSERT INTO opencve_reports (
            id, created_at, updated_at, seen, day, project_id, ai_summary,
            period_type, period_timezone
        )
        VALUES (
            '{yesterday_report_id}', now(), now(), 'f', '2025-01-19',
            '{project_id}', NULL, 'daily', 'UTC'
        );

        -- Daily report for 2025-01-18 (different day, should NOT be returned)
        INSERT INTO opencve_reports (
            id, created_at, updated_at, seen, day, project_id, ai_summary,
            period_type, period_timezone
        )
        VALUES (
            '{older_report_id}', now(), now(), 'f', '2025-01-18',
            '{project_id}', NULL, 'daily', 'UTC'
        );

        -- Weekly report for 2025-01-19 (same day, but wrong period_type)
        INSERT INTO opencve_reports (
            id, created_at, updated_at, seen, day, project_id, ai_summary,
            period_type, period_timezone
        )
        VALUES (
            '{weekly_report_id}', now(), now(), 'f', '2025-01-19',
            '{project_id}', NULL, 'weekly', 'UTC'
        );

        INSERT INTO opencve_reports_changes (report_id, change_id)
        VALUES
            ('{yesterday_report_id}', '{change_id_1}'),
            ('{older_report_id}', '{change_id_2}'),
            ('{weekly_report_id}', '{change_id_2}');
        """
    )

    # Query for day 2025-01-19: only the matching daily report should be returned
    results = web_pg_hook.get_records(
        sql=SQL_DAILY_REPORTS_CVES_TO_SUMMARIZE,
        parameters={"day": "2025-01-19"},
    )

    returned_report_ids = [r[0] for r in results]
    assert yesterday_report_id in returned_report_ids
    assert older_report_id not in returned_report_ids
    assert weekly_report_id not in returned_report_ids
