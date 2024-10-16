from unittest.mock import patch

import pytest
import pendulum
from airflow.utils.state import TaskInstanceState

from includes.operators.process_kb_operator import ProcessKbOperator
from includes.tasks.reports import list_changes, list_subscriptions, populate_reports
from utils import TestRepo


@pytest.mark.airflow_db
def test_list_changes_no_change(caplog, run_dag_task, tests_path, tmp_path_factory):
    repo = TestRepo("changes", tests_path, tmp_path_factory)

    # One commit found, but no change in DB
    repo.commit(["0001/CVE-2024-6962.v1.json"], hour=2, minute=00)
    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path):
        task = run_dag_task(
            task_fn=list_changes,
            start=pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC"),
            end=pendulum.datetime(2024, 1, 1, 3, 0, tz="UTC"),
        )
    assert task.state == TaskInstanceState.SKIPPED
    assert "No change found" in caplog.text


@pytest.mark.airflow_db
@pytest.mark.web_db
def test_list_changes_no_vendor(caplog, run_dag_task, tests_path, tmp_path_factory):
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
            task_fn=list_changes,
            start=pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC"),
            end=pendulum.datetime(2024, 1, 1, 3, 0, tz="UTC"),
        )
    assert task.state == TaskInstanceState.SKIPPED
    assert "No vendor with change found" in caplog.text


@pytest.mark.airflow_db
@pytest.mark.web_db
def test_list_changes_write_in_redis(run_dag_task, tests_path, tmp_path_factory):
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
            task_fn=list_changes,
            start=pendulum.datetime(2024, 1, 1, 3, 0, tz="UTC"),
            end=pendulum.datetime(2024, 1, 1, 4, 0, tz="UTC"),
        )
        assert task.state == TaskInstanceState.SUCCESS


@pytest.mark.airflow_db
@pytest.mark.web_db
@pytest.mark.web_redis
def test_list_changes(run_dag_task, tests_path, tmp_path_factory, web_redis_hook):
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
            task_fn=list_changes,
            start=pendulum.datetime(2024, 1, 1, 1, 0, tz="UTC"),
            end=pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC"),
        )

        changes_details_key = (
            "changes_details_2024-01-01 01:00:00+00:00_2024-01-01 01:59:59+00:00"
        )
        assert web_redis_hook.json().get(changes_details_key) == {
            "114e2218-49c5-43fe-bcd7-18a1adc17a25": {
                "change_id": "114e2218-49c5-43fe-bcd7-18a1adc17a25",
                "change_types": [
                    "description",
                    "title",
                    "weaknesses",
                    "references",
                    "metrics",
                ],
                "change_path": "0001/CVE-2024-6962.v1.json",
                "cve_vendors": ["foo", "foo$PRODUCT$bar"],
                "cve_id": "CVE-2024-6962",
                "cve_metrics": {
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
                },
            }
        }

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
def test_list_subscriptions(run_dag_task, web_redis_hook, web_pg_hook):
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
        task_fn=list_subscriptions,
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
def test_list_subscriptions_no_subscription(
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
        task_fn=list_subscriptions,
        start=pendulum.datetime(2024, 1, 1, 1, 0, tz="UTC"),
        end=pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC"),
    )
    assert task.state == TaskInstanceState.SKIPPED
    assert "No subscription found" in caplog.text


@pytest.mark.airflow_db
@pytest.mark.web_db
@pytest.mark.web_redis
def test_populate_reports(
    tests_path, tmp_path_factory, run_dag_task, web_redis_hook, web_pg_hook
):
    repo = TestRepo("changes", tests_path, tmp_path_factory)
    repo.commit(["0001/CVE-2024-6962.v1.json"], hour=1, minute=00)

    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path):
        operator = ProcessKbOperator(task_id="parse_test")
        operator.execute(
            {
                "data_interval_start": pendulum.datetime(2024, 1, 1, 1, tz="UTC"),
                "data_interval_end": pendulum.datetime(2024, 1, 1, 2, tz="UTC"),
            }
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

    web_redis_hook.json().set(
        "vendor_changes_2024-01-01 01:00:00+00:00_2024-01-01 01:59:59+00:00",
        "$",
        {
            "foo": ["114e2218-49c5-43fe-bcd7-18a1adc17a25"],
            "foo$PRODUCT$bar": ["114e2218-49c5-43fe-bcd7-18a1adc17a25"],
        },
    )
    web_redis_hook.json().set(
        "subscriptions_2024-01-01 01:00:00+00:00_2024-01-01 01:59:59+00:00",
        "$",
        {
            "0439aa01-62b3-465c-ba7b-bd07c961c778": ["foo"],
            "235fb6c2-adad-499f-b7e2-4a005fc31809": ["foo$PRODUCT$bar"],
        },
    )

    task = run_dag_task(
        task_fn=populate_reports,
        start=pendulum.datetime(2024, 1, 1, 1, 0, tz="UTC"),
        end=pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC"),
    )
    assert task.state == TaskInstanceState.SUCCESS

    project_changes = web_redis_hook.json().get(
        "project_changes_2024-01-01 01:00:00+00:00_2024-01-01 01:59:59+00:00"
    )
    assert project_changes == {
        "0439aa01-62b3-465c-ba7b-bd07c961c778": [
            "114e2218-49c5-43fe-bcd7-18a1adc17a25"
        ],
        "235fb6c2-adad-499f-b7e2-4a005fc31809": [
            "114e2218-49c5-43fe-bcd7-18a1adc17a25"
        ],
    }

    # Ensure a report with the change has been created in the DB for each project
    count_reports = web_pg_hook.get_records("SELECT count(*) FROM opencve_reports;")
    assert count_reports[0][0] == 2
    projects_reports = web_pg_hook.get_records(
        """
         SELECT changes.change_id
         FROM opencve_reports AS reports
         JOIN opencve_reports_changes AS changes
         ON reports.id = changes.report_id
         WHERE reports.project_id IN ('0439aa01-62b3-465c-ba7b-bd07c961c778', '235fb6c2-adad-499f-b7e2-4a005fc31809');
        """
    )
    assert projects_reports == [
        ("114e2218-49c5-43fe-bcd7-18a1adc17a25",),
        ("114e2218-49c5-43fe-bcd7-18a1adc17a25",),
    ]
