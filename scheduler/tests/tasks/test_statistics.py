import pytest
from unittest.mock import patch
from airflow.utils.state import TaskInstanceState

import pendulum
from includes.operators.process_kb_operator import ProcessKbOperator
from includes.tasks.statistics import insert_variable, compute_statistics
from utils import TestRepo


@pytest.mark.web_db
def test_insert_variable(web_pg_hook):
    insert_variable("foo", "bar")
    variables = web_pg_hook.get_records("SELECT name, value FROM opencve_variables;")
    assert len(variables) == 1
    assert variables[0][0] == "foo"
    assert variables[0][1] == "bar"


@pytest.mark.airflow_db
@pytest.mark.web_db
def test_compute_statistics(tests_path, tmp_path_factory, run_dag_task, web_pg_hook):
    repo = TestRepo("statistics", tests_path, tmp_path_factory)

    # Create some CVEs
    repo.commit(
        [
            "2017/CVE-2017-8923.json",
            "2021/CVE-2021-0310.json",
            "2022/CVE-2022-20443.json",
            "2023/CVE-2023-5253.json",
            "2024/CVE-2024-0100.json",
            "2024/CVE-2024-49761.json",
        ],
        hour=1,
        minute=00,
    )
    with patch("includes.utils.KB_LOCAL_REPO", repo.repo_path):
        operator = ProcessKbOperator(task_id="parse_test")
        operator.execute(
            {
                "data_interval_start": pendulum.datetime(2024, 1, 1, 1, tz="UTC"),
                "data_interval_end": pendulum.datetime(2024, 1, 1, 2, tz="UTC"),
            }
        )

    # Launch the task
    task = run_dag_task(
        task_fn=compute_statistics,
        start=pendulum.datetime(2024, 1, 1, 1, 0, tz="UTC"),
        end=pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC"),
    )
    assert task.state == TaskInstanceState.SUCCESS

    # TODO: check `statistics_cves_count_last_days`

    # Check `statistics_cves_cumulative_counts`
    value = web_pg_hook.get_records(
        "SELECT value FROM opencve_variables WHERE name = 'statistics_cves_cumulative_counts';"
    )
    assert value[0][0] == {"2017": 1, "2021": 2, "2022": 3, "2023": 4, "2024": 6}

    # Check `statistics_cves_cumulative_counts`
    value = web_pg_hook.get_records(
        "SELECT value FROM opencve_variables WHERE name = 'statistics_cves_yearly_counts';"
    )
    assert value[0][0] == {"2017": 1, "2021": 1, "2022": 1, "2023": 1, "2024": 2}

    # Check `statistics_cvss_rounded_scores`
    value = web_pg_hook.get_records(
        "SELECT value FROM opencve_variables WHERE name = 'statistics_cvss_rounded_scores';"
    )
    assert value[0][0] == {
        "cvssV2_0": {"7": 2},
        "cvssV3_0": {"7": 1},
        "cvssV3_1": {"5": 1, "6": 1, "7": 3, "9": 1},
        "cvssV4_0": {"6": 2},
    }

    # Check `statistics_cvss_categorized_scores`
    value = web_pg_hook.get_records(
        "SELECT value FROM opencve_variables WHERE name = 'statistics_cvss_categorized_scores';"
    )
    assert value[0][0] == {
        "cvssV2_0": {"High": 2},
        "cvssV3_0": {"High": 1},
        "cvssV3_1": {"High": 3, "Medium": 2, "Critical": 1},
        "cvssV4_0": {"Medium": 2},
    }

    # Check `statistics_cves_top_vendors`
    value = web_pg_hook.get_records(
        "SELECT value FROM opencve_variables WHERE name = 'statistics_cves_top_vendors';"
    )
    assert value[0][0] == {
        "php": 1,
        "ruby": 1,
        "google": 2,
        "redhat": 1,
        "ruby-lang": 1,
        "nozominetworks": 1,
    }

    # Check `statistics_cves_top_products`
    value = web_pg_hook.get_records(
        "SELECT value FROM opencve_variables WHERE name = 'statistics_cves_top_products';"
    )
    assert value[0][0] == {
        "cmc": 1,
        "php": 1,
        "rexml": 2,
        "android": 2,
        "guardian": 1,
        "rhel_aus": 1,
        "rhel_e4s": 1,
        "rhel_eus": 1,
        "rhel_tus": 1,
        "enterprise_linux": 1,
    }
