import pendulum
import pytest
from airflow.utils.state import TaskInstanceState

from includes.tasks.notifications import filter_changes, prepare_notifications


@pytest.mark.airflow_db
@pytest.mark.web_db
@pytest.mark.web_redis
def test_prepare_notifications(run_dag_task, web_pg_hook, web_redis_hook):
    web_redis_hook.json().set(
        "subscriptions_2024-01-01 01:00:00+00:00_2024-01-01 01:59:59+00:00",
        "$",
        {
            "0439aa01-62b3-465c-ba7b-bd07c961c778": ["foo"],
            "235fb6c2-adad-499f-b7e2-4a005fc31809": ["foo$PRODUCT$bar"],
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
            '{"vendors": ["foo"], "products": ["foo$PRODUCT$bar"]}',
            '16674ce5-ef22-4b27-8368-6d2d0ec7191e',
            't'
          );
      """
    )

    web_pg_hook.run(
        """
        INSERT INTO opencve_notifications
        VALUES
          (
            '32783f1a-25f2-419f-88a7-350b1d4fc176',
            '2024-01-01 00:00:00+00',
            '2024-01-01 00:00:00+00',
            'notification1',
            'webhook',
            't',
            '{"types": ["references"], "extras": {"url": "https://localhost:5000", "headers": {"foo": "bar"}}, "metrics": {"cvss31": "4"}}',
            '0439aa01-62b3-465c-ba7b-bd07c961c778'
          );
      """
    )

    task = run_dag_task(
        task_fn=prepare_notifications,
        start=pendulum.datetime(2024, 1, 1, 1, 0, tz="UTC"),
        end=pendulum.datetime(2024, 1, 1, 2, 0, tz="UTC"),
    )
    assert task.state == TaskInstanceState.SUCCESS
    notifications = web_redis_hook.json().get(
        "notifications_2024-01-01 01:00:00+00:00_2024-01-01 01:59:59+00:00"
    )
    assert notifications == {
        "0439aa01-62b3-465c-ba7b-bd07c961c778": [
            {
                "project_id": "0439aa01-62b3-465c-ba7b-bd07c961c778",
                "project_name": "orga1-project1",
                "project_subscriptions": ["foo"],
                "organization_name": "orga1",
                "notification_name": "notification1",
                "notification_type": "webhook",
                "notification_conf": {
                    "types": ["references"],
                    "extras": {
                        "url": "https://localhost:5000",
                        "headers": {"foo": "bar"},
                    },
                    "metrics": {"cvss31": "4"},
                },
            }
        ]
    }


def test_filter_changes(open_file):
    """
    There are 4 changes in project_changes with different types and score:
    - 3820f90d-c49e-4b83-aa13-1eb3520107e8 (cpes,metrics / 6.1)
    - cdfcc200-4cdb-42ba-98c1-42c800037f05 (metrics / 5.5)
    - 38a4b8f0-bb77-485e-a864-00c8e232cdf6 (cpes,vendors / 5.5)
    - df9fc70a-418d-49aa-b800-f54a7a2c1231 (title / 5.5)

    Default notification is:
    - score: 0
    - types: all
    """
    notifications = open_file("redis/0001/notifications.json")[
        "d9edc06b-1d7b-43c7-8cf5-bfa6687cd9fd"
    ][0]
    changes = open_file("redis/0001/project_changes.json")[
        "d9edc06b-1d7b-43c7-8cf5-bfa6687cd9fd"
    ]
    changes_details = open_file("redis/0001/changes_details.json")

    # All changes are returned by default
    assert filter_changes(notifications, changes, changes_details) == [
        "3820f90d-c49e-4b83-aa13-1eb3520107e8",
        "cdfcc200-4cdb-42ba-98c1-42c800037f05",
        "38a4b8f0-bb77-485e-a864-00c8e232cdf6",
        "df9fc70a-418d-49aa-b800-f54a7a2c1231",
    ]

    # Update by types
    notifications["notification_conf"]["types"] = []
    assert filter_changes(notifications, changes, changes_details) == []

    notifications["notification_conf"]["types"] = ["cpes", "title"]
    assert filter_changes(notifications, changes, changes_details) == [
        "3820f90d-c49e-4b83-aa13-1eb3520107e8",
        "38a4b8f0-bb77-485e-a864-00c8e232cdf6",
        "df9fc70a-418d-49aa-b800-f54a7a2c1231",
    ]

    notifications["notification_conf"]["types"] = ["metrics"]
    assert filter_changes(notifications, changes, changes_details) == [
        "3820f90d-c49e-4b83-aa13-1eb3520107e8",
        "cdfcc200-4cdb-42ba-98c1-42c800037f05",
    ]

    notifications["notification_conf"]["types"] = ["cpes", "vendors"]
    assert filter_changes(notifications, changes, changes_details) == [
        "3820f90d-c49e-4b83-aa13-1eb3520107e8",
        "38a4b8f0-bb77-485e-a864-00c8e232cdf6",
    ]

    # Increase the score threshold
    notifications["notification_conf"]["metrics"]["cvss31"] = 6
    assert filter_changes(notifications, changes, changes_details) == [
        "3820f90d-c49e-4b83-aa13-1eb3520107e8"
    ]

    notifications["notification_conf"]["metrics"]["cvss31"] = 8
    assert filter_changes(notifications, changes, changes_details) == []

    # Increase the score threshold and update the types
    notifications["notification_conf"]["metrics"]["cvss31"] = 6
    notifications["notification_conf"]["types"] = ["metrics"]
    assert filter_changes(notifications, changes, changes_details) == [
        "3820f90d-c49e-4b83-aa13-1eb3520107e8"
    ]

    notifications["notification_conf"]["metrics"]["cvss31"] = 6
    notifications["notification_conf"]["types"] = ["title"]
    assert filter_changes(notifications, changes, changes_details) == []
