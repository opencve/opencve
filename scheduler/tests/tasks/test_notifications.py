from includes.tasks.notifications import filter_changes


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
