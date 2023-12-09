from opencve.models.cve import Cve
from opencve.models.changes import Change
from opencve.models.events import Event
from opencve.models.tasks import Task


def test_check_references(create_cve, handle_events, open_file):
    cve = create_cve("CVE-2018-18074")
    references = cve.json["references"]
    assert len(references) == 9
    assert [r["url"] for r in references] == [
        "http://docs.python-requests.org/en/master/community/updates/#release-and-version-history",
        "http://lists.opensuse.org/opensuse-security-announce/2019-07/msg00024.html",
        "https://access.redhat.com/errata/RHSA-2019:2035",
        "https://bugs.debian.org/910766",
        "https://github.com/requests/requests/commit/c45d7c49ea75133e52ab22a8e9e13173938e36ff",
        "https://github.com/requests/requests/issues/4716",
        "https://github.com/requests/requests/pull/4718",
        "https://usn.ubuntu.com/3790-1/",
        "https://usn.ubuntu.com/3790-2/",
    ]

    # 1 reference added, 1 modified and 7 removed
    handle_events("modified_cves/CVE-2018-18074_references.json")
    cve = Cve.query.filter_by(cve_id="CVE-2018-18074").first()
    references = cve.json["references"]
    assert len(references) == 3
    assert sorted([r["url"] for r in references]) == sorted(
        [
            "https://www.opencve.io/",
            "https://access.redhat.com/errata/RHSA-2019:2035",
            "https://bugs.debian.org/910766",
        ]
    )

    # Task has been created
    tasks = Task.query.all()
    assert len(tasks) == 1
    task = tasks[0]

    # Change has been created
    changes = Change.query.all()
    assert len(changes) == 1
    change = changes[0]
    assert change.task.id == task.id
    references = change.json["references"]
    assert len(references) == 3
    assert sorted([r["url"] for r in references]) == sorted(
        [
            "https://www.opencve.io/",
            "https://access.redhat.com/errata/RHSA-2019:2035",
            "https://bugs.debian.org/910766",
        ]
    )

    # Event has been created
    events = Event.query.all()
    assert len(events) == 1
    event = events[0]
    assert event.type == "references"

    changed = event.details["changed"]
    assert len(changed) == 1
    assert changed[0]["old"]["tags"] == []
    assert changed[0]["new"]["tags"] == ["opencve"]

    added = event.details["added"]
    assert len(added) == 1
    assert added[0]["name"] == "OPENCVE-1234"
    assert added[0]["source"] == "OPENCVE"
    assert added[0]["tags"] == ["opencve"]
    assert added[0]["url"] == "https://www.opencve.io/"

    removed = event.details["removed"]
    assert len(removed) == 7
    assert sorted([r["url"] for r in removed]) == sorted(
        [
            "https://github.com/requests/requests/issues/4716",
            "https://github.com/requests/requests/commit/c45d7c49ea75133e52ab22a8e9e13173938e36ff",
            "http://docs.python-requests.org/en/master/community/updates/#release-and-version-history",
            "https://github.com/requests/requests/pull/4718",
            "https://usn.ubuntu.com/3790-2/",
            "https://usn.ubuntu.com/3790-1/",
            "http://lists.opensuse.org/opensuse-security-announce/2019-07/msg00024.html",
        ]
    )


def test_check_references_with_quote(create_cve, handle_events, open_file):
    cve = create_cve("CVE-2022-3122")
    references = cve.json["references"]
    assert len(references) == 2
    assert [r["url"] for r in references] == [
        "https://github.com/joinia/webray.com.cn/blob/main/Clinic's-Patient-Management-System/cpmssql.md",
        "https://vuldb.com/?id.207854",
    ]

    # 1 modified reference
    handle_events("modified_cves/CVE-2022-3122_references.json")
    cve = Cve.query.filter_by(cve_id="CVE-2022-3122").first()

    # Task has been created
    tasks = Task.query.all()
    assert len(tasks) == 1
    task = tasks[0]

    # Change has been created
    changes = Change.query.all()
    assert len(changes) == 1
    change = changes[0]
    assert change.task.id == task.id
    references = change.json["references"]
    assert len(references) == 2
    assert sorted([r["url"] for r in references]) == sorted(
        [
            "https://github.com/joinia/webray.com.cn/blob/main/Clinic's-Patient-Management-System/cpmssql.md",
            "https://vuldb.com/?id.207854",
        ]
    )

    # Event has been created
    events = Event.query.all()
    assert len(events) == 1
    event = events[0]
    assert event.type == "references"

    changed = event.details["changed"]
    assert len(changed) == 1
    assert changed[0]["old"]["tags"] == []
    assert changed[0]["new"]["tags"] == ["Exploit", "Third Party Advisory"]
