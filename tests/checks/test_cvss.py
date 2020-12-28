from opencve.models.cve import Cve
from opencve.models.changes import Change
from opencve.models.events import Event
from opencve.models.tasks import Task


def test_check_cvss(create_cve, handle_events, open_file):
    old_cvss2 = 5.0
    old_cvss3 = 9.8
    new_cvss2 = 6.0
    new_cvss3 = 10.0

    cve = create_cve("CVE-2018-18074")
    assert cve.cvss2 == old_cvss2
    assert cve.cvss3 == old_cvss3

    # The CVSS2 has been changed to 6.0 and the CVSS3 to 10.0
    handle_events("modified_cves/CVE-2018-18074_cvss.json")
    cve = Cve.query.filter_by(cve_id="CVE-2018-18074").first()
    assert cve.cvss2 == new_cvss2
    assert cve.cvss3 == new_cvss3

    # Task has been created
    tasks = Task.query.all()
    assert len(tasks) == 1
    task = tasks[0]

    # Change has been created
    changes = Change.query.all()
    assert len(changes) == 1
    change = changes[0]
    assert change.task.id == task.id
    assert change.json["impact"]["baseMetricV2"]["cvssV2"]["baseScore"] == new_cvss2
    assert change.json["impact"]["baseMetricV3"]["cvssV3"]["baseScore"] == new_cvss3

    # Event has been created
    events = Event.query.all()
    assert len(events) == 1
    event = events[0]
    assert event.type == "cvss"
    assert event.details == {
        "new": {"v2": new_cvss2, "v3": new_cvss3},
        "old": {"v2": old_cvss2, "v3": old_cvss3},
    }
    assert event.review == False
    assert event.cve.cve_id == "CVE-2018-18074"
    assert event.change.id == change.id
