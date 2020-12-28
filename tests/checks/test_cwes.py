from opencve.models.changes import Change
from opencve.models.cve import Cve
from opencve.models.cwe import Cwe
from opencve.models.events import Event
from opencve.models.tasks import Task


def test_check_cwes(create_cve, handle_events, open_file):
    old = "CWE-522"
    new = "CWE-1337"
    cve = create_cve("CVE-2018-18074")

    # Check the current CWE
    assert cve.cwes == [old]
    cwes = Cwe.query.all()
    assert len(cwes) == 1
    cwe = cwes[0]
    assert cwe.cwe_id == old
    assert not cwe.name

    # The CWE-522 has been removed and the CWE-1337 has been added
    handle_events("modified_cves/CVE-2018-18074_cwes.json")
    cve = Cve.query.filter_by(cve_id="CVE-2018-18074").first()
    assert cve.cwes == [new]

    # New CWE has been created
    assert Cwe.query.filter_by(cwe_id=new).first()

    # Task has been created
    tasks = Task.query.all()
    assert len(tasks) == 1
    task = tasks[0]

    # Change has been created
    changes = Change.query.all()
    assert len(changes) == 1
    change = changes[0]
    assert change.task.id == task.id
    assert (
        change.json["cve"]["problemtype"]["problemtype_data"][0]["description"][0][
            "value"
        ]
        == new
    )

    # Event has been created
    events = Event.query.all()
    assert len(events) == 1
    event = events[0]
    assert event.type == "cwes"
    assert event.details == {"added": [new], "removed": [old]}
