from pathlib import Path
from unittest.mock import patch, Mock, PropertyMock

from opencve.extensions import db
from opencve.models.changes import Change
from opencve.models.events import Event
from opencve.models.tasks import Task
from opencve.models.cve import Cve


def test_new_cve_detected(handle_events):
    cves = Cve.query.all()
    assert len(cves) == 0

    handle_events("modified_cves/CVE-2018-18074.json")

    # The CVE is created
    cves = Cve.query.all()
    assert len(cves) == 1

    cve = cves[0]
    assert cve.cve_id == "CVE-2018-18074"

    # Task has been created
    tasks = Task.query.all()
    assert len(tasks) == 1
    task = tasks[0]

    # Change has been created
    changes = Change.query.all()
    assert len(changes) == 1
    change = changes[0]
    assert change.task.id == task.id
    assert change.json["id"] == "CVE-2018-18074"

    # Event has been created
    events = Event.query.all()
    assert len(events) == 1
    event = events[0]
    assert event.type == "new_cve"
    assert event.details == {}
    assert event.review == False
    assert event.cve.cve_id == "CVE-2018-18074"
    assert event.change.id == change.id
