from opencve.models.cve import Cve
from opencve.models.changes import Change
from opencve.models.events import Event
from opencve.models.tasks import Task


def test_check_summary(create_cve, handle_events, open_file):
    old = "The Requests package before 2.20.0 for Python sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect, which makes it easier for remote attackers to discover credentials by sniffing the network."
    new = "The summary has been changed."

    cve = create_cve("CVE-2018-18074")
    assert cve.summary == old

    # The 'summary' has been changed in this file
    handle_events("modified_cves/CVE-2018-18074_summary.json")
    cve = Cve.query.filter_by(cve_id="CVE-2018-18074").first()
    assert cve.summary == new

    # Task has been created
    tasks = Task.query.all()
    assert len(tasks) == 1
    task = tasks[0]

    # Change has been created
    changes = Change.query.all()
    assert len(changes) == 1
    change = changes[0]
    assert change.task.id == task.id
    assert change.json["cve"]["description"]["description_data"][0]["value"] == new

    # Event has been created
    events = Event.query.all()
    assert len(events) == 1
    event = events[0]
    assert event.type == "summary"
    assert event.details == {"old": old, "new": new}
    assert event.review == False
    assert event.cve.cve_id == "CVE-2018-18074"
    assert event.change.id == change.id
