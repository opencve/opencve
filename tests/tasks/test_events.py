from pathlib import Path
from unittest.mock import patch, Mock, PropertyMock

from opencve.extensions import db
from opencve.models.changes import Change
from opencve.models.events import Event
from opencve.models.tasks import Task
from opencve.models.cve import Cve
from opencve.models.metas import Meta
from opencve.tasks.events import has_changed, download_modified_items


@patch("opencve.tasks.events.requests.get")
def test_has_changed(mock_get, open_raw_file, handle_events):
    old = "default"
    new = "CE80026155D878F20E49576A1C7D2A52163CF4C52C1CCCC41497CA14E03761D5"
    type(mock_get.return_value).content = PropertyMock(
        return_value=open_raw_file("nvdcve-1.1-modified.meta").encode("utf-8")
    )

    # Create the initial meta
    db.session.add(Meta(name="nvd_last_sha256", value=old))
    db.session.commit()

    # The sha256 has changed
    meta, sha256 = has_changed()
    assert meta.value == old
    assert sha256 == new


@patch("opencve.tasks.events.requests.get")
def test_has_not_changed(mock_get, open_raw_file, handle_events):
    value = "CE80026155D878F20E49576A1C7D2A52163CF4C52C1CCCC41497CA14E03761D5"
    type(mock_get.return_value).content = PropertyMock(
        return_value=open_raw_file("nvdcve-1.1-modified.meta").encode("utf-8")
    )

    # Create the initial meta
    db.session.add(Meta(name="nvd_last_sha256", value=value))
    db.session.commit()

    # The sha256 has changed
    meta, sha256 = has_changed()
    assert meta.value == value
    assert sha256 == None


@patch("opencve.tasks.events.requests.get")
def test_download_modified_items(mock_get, open_raw_file):
    with open(
        Path(__file__).parent.parent.resolve()
        / "data/modified_cves/nvdcve-1.1-modified.json.gz"
    ) as f:
        data = f.buffer.read()
    type(mock_get.return_value).content = PropertyMock(return_value=data)
    items = download_modified_items()
    assert len(items) == 1
    assert items[0]["cve"]["CVE_data_meta"]["ID"] == "CVE-2005-0366"


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
    assert change.json["cve"]["CVE_data_meta"]["ID"] == "CVE-2018-18074"

    # Event has been created
    events = Event.query.all()
    assert len(events) == 1
    event = events[0]
    assert event.type == "new_cve"
    assert event.details == {}
    assert event.review == False
    assert event.cve.cve_id == "CVE-2018-18074"
    assert event.change.id == change.id
