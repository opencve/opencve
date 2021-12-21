from opencve.constants import PRODUCT_SEPARATOR
from opencve.models.cve import Cve
from opencve.models.changes import Change
from opencve.models.events import Event
from opencve.models.products import Product
from opencve.models.tasks import Task
from opencve.models.vendors import Vendor
from opencve.utils import convert_cpes


def test_check_first_time(create_cve, handle_events):
    """
    This test demontrates the difference between the `cpes` and `first_time`
    events. While the first one will always been triggered when a new CPE is updated,
    the second one will just been triggered for the first apparition of the vendor.
    """
    create_cve("CVE-2018-18074")

    vendors = Vendor.query.all()
    assert len(vendors) == 2
    assert sorted([v.name for v in vendors]) == sorted(["python-requests", "canonical"])

    # This version adds a new CPE (cpe:2.3:a:opencveio:opencve:1:*:*:*:*:*:*:*)
    handle_events("modified_cves/CVE-2018-18074_first_time_1.json")

    # 2 events: `cpes` and `first_time`
    events = Event.query.all()
    assert len(events) == 2
    assert sorted([e.type.code for e in events]) == ["cpes", "first_time"]

    # The `fist_time event` contains the new vendors in its details
    event = Event.query.filter_by(type="first_time").first()
    assert sorted(event.details) == ["opencveio", "opencveio$PRODUCT$opencve"]

    # This version adds a new CPE (cpe:2.3:a:opencveio:opencve:2:*:*:*:*:*:*:*)
    handle_events("modified_cves/CVE-2018-18074_first_time_2.json")

    # Another `cpes` event has been triggered, but not the `first_time` one
    # because the `opencveio` vendor and `opencve` product have already appeared
    # in a previous event.
    events = Event.query.all()
    assert len(events) == 3
    assert sorted([e.type.code for e in events]) == ["cpes", "cpes", "first_time"]
