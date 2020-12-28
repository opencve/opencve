import datetime

from opencve.commands.utils import CveUtil
from opencve.constants import PRODUCT_SEPARATOR
from opencve.extensions import db
from opencve.models.changes import Change
from opencve.models.cve import Cve
from opencve.models.cwe import Cwe
from opencve.models.events import Event
from opencve.models.tasks import Task
from opencve.models.vendors import Vendor
from opencve.models.products import Product


def test_create_cve(app, open_file):
    cve = CveUtil.create_cve(open_file("cves/CVE-2020-26116.json"))

    cves = Cve.query.all()
    assert len(cves) == 1

    # The CVE has been created
    assert cve.id == cves[0].id
    assert cve.cve_id == "CVE-2020-26116"
    assert cve.cwes == ["CWE-116"]
    assert sorted(cve.vendors) == sorted(
        [
            "fedoraproject",
            f"fedoraproject{PRODUCT_SEPARATOR}fedora",
            "python",
            f"python{PRODUCT_SEPARATOR}python",
        ]
    )
    assert (
        cve.summary
        == "http.client in Python 3.x before 3.5.10, 3.6.x before 3.6.12, 3.7.x before 3.7.9, and 3.8.x before 3.8.5 allows CRLF injection if the attacker controls the HTTP request method, as demonstrated by inserting CR and LF control characters in the first argument of HTTPConnection.request."
    )
    assert cve.cvss2 == 6.4
    assert cve.cvss3 == 7.2
    assert cve.events == []
    assert cve.changes == []
    assert cve.alerts == []
    assert round(cve.cvss_weight, 1) == 13.6

    # The CWE has been created
    cwes = Cwe.query.all()
    assert len(cwes) == 1
    cwe = cwes[0]
    assert cwe.cwe_id == "CWE-116"

    # The vendors and products has been created
    vendors = Vendor.query.all()
    assert len(vendors) == 2

    vendor_1 = Vendor.query.filter_by(name="fedoraproject").first()
    assert len(vendor_1.products) == 1
    assert vendor_1.products[0].name == "fedora"

    vendor_2 = Vendor.query.filter_by(name="python").first()
    assert len(vendor_2.products) == 1
    assert vendor_2.products[0].name == "python"


def test_has_changed(app, open_file):
    cve_json = open_file("cves/CVE-2020-26116.json")
    cve_db = CveUtil.create_cve(cve_json)

    cve_db.updated_at = datetime.datetime.now() - datetime.timedelta(days=1)
    db.session.commit()

    assert CveUtil.cve_has_changed(cve_db, cve_json)


def test_create_event(app, open_file):
    cve_json = open_file("cves/CVE-2020-26116.json")
    cve = CveUtil.create_cve(cve_json)

    event = CveUtil.create_event(cve, cve_json, "new_cve", {"foo": "bar"})
    assert Event.query.first().id == event.id

    assert event.type == "new_cve"
    assert event.details == {"foo": "bar"}
    assert event.review == False
    assert event.cve_id == cve.id
    assert event.cve.id == cve.id
    assert event.change == None
    assert event.change_id == None
    assert event.alerts == []


def test_create_change(open_file):
    task = Task()
    db.session.add(task)
    db.session.commit()

    cve_json = open_file("cves/CVE-2020-26116.json")
    cve = CveUtil.create_cve(cve_json)

    change = CveUtil.create_change(cve, cve_json, task, [])
    assert Change.query.first().id == change.id

    assert change.json == cve_json
    assert change.cve_id == cve.id
    assert change.cve.id == cve.id
    assert change.task_id == task.id
    assert change.task.id == task.id
    assert change.events == []
