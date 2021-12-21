from opencve.constants import PRODUCT_SEPARATOR
from opencve.models.cve import Cve
from opencve.models.changes import Change
from opencve.models.events import Event
from opencve.models.products import Product
from opencve.models.tasks import Task
from opencve.models.vendors import Vendor
from opencve.utils import convert_cpes


def test_check_cpes(create_cve, handle_events, open_file):
    cve = create_cve("CVE-2018-18074")
    assert sorted(cve.vendors) == sorted(
        [
            "python-requests",
            f"python-requests{PRODUCT_SEPARATOR}requests",
            "canonical",
            f"canonical{PRODUCT_SEPARATOR}ubuntu_linux",
        ]
    )

    # The CVE creation already created vendors and products
    vendors = Vendor.query.all()
    assert len(vendors) == 2
    assert sorted([v.name for v in vendors]) == sorted(["python-requests", "canonical"])

    products = Product.query.all()
    assert len(products) == 2
    assert sorted([p.name for p in products]) == sorted(["requests", "ubuntu_linux"])

    # 1 CPE added and 1 CPE removed (including 1 new vendor and product)
    handle_events("modified_cves/CVE-2018-18074_cpes.json")
    cve = Cve.query.filter_by(cve_id="CVE-2018-18074").first()
    assert sorted(cve.vendors) == sorted(
        [
            "canonical",
            f"canonical{PRODUCT_SEPARATOR}ubuntu_linux",
            "opencveio",
            f"opencveio{PRODUCT_SEPARATOR}opencve",
        ]
    )

    # 1 new vendor
    vendors = Vendor.query.all()
    assert len(vendors) == 3
    assert sorted([v.name for v in vendors]) == sorted(
        ["python-requests", "canonical", "opencveio"]
    )

    # 1 new product
    products = Product.query.all()
    assert len(products) == 3
    assert sorted([p.name for p in products]) == sorted(
        ["requests", "ubuntu_linux", "opencve"]
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
    assert convert_cpes(change.json["configurations"]) == {
        "canonical": ["ubuntu_linux"],
        "opencveio": ["opencve"],
    }

    # Event has been created
    event = Event.query.filter_by(type="cpes").first()
    assert event.type == "cpes"
    assert event.details == {
        "added": ["cpe:2.3:a:opencveio:opencve:*:*:*:*:*:*:*:*"],
        "removed": ["cpe:2.3:a:python-requests:requests:*:*:*:*:*:*:*:*"],
    }
    assert event.review == False
    assert event.cve.cve_id == "CVE-2018-18074"
    assert event.change.id == change.id
