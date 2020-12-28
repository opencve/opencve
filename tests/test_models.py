from opencve.models.cve import Cve
from opencve.models.cwe import Cwe
from opencve.models.metas import Meta
from opencve.models.products import Product
from opencve.models.vendors import Vendor
from opencve.models.users import User
from opencve.models.products import Product
from opencve.models.vendors import Vendor
from opencve.models.users import User


def test_new_cve():
    cve = Cve(
        cve_id="CVE-2020-1234",
        json={"foo": "bar"},
        vendors=["vendor-1", "vendor-2", "product-1"],
        cwes=["CWE-1234"],
        summary="Example of summary",
        cvss2=5.0,
        cvss3=10.0,
        events=[],
        changes=[],
        alerts=[],
    )
    assert cve.cve_id == "CVE-2020-1234"
    assert cve.json == {"foo": "bar"}
    assert cve.vendors == ["vendor-1", "vendor-2", "product-1"]
    assert cve.cwes == ["CWE-1234"]
    assert cve.summary == "Example of summary"
    assert cve.cvss2 == 5.0
    assert cve.cvss3 == 10.0
    assert cve.events == []
    assert cve.changes == []
    assert cve.alerts == []


def test_new_cwe():
    cwe = Cwe(
        cwe_id="CWE-79",
        name="Improper Neutralization...",
        description="The software does not...",
    )
    assert str(cwe) == "<Cwe CWE-79>"
    assert cwe.cwe_id == "CWE-79"
    assert cwe.name == "Improper Neutralization..."
    assert cwe.description == "The software does not..."


def test_new_meta():
    meta = Meta(name="foo", value="bar",)
    assert meta.name == "foo"
    assert meta.value == "bar"


def test_new_product():
    product = Product(name="Requests", vendor=Vendor(name="Python"))
    assert str(product) == "<Product Requests>"
    assert product.name == "Requests"
    assert product.vendor.name == "Python"


def test_product_with_users():
    product = Product(
        name="Requests",
        vendor=Vendor(name="Python"),
        users=[User(username="nicolas"), User(username="laurent")],
    )
    assert len(product.users) == 2
    assert [u.username for u in product.users] == ["nicolas", "laurent"]


def test_empty_vendor():
    vendor = Vendor(name="Python")
    assert str(vendor) == "<Vendor Python>"
    assert vendor.name == "Python"
    assert vendor.products == []
    assert vendor.users == []


def test_vendor_with_products():
    vendor = Vendor(
        name="Python",
        products=[
            Product(name="Requests"),
            Product(name="Celery"),
            Product(name="Virtualenv"),
        ],
    )

    assert len(vendor.products) == 3
    assert [p.name for p in vendor.products] == ["Requests", "Celery", "Virtualenv"]


def test_vendor_with_users():
    vendor = Vendor(
        name="Python", users=[User(username="nicolas"), User(username="laurent")]
    )
    assert len(vendor.users) == 2
    assert [u.username for u in vendor.users] == ["nicolas", "laurent"]
