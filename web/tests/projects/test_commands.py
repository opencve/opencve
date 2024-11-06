from cves.constants import PRODUCT_SEPARATOR
from cves.models import Vendor, Product
from projects.models import Project

from django.core.management import call_command


def test_fix_missing_vendors(create_organization):
    def _list_vendors():
        return list(Vendor.objects.values_list("name", flat=True))

    def _list_products():
        return list(
            f"{p[1]}{PRODUCT_SEPARATOR}{p[0]}"
            for p in Product.objects.values_list("name", "vendor__name")
        )

    # Only 1 vendor and 1 product are saved in DB
    vendor = Vendor.objects.create(name="vendor1")
    Product.objects.create(name="productA", vendor=vendor)

    # The project subscriptions include another records
    Project.objects.create(
        name="myproject",
        organization=create_organization("myorga"),
        subscriptions={
            "vendors": ["vendor1", "vendor2"],
            "products": ["vendor1$PRODUCT$productA", "vendor1$PRODUCT$productB"],
        },
    )

    assert _list_vendors() == ["vendor1"]
    assert _list_products() == ["vendor1$PRODUCT$productA"]

    call_command("fix_missing_vendors")

    assert _list_vendors() == ["vendor1", "vendor2"]
    assert _list_products() == ["vendor1$PRODUCT$productA", "vendor1$PRODUCT$productB"]
