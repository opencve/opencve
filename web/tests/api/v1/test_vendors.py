import pytest
from django.urls import reverse

from cves.constants import PRODUCT_SEPARATOR
from cves.models import Cve, Product, Vendor


@pytest.mark.django_db
@pytest.mark.parametrize(
    "vendor_name,product_name",
    [
        ("nodejs", "node.js"),
        ("ui.com", "unifi_os"),
        ("arox", "school_management_software_php\\/mysql"),
        ("cisco", "dna_spaces\\"),
        ("foo\\", "bar"),
    ],
)
def test_vendor_and_product_names_with_special_characters(
    auth_client, vendor_name, product_name
):
    vendor = Vendor.objects.create(name=vendor_name)
    Product.objects.create(vendor=vendor, name=product_name)
    Cve.objects.create(
        cve_id="CVE-2024-0001",
        vendors=[vendor_name, f"{vendor_name}{PRODUCT_SEPARATOR}{product_name}"],
    )
    client = auth_client()

    response = client.get(reverse("vendor-detail", kwargs={"name": vendor_name}))
    assert response.status_code == 200
    assert response.json()["name"] == vendor_name

    response = client.get(
        reverse("vendor-cves-list", kwargs={"vendor_name": vendor_name})
    )
    assert response.status_code == 200
    assert [c["cve_id"] for c in response.json()["results"]] == ["CVE-2024-0001"]

    response = client.get(
        reverse("vendor-products-list", kwargs={"vendor_name": vendor_name})
    )
    assert response.status_code == 200
    assert [p["name"] for p in response.json()["results"]] == [product_name]

    response = client.get(
        reverse(
            "vendor-products-detail",
            kwargs={"vendor_name": vendor_name, "name": product_name},
        )
    )
    assert response.status_code == 200
    assert response.json()["name"] == product_name

    response = client.get(
        reverse(
            "product-cves-list",
            kwargs={"vendor_name": vendor_name, "product_name": product_name},
        )
    )
    assert response.status_code == 200
    assert [c["cve_id"] for c in response.json()["results"]] == ["CVE-2024-0001"]
