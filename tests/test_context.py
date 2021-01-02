from opencve.constants import PRODUCT_SEPARATOR
from opencve.context import _excerpt


def test_vendors_excerpt_without_more():
    result = _excerpt(
        [
            "vendor1",
            "vendor2",
            f"vendor1{PRODUCT_SEPARATOR}product1",
            f"vendor2{PRODUCT_SEPARATOR}product2",
        ],
        "vendors",
    )

    assert '<span class="badge badge-primary">2</span>' in result
    assert "Vendor1" in result
    assert "cve?vendor=vendor1" in result
    assert "Vendor2" in result
    assert "cve?vendor=vendor2" in result


def test_vendors_excerpt_with_more():
    result = _excerpt(
        [
            "vendor1",
            "vendor2",
            "vendor3",
            "vendor4",
            f"vendor1{PRODUCT_SEPARATOR}product1",
            f"vendor2{PRODUCT_SEPARATOR}product2",
            f"vendor3{PRODUCT_SEPARATOR}product3",
            f"vendor4{PRODUCT_SEPARATOR}product4",
        ],
        "vendors",
    )

    assert '<span class="badge badge-primary">4</span>' in result
    assert "Vendor1" in result
    assert "cve?vendor=vendor1" in result
    assert "Vendor2" in result
    assert "cve?vendor=vendor2" in result
    assert "Vendor3" in result
    assert "cve?vendor=vendor3" in result
    assert "<i>and 1 more</i>" in result


def test_products_excerpt_without_more():
    result = _excerpt(
        [
            "vendor1",
            "vendor2",
            f"vendor1{PRODUCT_SEPARATOR}product1",
            f"vendor2{PRODUCT_SEPARATOR}product2",
        ],
        "products",
    )

    assert '<span class="badge badge-primary">2</span>' in result
    assert "Product1" in result
    assert "cve?vendor=vendor1&product=product1" in result
    assert "Product2" in result
    assert "cve?vendor=vendor2&product=product2" in result


def test_products_excerpt_with_more():
    result = _excerpt(
        [
            "vendor1",
            "vendor2",
            "vendor3",
            "vendor4",
            f"vendor1{PRODUCT_SEPARATOR}product1",
            f"vendor2{PRODUCT_SEPARATOR}product2",
            f"vendor3{PRODUCT_SEPARATOR}product3",
            f"vendor4{PRODUCT_SEPARATOR}product4",
        ],
        "products",
    )

    assert '<span class="badge badge-primary">4</span>' in result
    assert "Product1" in result
    assert "cve?vendor=vendor1&product=product1" in result
    assert "Product2" in result
    assert "cve?vendor=vendor2&product=product2" in result
    assert "Product3" in result
    assert "cve?vendor=vendor3&product=product3" in result
    assert "<i>and 1 more</i>" in result
