import uuid

import pytest

from cves.models import Product, Vendor
from opencve.pagination import (
    keyset_cursor_payload,
    paginate_keyset,
    parse_keyset_cursor,
)


@pytest.mark.parametrize(
    "name,id_,expected",
    [
        (None, None, None),
        ("", "", None),
        ("vendor", None, None),
        (None, str(uuid.uuid4()), None),
        ("vendor", "not-a-uuid", None),
        ("", str(uuid.uuid4()), None),
        ("a" * 257, str(uuid.uuid4()), None),
    ],
)
def test_parse_keyset_cursor_invalid(name, id_, expected):
    assert parse_keyset_cursor(name, id_) == expected


def test_parse_keyset_cursor_valid():
    vendor_id = str(uuid.uuid4())
    assert parse_keyset_cursor("microsoft", vendor_id) == ("microsoft", vendor_id)


def test_paginate_keyset_first_page(db):
    for index in range(25):
        Vendor.objects.create(name=f"vendor-{index:02d}")

    page = paginate_keyset(Vendor.objects.all(), cursor=None, limit=20)

    assert len(page.items) == 20
    assert page.has_next is True
    assert page.next_cursor == (page.items[-1].name, str(page.items[-1].id))


def test_paginate_keyset_next_page(db):
    vendors = [Vendor.objects.create(name=f"vendor-{index:02d}") for index in range(25)]
    first_page = paginate_keyset(Vendor.objects.all(), cursor=None, limit=20)
    second_page = paginate_keyset(
        Vendor.objects.all(), cursor=first_page.next_cursor, limit=20
    )

    assert set(item.id for item in first_page.items).isdisjoint(
        {item.id for item in second_page.items}
    )
    assert len(second_page.items) == 5
    assert second_page.has_next is False
    assert second_page.next_cursor is None
    assert first_page.items[-1].id == vendors[19].id
    assert second_page.items[0].id == vendors[20].id


def test_paginate_keyset_stale_cursor_returns_empty_page(db):
    Vendor.objects.create(name="vendor-00")
    Vendor.objects.create(name="vendor-01")

    page = paginate_keyset(
        Vendor.objects.all(),
        cursor=("vendor-99", str(uuid.uuid4())),
        limit=20,
    )

    assert page.items == []
    assert page.has_next is False
    assert page.next_cursor is None


def test_paginate_keyset_stable_order_for_duplicate_product_names(db):
    vendor_a = Vendor.objects.create(name="vendor-a")
    vendor_b = Vendor.objects.create(name="vendor-b")
    product_a = Product.objects.create(name="android", vendor=vendor_a)
    product_b = Product.objects.create(name="android", vendor=vendor_b)

    page = paginate_keyset(Product.objects.all(), cursor=None, limit=1)
    second_page = paginate_keyset(
        Product.objects.all(), cursor=page.next_cursor, limit=1
    )

    assert page.items[0].id != second_page.items[0].id
    ordered_ids = sorted(
        [product_a.id, product_b.id],
        key=lambda product_id: (
            "android",
            str(product_id),
        ),
    )
    assert page.items[0].id == ordered_ids[0]
    assert second_page.items[0].id == ordered_ids[1]


def test_keyset_cursor_payload(db):
    Vendor.objects.create(name="payload-vendor-00")
    Vendor.objects.create(name="payload-vendor-01")
    page = paginate_keyset(
        Vendor.objects.filter(name__startswith="payload-vendor"),
        cursor=None,
        limit=1,
    )

    assert keyset_cursor_payload(page) == {
        "has_next": True,
        "after": "payload-vendor-00",
        "after_id": str(page.items[0].id),
    }
