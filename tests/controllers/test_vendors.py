import pytest
from werkzeug.exceptions import NotFound

from opencve.controllers.vendors import VendorController


def test_metas(app):
    with app.test_request_context():
        _, metas, _ = VendorController.list()
    assert metas == {}


def test_list(app, create_vendor):
    create_vendor("vendor1", "product1")
    create_vendor("vendor2", "product2")

    with app.test_request_context():
        vendors = VendorController.list_items()
    assert len(vendors) == 2
    assert sorted([v.name for v in vendors]) == ["vendor1", "vendor2"]


def test_list_paginated(app, create_vendor):
    old = app.config["VENDORS_PER_PAGE"]
    app.config["VENDORS_PER_PAGE"] = 3

    create_vendor("vendor1", "product1")
    create_vendor("vendor2", "product2")
    create_vendor("vendor3", "product3")
    create_vendor("vendor4", "product4")

    with app.test_request_context():
        vendors = VendorController.list_items()
        assert sorted([v.name for v in vendors]) == ["vendor1", "vendor2", "vendor3"]
        vendors = VendorController.list_items({"page": 2})
        assert sorted([v.name for v in vendors]) == ["vendor4"]

    app.config["VENDORS_PER_PAGE"] = old


@pytest.mark.parametrize(
    "args,result",
    [
        ({"search": "nonexistingkeyword"}, []),
        ({"search": "1"}, ["vendor_1"]),
        ({"search": "vendor"}, ["vendor_1", "vendor_2"]),
        ({"search": "vendor 2"}, ["vendor_2"]),
    ],
)
def test_by_search(app, create_vendor, args, result):
    create_vendor("vendor_1", "product1")
    create_vendor("vendor_2", "product2")

    with app.test_request_context():
        vendors = VendorController.list_items(args)
    assert sorted([v.name for v in vendors]) == result
