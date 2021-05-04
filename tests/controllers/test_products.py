import pytest
from werkzeug.exceptions import NotFound

from opencve.controllers.products import ProductController
from opencve.models.vendors import Vendor


def test_metas(app, create_vendor):
    create_vendor("vendor1", "product1")

    with app.test_request_context():
        _, metas, _ = ProductController.list({"vendor": "vendor1"})
    assert metas == {}


def test_list_vendor_notfound(app):
    with app.test_request_context():
        with pytest.raises(NotFound):
            ProductController.list({"vendor": "notfound"})


def test_list(app, create_vendor):
    create_vendor("vendor1", "product1")
    create_vendor("vendor1", "product2")

    with app.test_request_context():
        products = ProductController.list_items({"vendor": "vendor1"})
    assert len(products) == 2
    assert sorted([p.name for p in products]) == ["product1", "product2"]


def test_list_paginated(app, create_vendor):
    old = app.config["PRODUCTS_PER_PAGE"]
    app.config["PRODUCTS_PER_PAGE"] = 3

    create_vendor("vendor1", "product1")
    create_vendor("vendor1", "product2")
    create_vendor("vendor1", "product3")
    create_vendor("vendor1", "product4")

    with app.test_request_context():
        products = ProductController.list_items({"vendor": "vendor1"})
        assert sorted([p.name for p in products]) == [
            "product1",
            "product2",
            "product3",
        ]
        products = ProductController.list_items({"vendor": "vendor1", "page": 2})
        assert sorted([p.name for p in products]) == ["product4"]

    app.config["PRODUCTS_PER_PAGE"] = old


@pytest.mark.parametrize(
    "args,result",
    [
        ({"search": "nonexistingkeyword"}, []),
        ({"search": "1"}, ["product1"]),
        ({"search": "product"}, ["product1", "product2"]),
    ],
)
def test_by_search(app, create_vendor, args, result):
    create_vendor("vendor1", "product1")
    create_vendor("vendor1", "product2")

    with app.test_request_context():
        products = ProductController.list_items({"vendor": "vendor1", **args})
    assert sorted([p.name for p in products]) == result
