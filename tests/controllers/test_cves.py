import pytest
from flask import request
from werkzeug.exceptions import NotFound

from opencve.controllers.cves import CveController


def test_metas(app, create_cves):
    create_cves(["CVE-2018-18074", "CVE-2020-9392", "CVE-2020-26116", "CVE-2020-27781"])

    with app.test_request_context():
        cves, metas, _ = CveController.list()
        assert len(cves.items) == 4
        assert metas == {"vendor": None, "product": None}

        cves, metas, _ = CveController.list({"vendor": "python"})
        assert len(cves.items) == 1
        assert metas["vendor"].name == "python"

        cves, metas, _ = CveController.list(
            {"vendor": "redhat", "product": "ceph_storage"}
        )
        assert len(cves.items) == 1
        assert metas["vendor"].name == "redhat"
        assert metas["product"].name == "ceph_storage"


def test_list_all_cves(app, create_cves):
    create_cves(["CVE-2018-18074", "CVE-2020-9392", "CVE-2020-26116", "CVE-2020-27781"])

    with app.test_request_context():
        cves = CveController.list_items()

    assert len(cves) == 4
    assert sorted([cve.cve_id for cve in cves]) == [
        "CVE-2018-18074",
        "CVE-2020-26116",
        "CVE-2020-27781",
        "CVE-2020-9392",
    ]


def test_list_cves_paginated(app, create_cves):
    old = app.config["CVES_PER_PAGE"]
    app.config["CVES_PER_PAGE"] = 3

    create_cves(
        [
            "CVE-2018-18074",
            "CVE-2020-9392",
            "CVE-2020-26116",
            "CVE-2020-27781",
            "CVE-2019-17052",
        ]
    )

    with app.test_request_context():
        cves = CveController.list_items()
        assert sorted([cve.cve_id for cve in cves]) == [
            "CVE-2019-17052",
            "CVE-2020-26116",
            "CVE-2020-27781",
        ]

        cves = CveController.list_items({"page": 2})
        assert sorted([cve.cve_id for cve in cves]) == [
            "CVE-2018-18074",
            "CVE-2020-9392",
        ]

        with pytest.raises(NotFound):
            cves = CveController.list_items({"page": 3})

    app.config["CVES_PER_PAGE"] = old


@pytest.mark.parametrize(
    "args,result",
    [
        ({"search": "nonexistingkeyword"}, []),
        ({"search": "CRLF"}, ["CVE-2020-26116"]),
        ({"search": "http"}, ["CVE-2018-18074", "CVE-2020-26116"]),
    ],
)
def test_search_cves(app, create_cves, args, result):
    create_cves(["CVE-2018-18074", "CVE-2020-9392", "CVE-2020-26116"])

    with app.test_request_context():
        cves = CveController.list_items(args)
    assert sorted([cve.cve_id for cve in cves]) == result


@pytest.mark.parametrize(
    "args,result",
    [
        ({"cwe": "CWE-276"}, ["CVE-2020-9392"]),
        ({"cwe": "CWE-522"}, ["CVE-2018-18074", "CVE-2020-27781"]),
        ({"cwe": "CWE-1234"}, []),
    ],
)
def test_filtered_by_cwe(app, create_cves, args, result):
    create_cves(["CVE-2018-18074", "CVE-2020-9392", "CVE-2020-26116", "CVE-2020-27781"])

    with app.test_request_context():
        cves = CveController.list_items(args)
    assert sorted([cve.cve_id for cve in cves]) == result


@pytest.mark.parametrize(
    "args,result",
    [
        ({"cvss": "none"}, ["CVE-2020-35076"]),
        ({"cvss": "low"}, ["CVE-2019-17052"]),
        ({"cvss": "medium"}, ["CVE-2020-29660"]),
        ({"cvss": "high"}, ["CVE-2020-26116", "CVE-2020-9392"]),
        ({"cvss": "critical"}, ["CVE-2018-18074"]),
    ],
)
def test_filtered_by_cvss(app, create_cves, args, result):
    create_cves(
        [
            "CVE-2018-18074",
            "CVE-2020-9392",
            "CVE-2020-26116",
            "CVE-2020-29660",
            "CVE-2019-17052",
            "CVE-2020-35076",
        ]
    )

    with app.test_request_context():
        cves = CveController.list_items(args)
    assert sorted([cve.cve_id for cve in cves]) == result


@pytest.mark.parametrize(
    "args,result",
    [
        ({"vendor": "redhat", "product": "ceph_storage"}, ["CVE-2020-27781"]),
        (
            {"vendor": "linux", "product": "linux_kernel"},
            ["CVE-2019-17052", "CVE-2019-8075"],
        ),
        ({"vendor": "redhat"}, ["CVE-2020-27781"]),
        ({"vendor": "linux"}, ["CVE-2019-17052", "CVE-2019-8075"]),
    ],
)
def test_filtered_by_vendors_products(app, create_cves, args, result):
    create_cves(["CVE-2019-8075", "CVE-2019-17052", "CVE-2020-27781"])

    with app.test_request_context():
        cves = CveController.list_items(args)
    assert sorted([cve.cve_id for cve in cves]) == result


def test_vendors_products_not_found(app):
    with app.test_request_context():
        with pytest.raises(NotFound):
            CveController.list_items({"vendor": "foo"})
        with pytest.raises(NotFound):
            CveController.list_items({"vendor": "foo", "product": "bar"})
