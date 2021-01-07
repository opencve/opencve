import pytest
from flask import request


def test_list_no_cves(client):
    response = client.get("/cve")
    assert response.status_code == 200
    assert b"No CVE found." in response.data


def test_list_all_cves(client, create_cve, make_soup, get_cve_names):
    create_cve("CVE-2018-18074")
    create_cve("CVE-2020-9392")
    create_cve("CVE-2020-26116")
    create_cve("CVE-2020-27781")

    response = client.get("/cve")
    soup = make_soup(response.data)
    cves = get_cve_names(soup)
    assert response.status_code == 200
    assert sorted(cves) == [
        "CVE-2018-18074",
        "CVE-2020-26116",
        "CVE-2020-27781",
        "CVE-2020-9392",
    ]


def test_list_cves_paginated(app, client, create_cve, make_soup, get_cve_names):
    old = app.config["CVES_PER_PAGE"]
    app.config["CVES_PER_PAGE"] = 3

    create_cve("CVE-2018-18074")
    create_cve("CVE-2020-9392")
    create_cve("CVE-2020-26116")
    create_cve("CVE-2020-27781")
    create_cve("CVE-2019-17052")

    response = client.get("/cve")
    soup = make_soup(response.data)
    cves = get_cve_names(soup)
    assert len(cves) == 3
    assert sorted(cves) == ["CVE-2019-17052", "CVE-2020-26116", "CVE-2020-27781"]

    response = client.get("/cve?page=1")
    soup = make_soup(response.data)
    cves = get_cve_names(soup)
    assert len(cves) == 3
    assert sorted(cves) == ["CVE-2019-17052", "CVE-2020-26116", "CVE-2020-27781"]

    response = client.get("/cve?page=2")
    soup = make_soup(response.data)
    cves = get_cve_names(soup)
    assert len(cves) == 2
    assert sorted(cves) == ["CVE-2018-18074", "CVE-2020-9392"]

    response = client.get("/cve?page=3")
    assert response.status_code == 404

    app.config["CVES_PER_PAGE"] = old


@pytest.mark.parametrize(
    "url,result",
    [
        ("/cve?search=nonexistingkeyword", []),
        ("/cve?search=CRLF", ["CVE-2020-26116"]),
        ("/cve?search=http", ["CVE-2018-18074", "CVE-2020-26116"]),
    ],
)
def test_search_cves(client, create_cve, make_soup, get_cve_names, url, result):
    create_cve("CVE-2018-18074")  # ... http ...
    create_cve("CVE-2020-9392")  # ...
    create_cve("CVE-2020-26116")  # ... http ... CRLF ...

    response = client.get(url)
    soup = make_soup(response.data)
    cves = get_cve_names(soup)
    assert sorted(cves) == result


@pytest.mark.parametrize(
    "url,result",
    [
        (
            "/cve?cwe=",
            ["CVE-2018-18074", "CVE-2020-26116", "CVE-2020-27781", "CVE-2020-9392"],
        ),
        ("/cve?cwe=CWE-276", ["CVE-2020-9392"]),
        ("/cve?cwe=CWE-522", ["CVE-2018-18074", "CVE-2020-27781"]),
        ("/cve?cwe=CWE-1234", []),
    ],
)
def test_filtered_by_cwe(client, create_cve, make_soup, get_cve_names, url, result):
    create_cve("CVE-2018-18074")  # CWE-522
    create_cve("CVE-2020-9392")  # CWE-276
    create_cve("CVE-2020-26116")  # CWE-116
    create_cve("CVE-2020-27781")  # CWE-522

    response = client.get(url)
    soup = make_soup(response.data)
    cves = get_cve_names(soup)
    assert sorted(cves) == result


@pytest.mark.parametrize(
    "url,result",
    [
        (
            "/cve",
            [
                "CVE-2018-18074",
                "CVE-2019-17052",
                "CVE-2020-26116",
                "CVE-2020-29660",
                "CVE-2020-35076",
                "CVE-2020-9392",
            ],
        ),
        ("/cve?cvss=none", ["CVE-2020-35076"]),
        ("/cve?cvss=low", ["CVE-2019-17052"]),
        ("/cve?cvss=medium", ["CVE-2020-29660"]),
        ("/cve?cvss=high", ["CVE-2020-26116", "CVE-2020-9392"]),
        ("/cve?cvss=critical", ["CVE-2018-18074"]),
    ],
)
def test_filtered_by_cvss(client, create_cve, make_soup, get_cve_names, url, result):
    create_cve("CVE-2018-18074")  # 9.8 - CRITICAL
    create_cve("CVE-2020-9392")  # 7.3 - HIGH
    create_cve("CVE-2020-26116")  # 7.2 - HIGH
    create_cve("CVE-2020-29660")  # 4.4 - MEDIUM
    create_cve("CVE-2019-17052")  # 3.3 - LOW
    create_cve("CVE-2020-35076")  # NONE

    response = client.get(url)
    soup = make_soup(response.data)
    cves = get_cve_names(soup)
    assert sorted(cves) == result


@pytest.mark.parametrize(
    "url,result",
    [
        (
            "/cve?vendor=&product=",
            ["CVE-2019-17052", "CVE-2019-8075", "CVE-2020-27781"],
        ),
        ("/cve?vendor=foo&product=bar", []),
        ("/cve?vendor=redhat&product=ceph_storage", ["CVE-2020-27781"]),
        ("/cve?vendor=linux&product=linux_kernel", ["CVE-2019-17052", "CVE-2019-8075"]),
        ("/cve?vendor=", ["CVE-2019-17052", "CVE-2019-8075", "CVE-2020-27781"]),
        ("/cve?vendor=foo", []),
        ("/cve?vendor=redhat", ["CVE-2020-27781"]),
        ("/cve?vendor=linux", ["CVE-2019-17052", "CVE-2019-8075"]),
    ],
)
def test_filtered_by_vendors_products(
    client, create_cve, make_soup, get_cve_names, url, result
):
    create_cve("CVE-2019-8075")  # linux:linux_kernel
    create_cve("CVE-2019-17052")  # linux:linux_kernel
    create_cve("CVE-2020-27781")  # redhat:ceph_storage

    response = client.get(url)
    soup = make_soup(response.data)
    cves = get_cve_names(soup)
    assert sorted(cves) == result
