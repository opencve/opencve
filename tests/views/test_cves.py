from opencve.models import get_uuid
from opencve.models.changes import Change


def test_list_no_cves(client):
    response = client.get("/cve")
    assert response.status_code == 200
    assert b"No CVE found." in response.data


def test_list_cves(client, create_cves):
    cves = ["CVE-2018-18074", "CVE-2020-9392", "CVE-2020-26116"]
    vendors = ["canonical", "python-requests", "supsystic", "fedoraproject", "python"]
    products = [
        "ubuntu_linux",
        "requests",
        "pricing_table_by_supsystic",
        "fedora",
        "python",
    ]
    create_cves(cves)

    response = client.get("/cve")
    assert response.status_code == 200

    for word in cves + vendors + products:
        assert word in response.data.decode("utf-8")


def test_get_cve_not_found(client):
    response = client.get("/cve/404")
    assert response.status_code == 404
    assert b"Page not found" in response.data


def test_get_cve(client, create_cve, create_cwe):
    create_cwe(
        "CWE-522",
        "Insufficiently Protected Credentials",
        "The product transmits or stores authentication credentials, but it uses an insecure method that is susceptible to unauthorized interception and/or retrieval.",
    )
    create_cve("CVE-2018-18074")
    response = client.get("/cve/CVE-2018-18074")

    assert b"CVE-2018-18074" in response.data
    assert b"The Requests package before 2.20.0 for Python" in response.data
    assert b"5.0" in response.data
    assert b"9.8" in response.data
    assert b"http://docs.python-requests.org" in response.data
    assert b"cpe:2.3:a:python-requests:requests:*:*:*:*:*:*:*:*" in response.data
    assert b"CWE-522" in response.data
    assert b"Insufficiently Protected Credentials" in response.data
    assert b"<strong>canonical</strong>" in response.data
    assert b"<li>ubuntu_linux</li>" in response.data
    assert b"<strong>python-requests</strong>" in response.data
    assert b"<li>requests</li>" in response.data
    assert b"No history." in response.data


def test_get_change_not_found(client, create_cve, handle_events):
    response = client.get(f"/cve/CVE-2000-1234/changes/{get_uuid()}")
    assert response.status_code == 404

    create_cve("CVE-2018-18074")
    response = client.get(f"/cve/CVE-2018-18074/changes/{get_uuid()}")
    assert response.status_code == 404

    handle_events("modified_cves/CVE-2018-18074_summary.json")
    change = Change.query.first()
    response = client.get(f"/cve/CVE-2018-18074/changes/{change.id}")
    assert response.status_code == 200


def test_get_change(client, create_cve, handle_events, make_soup):
    create_cve("CVE-2018-18074")
    handle_events("modified_cves/CVE-2018-18074_summary.json")
    change = Change.query.first()

    response = client.get(f"/cve/CVE-2018-18074/changes/{change.id}")
    assert response.status_code == 200
    assert b"CVE-2018-18074" in response.data
    assert b"List of Events" in response.data
    assert b"JSON Diff" in response.data

    soup = make_soup(response.data)
    assert sorted([s.text for s in soup.find("table").find("tr").find_all("td")]) == [
        "Summary",
        "The Requests package before 2.20.0 for Python sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect, which makes it easier for remote attackers to discover credentials by sniffing the network.",
        "The summary has been changed.",
    ]
