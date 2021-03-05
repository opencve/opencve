def test_list_cves_authentication(client, create_user):
    create_user("opencve")
    response = client.get("/api/cve")
    assert response.status_code == 401
    response = client.login("john").get("/api/cve")
    assert response.status_code == 401
    response = client.login("opencve").get("/api/cve")
    assert response.status_code == 200


def test_list_cves(client, create_user, create_cve):
    create_user("opencve")
    response = client.login("opencve").get("/api/cve")
    assert response.status_code == 200
    assert response.json == []

    create_cve("CVE-2018-18074")
    response = client.login("opencve").get("/api/cve")
    assert response.status_code == 200
    assert len(response.json) == 1
    assert response.json[0] == {
        "created_at": "2018-10-09T17:29:00Z",
        "id": "CVE-2018-18074",
        "summary": "The Requests package before 2.20.0 for Python sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect, which makes it easier for remote attackers to discover credentials by sniffing the network.",
        "updated_at": "2019-10-03T00:03:00Z",
    }


def test_get_cve_not_found(client, create_user):
    create_user("opencve")
    response = client.login("opencve").get("/api/cve/404")
    assert response.status_code == 404
    assert response.json == {"message": "Not found."}


def test_get_cve(client, create_user, create_cve, open_file):
    create_user("opencve")
    create_cve("CVE-2018-18074")

    response = client.login("opencve").get("/api/cve/CVE-2018-18074")
    assert response.status_code == 200

    raw_nvd_data = response.json.pop("raw_nvd_data")
    assert response.json == {
        "created_at": "2018-10-09T17:29:00Z",
        "id": "CVE-2018-18074",
        "summary": "The Requests package before 2.20.0 for Python sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect, which makes it easier for remote attackers to discover credentials by sniffing the network.",
        "updated_at": "2019-10-03T00:03:00Z",
        "cvss": {"v2": 5.0, "v3": 9.8},
        "cwes": ["CWE-522"],
        "vendors": {"canonical": ["ubuntu_linux"], "python-requests": ["requests"]},
    }

    data = open_file("cves/CVE-2018-18074.json")
    assert data == raw_nvd_data
