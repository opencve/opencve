def test_list_cwes_authentication(client, create_user):
    create_user("opencve")
    response = client.get("/api/cwe")
    assert response.status_code == 401
    response = client.login("john").get("/api/cwe")
    assert response.status_code == 401
    response = client.login("opencve").get("/api/cwe")
    assert response.status_code == 200


def test_list_cwes(client, create_user, create_cwe):
    create_user("opencve")
    response = client.login("opencve").get("/api/cwe")
    assert response.status_code == 200
    assert response.json == []

    create_cwe("CWE-123", "The name", "The description")
    response = client.login("opencve").get("/api/cwe")
    assert response.status_code == 200
    assert len(response.json) == 1
    assert response.json[0] == {
        "id": "CWE-123",
        "name": "The name",
        "description": "The description",
    }


def test_get_cwe_not_found(client, create_user):
    create_user("opencve")
    response = client.login("opencve").get("/api/cwe/404")
    assert response.status_code == 404
    assert response.json == {"message": "Not found."}


def test_get_cwe(client, create_user, create_cwe):
    create_user("opencve")
    create_cwe("CWE-123", "The name", "The description")

    response = client.login("opencve").get("/api/cwe/CWE-123")
    assert response.status_code == 200
    assert response.json == {
        "id": "CWE-123",
        "name": "The name",
        "description": "The description",
    }


def test_list_cwe_cves(client, create_user, create_cve):
    create_user("opencve")
    create_cve("CVE-2018-18074")

    response = client.login("opencve").get("/api/cwe/CWE-522/cve")
    assert len(response.json) == 1

    assert response.json[0] == {
        "created_at": "2018-10-09T17:29:00Z",
        "id": "CVE-2018-18074",
        "summary": "The Requests package before 2.20.0 for Python sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect, which makes it easier for remote attackers to discover credentials by sniffing the network.",
        "updated_at": "2019-10-03T00:03:00Z",
    }
