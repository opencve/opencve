def test_list_vendors_authentication(client, create_user):
    create_user("opencve")
    response = client.get("/api/vendors")
    assert response.status_code == 401
    response = client.login("john").get("/api/vendors")
    assert response.status_code == 401
    response = client.login("opencve").get("/api/vendors")
    assert response.status_code == 200


def test_list_vendors(client, create_user, create_vendor):
    create_user("opencve")
    response = client.login("opencve").get("/api/vendors")
    assert response.status_code == 200
    assert response.json == []

    create_vendor("the_vendor", "the_product")
    response = client.login("opencve").get("/api/vendors")
    assert response.status_code == 200
    assert len(response.json) == 1
    assert response.json[0] == {"human_name": "The Vendor", "name": "the_vendor"}


def test_get_vendor_not_found(client, create_user):
    create_user("opencve")
    response = client.login("opencve").get("/api/vendors/404")
    assert response.status_code == 404
    assert response.json == {"message": "Not found."}


def test_get_vendor(client, create_user, create_vendor):
    create_user("opencve")
    create_vendor("vendor1", "product1")
    create_vendor("vendor1", "product2")

    response = client.login("opencve").get("/api/vendors/vendor1")
    assert response.status_code == 200
    assert response.json == {
        "human_name": "Vendor1",
        "name": "vendor1",
        "products": ["product1", "product2"],
    }


def test_list_vendor_cves(client, create_user, create_cve):
    create_user("opencve")
    create_cve("CVE-2018-18074")

    response = client.login("opencve").get("/api/vendors/canonical/cve")
    assert len(response.json) == 1

    assert response.json[0] == {
        "created_at": "2018-10-09T17:29:00Z",
        "id": "CVE-2018-18074",
        "summary": "The Requests package before 2.20.0 for Python sends an HTTP Authorization header to an http URI upon receiving a same-hostname https-to-http redirect, which makes it easier for remote attackers to discover credentials by sniffing the network.",
        "updated_at": "2019-10-03T00:03:00Z",
    }
