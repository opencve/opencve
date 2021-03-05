def test_list_no_vendors(client):
    response = client.get("/vendors")
    assert response.status_code == 200
    assert b"No vendor found." in response.data


def test_list_vendors(client, create_vendor):
    create_vendor("the_vendor_1", "product1")
    create_vendor("the_vendor_2", "product1")
    create_vendor("the_vendor_2", "product2")

    response = client.get("/vendors")
    assert response.status_code == 200
    assert b"The Vendor 1" in response.data
    assert b"The Vendor 2" in response.data

    # number of associated products
    assert b">1</a>" in response.data
    assert b">2</a>" in response.data
