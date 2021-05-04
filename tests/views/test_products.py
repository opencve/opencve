def test_get_vendor_not_found(client):
    response = client.get("/vendors/404/products")
    assert response.status_code == 404
    assert b"Page not found" in response.data


def test_get_products(client, create_vendor):
    create_vendor("the_vendor_1", "the_product_1")
    create_vendor("the_vendor_1", "the_product_2")

    response = client.get("/vendors/the_vendor_1/products")
    assert b"The Product 1" in response.data
    assert b"The Product 2" in response.data
