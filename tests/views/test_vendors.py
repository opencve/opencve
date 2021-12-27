def test_list_no_vendors(client):
    response = client.get("/vendors")
    assert response.status_code == 200
    assert b"Vendors (0)" in response.data
    assert b"Products (0)" in response.data


def test_list_vendors(client, create_vendor):
    create_vendor("vendor1", "product1")
    create_vendor("vendor2", "product1")
    create_vendor("vendor2", "product2")

    response = client.get("/vendors")
    assert response.status_code == 200
    assert b"Vendor1" in response.data
    assert b"Vendor2" in response.data
    assert b"Product1" in response.data
    assert b"Product2" in response.data
    assert b"Vendors (2)" in response.data
    assert b"Products (3)" in response.data


def test_vendor_search(client, create_vendor):
    create_vendor("the_vendor_1", "product1")
    create_vendor("the_vendor_2", "the_product_1")
    create_vendor("the_vendor_2", "product2")

    response = client.get("/vendors")
    assert b"Search in vendors and products" in response.data

    response = client.get("/vendors?search=Vendor 1")
    assert response.status_code == 200
    assert b"Vendors (1)" in response.data
    assert b"Products (0)" in response.data

    response = client.get("/vendors?search=the")
    assert b"Vendors (2)" in response.data
    assert b"Products (1)" in response.data
    assert b"The Vendor 1" in response.data
    assert b"The Vendor 2" in response.data
    assert b"The Product 1" in response.data

    response = client.get("/vendors?search=foobar")
    assert b"Vendors (0)" in response.data
    assert b"Products (0)" in response.data


def test_vendor_not_found(client, create_vendor):
    create_vendor("vendor1", "product1")
    response = client.get("/vendors?vendor=vendor1")
    assert response.status_code == 200
    response = client.get("/vendors?vendor=foobar")
    assert response.status_code == 404


def test_list_products(client, create_vendor):
    create_vendor("vendor1", "product1")
    create_vendor("vendor2", "product2")
    create_vendor("vendor2", "product3")

    response = client.get("/vendors?vendor=vendor2")
    assert b"Vendor <strong>Vendor2</strong> selected" in response.data
    assert b"Products (2)" in response.data
    assert b"Product2" in response.data
    assert b"Product3" in response.data


def test_search_products(client, create_vendor):
    create_vendor("vendor1", "product1")
    create_vendor("vendor2", "product1")
    create_vendor("vendor2", "product2")

    response = client.get("/vendors?vendor=vendor2")
    assert b"Vendor <strong>Vendor2</strong> selected" in response.data
    assert b"Search in <strong>Vendor2</strong> vendor" in response.data

    response = client.get("/vendors?vendor=vendor2&search=1")
    assert b"Products (1)" in response.data
    assert b"Product1" in response.data
    assert b"Product2" not in response.data


def test_vendors_products_paginated(app, client, create_vendor):
    old_vendors_setting = app.config["VENDORS_PER_PAGE"]
    old_products_setting = app.config["PRODUCTS_PER_PAGE"]
    app.config["VENDORS_PER_PAGE"] = 2
    app.config["PRODUCTS_PER_PAGE"] = 2

    for i in range(5):
        create_vendor(f"vendor{i}", f"product{i}")

    response = client.get("/vendors")
    assert b"Vendors (5)" in response.data
    assert b"Vendor0" in response.data
    assert b"Vendor1" in response.data
    assert b"Vendor2" not in response.data
    assert b"Products (5)" in response.data
    assert b"Product0" in response.data
    assert b"Product1" in response.data
    assert b"Product2" not in response.data

    response = client.get("/vendors?page=2")
    assert b"Vendors (5)" in response.data
    assert b"Vendor2" in response.data
    assert b"Vendor3" in response.data
    assert b"Vendor4" not in response.data
    assert b"Products (5)" in response.data
    assert b"Product0" in response.data
    assert b"Product1" in response.data
    assert b"Product2" not in response.data

    response = client.get("/vendors?page=2&product_page=2")
    assert b"Vendors (5)" in response.data
    assert b"Vendor2" in response.data
    assert b"Vendor3" in response.data
    assert b"Vendor4" not in response.data
    assert b"Products (5)" in response.data
    assert b"Product2" in response.data
    assert b"Product3" in response.data
    assert b"Product4" not in response.data

    response = client.get("/vendors?page=100&product_page=2")
    assert response.status_code == 404

    response = client.get("/vendors?product_page=100")
    assert response.status_code == 404

    app.config["VENDORS_PER_PAGE"] = old_vendors_setting
    app.config["PRODUCTS_PER_PAGE"] = old_products_setting
