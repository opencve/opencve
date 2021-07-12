from opencve.controllers.vendors import VendorController


def test_subscribe_to_vendor_invalid_action(login, client, create_vendor):

    test_vendor = create_vendor("test vendor", "test product")

    with client:
        response = client.post(
            "/subscriptions",
            data={"obj": "vendor",
                  "id": test_vendor.id,
                  "action": "non-existent action"},
            follow_redirects=True,
        )

        assert response.status_code == 200
        assert b'"message": "bad request"' in response.data
        assert b'"status": "error"' in response.data


def test_subscribe_to_vendor(login, client, create_vendor):

    test_vendor = create_vendor("test vendor", "test product")

    with client:
        response = client.post(
            "/subscriptions",
            data={"obj": "vendor",
                  "id": test_vendor.id,
                  "action": "subscribe"},
            follow_redirects=True,
        )

        assert response.status_code == 200
        assert b'"message": "vendor added"' in response.data
        assert b'"status": "ok"' in response.data


def test_subscribe_to_product(login, client, create_vendor):

    test_vendor = create_vendor("test vendor", "test product")

    with client:
        response = client.post(
            "/subscriptions",
            data={"obj": "product",
                  "id": test_vendor.products[0].id,
                  "action": "subscribe"},
            follow_redirects=True,
        )

        assert response.status_code == 200
        assert b'"message": "product added"' in response.data
        assert b'"status": "ok"' in response.data


def test_unsubscribe_to_vendor_subscribed_to(login, client, create_vendor):

    test_vendor = create_vendor("test vendor", "test product")

    with client:
        # Subscribe to the vendor
        response = client.post(
            "/subscriptions",
            data={"obj": "vendor",
                  "id": test_vendor.id,
                  "action": "subscribe"},
            follow_redirects=True,
        )

        # Get the vendor subscribed to
        test_vendor = VendorController.list_items()[0]

        # Unsubscribe to the vendor
        response = client.post(
            "/subscriptions",
            data={"obj": "vendor",
                  "id": test_vendor.id,
                  "action": "unsubscribe"},
            follow_redirects=True,
        )

        assert response.status_code == 200
        assert b'"message": "vendor removed"' in response.data
        assert b'"status": "ok"' in response.data


def test_unsubscribe_to_product_subscribed_to(login, client, create_vendor):

    test_vendor = create_vendor("test vendor", "test product")

    with client:
        response = client.post(
            "/subscriptions",
            data={"obj": "product",
                  "id": test_vendor.products[0].id,
                  "action": "subscribe"},
            follow_redirects=True,
        )

        assert response.status_code == 200
        assert b'"message": "product added"' in response.data
        assert b'"status": "ok"' in response.data

        response = client.post(
            "/subscriptions",
            data={"obj": "product",
                  "id": test_vendor.products[0].id,
                  "action": "unsubscribe"},
            follow_redirects=True,
        )

        assert response.status_code == 200
        assert b'"message": "product removed"' in response.data
        assert b'"status": "ok"' in response.data
