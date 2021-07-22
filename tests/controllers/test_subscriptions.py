from opencve.controllers.vendors import VendorController


def test_subscribe_to_vendor_invalid_action(login, client, create_vendor):

    test_vendor = create_vendor("test vendor", "test product")

    with client:
        response = client.post(
            "/subscriptions",
            data={
                "obj": "vendor",
                "id": test_vendor.id,
                "action": "non-existent action",
            },
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
            data={"obj": "vendor", "id": test_vendor.id, "action": "subscribe"},
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
            data={
                "obj": "product",
                "id": test_vendor.products[0].id,
                "action": "subscribe",
            },
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
            data={"obj": "vendor", "id": test_vendor.id, "action": "subscribe"},
            follow_redirects=True,
        )

        # Get the vendor subscribed to
        test_vendor = VendorController.list_items()[0]

        # Unsubscribe to the vendor
        response = client.post(
            "/subscriptions",
            data={"obj": "vendor", "id": test_vendor.id, "action": "unsubscribe"},
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
            data={
                "obj": "product",
                "id": test_vendor.products[0].id,
                "action": "subscribe",
            },
            follow_redirects=True,
        )

        assert response.status_code == 200
        assert b'"message": "product added"' in response.data
        assert b'"status": "ok"' in response.data

        response = client.post(
            "/subscriptions",
            data={
                "obj": "product",
                "id": test_vendor.products[0].id,
                "action": "unsubscribe",
            },
            follow_redirects=True,
        )

        assert response.status_code == 200
        assert b'"message": "product removed"' in response.data
        assert b'"status": "ok"' in response.data


def test_subscribe_to_invalid_vendor_id_with_invalid_uuid(login, client):

    with client:
        response = client.post(
            "/subscriptions",
            data={
                "obj": "vendor",
                "id": "invalid_id",
                "action": "subscribe",
            },
            follow_redirects=True,
        )

        assert response.status_code == 400
        assert response.json["message"] == "vendor invalid_id does not exist"
        assert response.json["status"] == "error"


def test_subscribe_to_invalid_product_id_with_invalid_uuid(login, client):

    with client:
        response = client.post(
            "/subscriptions",
            data={
                "obj": "product",
                "id": "invalid_id",
                "action": "subscribe",
            },
            follow_redirects=True,
        )

        assert response.status_code == 400
        assert response.json["message"] == "product invalid_id does not exist"
        assert response.json["status"] == "error"


def test_subscribe_to_invalid_vendor_id_with_valid_uuid(login, client):

    with client:
        response = client.post(
            "/subscriptions",
            data={
                "obj": "vendor",
                "id": "38e0697e-b406-4724-80af-e39e354b291c",
                "action": "subscribe",
            },
            follow_redirects=True,
        )

        assert response.status_code == 400
        assert (
            response.json["message"]
            == "vendor 38e0697e-b406-4724-80af-e39e354b291c does not exist"
        )
        assert response.json["status"] == "error"


def test_subscribe_to_invalid_product_id_with_valid_uuid(login, client):

    with client:
        response = client.post(
            "/subscriptions",
            data={
                "obj": "product",
                "id": "38e0697e-b406-4724-80af-e39e354b291c",
                "action": "subscribe",
            },
            follow_redirects=True,
        )

        assert response.status_code == 400
        assert (
            response.json["message"]
            == "product 38e0697e-b406-4724-80af-e39e354b291c does not exist"
        )
        assert response.json["status"] == "error"
