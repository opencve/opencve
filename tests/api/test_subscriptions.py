from opencve.extensions import db
from opencve.models.products import Product
from opencve.models.vendors import Vendor


def test_list_subscriptions_authentication(client, create_user):
    create_user("opencve")
    response = client.get("/api/account/subscriptions/vendors")
    assert response.status_code == 401
    response = client.get("/api/account/subscriptions/products")
    assert response.status_code == 401

    response = client.login("john").get("/api/account/subscriptions/vendors")
    assert response.status_code == 401
    response = client.login("john").get("/api/account/subscriptions/products")
    assert response.status_code == 401

    response = client.login("opencve").get("/api/account/subscriptions/vendors")
    assert response.status_code == 200
    response = client.login("opencve").get("/api/account/subscriptions/products")
    assert response.status_code == 200


def test_list_vendors_subscriptions(client, create_user, handle_events):
    user = create_user("opencve")
    response = client.login("opencve").get("/api/account/subscriptions/vendors")
    assert response.status_code == 200
    assert response.json == []

    handle_events("modified_cves/CVE-2018-18074.json")
    vendor = Vendor.query.filter_by(name="canonical").first()
    user.vendors.append(vendor)
    db.session.commit()

    response = client.login("opencve").get("/api/account/subscriptions/vendors")
    assert response.status_code == 200
    assert response.json == [
        {"human_name": "Canonical", "name": "canonical", "vendor_id": str(vendor.id)}
    ]


def test_list_products_subscriptions(client, create_user, handle_events):
    user = create_user("opencve")
    response = client.login("opencve").get("/api/account/subscriptions/products")
    assert response.status_code == 200
    assert response.json == []

    handle_events("modified_cves/CVE-2018-18074.json")
    user.products.append(Product.query.filter_by(name="requests").first())
    db.session.commit()

    response = client.login("opencve").get("/api/account/subscriptions/products")
    assert response.status_code == 200
    assert response.json == [
        {
            "name": "requests",
            "human_name": "Requests",
            "parent_vendor": "python-requests",
        }
    ]


def test_add_vendor_subscription(client, create_user, create_vendor):
    create_vendor("vendor1")
    vendor_id = str(Vendor.query.filter_by(name="vendor1").first().id)
    create_user("opencve")

    response = client.login("opencve").post(
        "/api/account/subscriptions/vendor/add", data={"id": "fail"}
    )
    assert response.json == {"status": "fail"}
    assert response.status_code == 400

    response = client.login("opencve").post(
        "/api/account/subscriptions/vendor/add", data={"id": f"{vendor_id[:-1]}a"}
    )
    assert response.json == {"status": "fail"}
    assert response.status_code == 400

    response = client.login("opencve").post(
        "/api/account/subscriptions/vendor/add", data={"id": vendor_id}
    )
    assert response.json == {"status": "ok"}
    assert response.status_code == 200

    response = client.login("opencve").get("/api/account/subscriptions/vendors")
    assert response.status_code == 200
    assert response.json == [
        {"human_name": "Vendor1", "name": "vendor1", "vendor_id": vendor_id}
    ]
