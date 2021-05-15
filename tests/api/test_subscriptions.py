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
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    db.session.commit()

    response = client.login("opencve").get("/api/account/subscriptions/vendors")
    assert response.status_code == 200
    assert response.json == [{"human_name": "Canonical", "name": "canonical"}]


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
