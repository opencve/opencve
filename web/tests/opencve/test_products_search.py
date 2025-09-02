import pytest
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from cves.models import Vendor, Product

@pytest.mark.django_db
def test_vendor_products_search_by_name():
    User = get_user_model()
    user = User.objects.create_user(username="testuser", password="s3cret!")
    client = APIClient()
    client.force_authenticate(user=user)

    v = Vendor.objects.create(name="wordpress")
    p1 = Product.objects.create(name="adserve", vendor=v)
    p2 = Product.objects.create(name="graphql", vendor=v)

    resp = client.get(f"/api/vendors/{v.name}/products", {"search": "serve"})
    assert resp.status_code == 200

    data = resp.json()
    results = data.get("results", data)
    names = [it["name"] for it in results]
    assert p1.name in names
    assert p2.name not in names
