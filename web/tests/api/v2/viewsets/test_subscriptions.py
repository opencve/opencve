import json

import pytest
from django.test import override_settings

from cves.constants import PRODUCT_SEPARATOR
from cves.models import Product, Vendor
from organizations.models import OrganizationAPIToken
from tests.api.v2.conftest import (
    assert_v2_error,
    bearer,
    subscriptions_url,
    write_token,
    read_token,
)


@pytest.mark.django_db
def test_get_subscriptions(client, api_context, write_token, create_project):
    """GET returns the project's current subscriptions."""
    _user, organization, _create_token = api_context
    create_project(
        name="prod",
        organization=organization,
        vendors=["python"],
    )

    response = client.get(subscriptions_url(), **bearer(write_token))

    assert response.status_code == 200
    assert response.json() == {"vendors": ["python"], "products": {}}


@pytest.mark.django_db
def test_post_subscription_returns_200_and_full_list(
    client, api_context, write_token, create_project
):
    """POST add returns 200 and the full subscription list."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)
    vendor = Vendor.objects.create(name="apache")
    Product.objects.create(vendor=vendor, name="airflow")
    token_string = write_token

    response = client.post(
        subscriptions_url(),
        data=json.dumps({"vendor": "apache", "product": "airflow"}),
        content_type="application/json",
        **bearer(token_string),
    )

    assert response.status_code == 200
    assert response.json() == {
        "vendors": [],
        "products": {"apache": ["airflow"]},
    }
    project.refresh_from_db()
    assert project.subscriptions["products"] == [f"apache{PRODUCT_SEPARATOR}airflow"]


@pytest.mark.django_db
def test_post_invalid_vendor(client, api_context, write_token, create_project):
    """POST rejects an unknown vendor and leaves subscriptions unchanged."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)

    response = client.post(
        subscriptions_url(),
        data=json.dumps({"vendor": "missing"}),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 400
    project.refresh_from_db()
    assert project.subscriptions == {"vendors": [], "products": []}


@pytest.mark.django_db
def test_put_replaces_all_subscriptions(
    client, api_context, write_token, create_project
):
    """PUT replaces all subscriptions atomically."""
    _user, organization, _create_token = api_context
    project = create_project(
        name="prod",
        organization=organization,
        vendors=["linux"],
    )
    python_vendor = Vendor.objects.create(name="python")
    apache_vendor = Vendor.objects.create(name="apache")
    Product.objects.create(vendor=python_vendor, name="django")
    Product.objects.create(vendor=apache_vendor, name="airflow")

    response = client.put(
        subscriptions_url(),
        data=json.dumps(
            {
                "vendors": ["python"],
                "products": {"apache": ["airflow"]},
            }
        ),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 200
    assert response.json() == {
        "vendors": ["python"],
        "products": {"apache": ["airflow"]},
    }
    project.refresh_from_db()
    assert project.subscriptions == {
        "vendors": ["python"],
        "products": [f"apache{PRODUCT_SEPARATOR}airflow"],
    }


@pytest.mark.django_db
def test_put_invalid_is_atomic(client, api_context, write_token, create_project):
    """PUT rejects invalid payloads without modifying stored subscriptions."""
    _user, organization, _create_token = api_context
    project = create_project(
        name="prod",
        organization=organization,
        vendors=["python"],
    )
    Vendor.objects.create(name="python")

    response = client.put(
        subscriptions_url(),
        data=json.dumps(
            {
                "vendors": ["python"],
                "products": {"python": ["missing"]},
            }
        ),
        content_type="application/json",
        **bearer(write_token),
    )

    assert response.status_code == 400
    project.refresh_from_db()
    assert project.subscriptions == {"vendors": ["python"], "products": []}


@pytest.mark.django_db
def test_delete_vendor(client, api_context, write_token, create_project):
    """DELETE removes a vendor subscription."""
    _user, organization, _create_token = api_context
    create_project(
        name="prod",
        organization=organization,
        vendors=["python"],
    )

    response = client.delete(
        f"{subscriptions_url()}?vendor=python",
        **bearer(write_token),
    )

    assert response.status_code == 200
    assert response.json() == {"vendors": [], "products": {}}


@pytest.mark.django_db
def test_delete_product(client, api_context, write_token, create_project):
    """DELETE removes a vendor and product subscription."""
    _user, organization, _create_token = api_context
    create_project(
        name="prod",
        organization=organization,
        products=[f"apache{PRODUCT_SEPARATOR}airflow"],
    )

    response = client.delete(
        f"{subscriptions_url()}?vendor=apache&product=airflow",
        **bearer(write_token),
    )

    assert response.status_code == 200
    assert response.json() == {"vendors": [], "products": {}}


@pytest.mark.django_db
def test_delete_without_vendor_returns_400(
    client, api_context, write_token, create_project
):
    """DELETE without a vendor query parameter returns 400."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)

    response = client.delete(subscriptions_url(), **bearer(write_token))

    assert_v2_error(
        response,
        "validation_error",
        details={"vendor": "This field is required."},
    )


@pytest.mark.django_db
@override_settings(API_SCOPES_ENABLED=True)
def test_read_only_token_on_post_returns_403(
    client, api_context, read_token, create_project
):
    """POST rejects read-only tokens with 403."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)

    response = client.post(
        subscriptions_url(),
        data=json.dumps({"vendor": "python"}),
        content_type="application/json",
        **bearer(read_token),
    )

    assert_v2_error(response, "read_only_token", status_code=403)


@pytest.mark.django_db
@override_settings(API_SCOPES_ENABLED=True)
def test_missing_subscriptions_write_scope_returns_403(
    client, api_context, create_org_token, create_project
):
    """POST rejects tokens missing the subscriptions:write scope."""
    _user, organization, _create_token = api_context
    create_project(name="prod", organization=organization)
    token_string = create_org_token(
        access_mode=OrganizationAPIToken.AccessMode.WRITE,
        scopes=["projects:write"],
    )

    response = client.post(
        subscriptions_url(),
        data=json.dumps({"vendor": "python"}),
        content_type="application/json",
        **bearer(token_string),
    )

    assert_v2_error(
        response,
        "missing_scope",
        status_code=403,
        required_scope="subscriptions:write",
    )


@pytest.mark.django_db
def test_post_idempotent_re_add(client, api_context, write_token, create_project):
    """POST re-adding the same subscription is idempotent."""
    _user, organization, _create_token = api_context
    project = create_project(name="prod", organization=organization)
    vendor = Vendor.objects.create(name="apache")
    Product.objects.create(vendor=vendor, name="airflow")
    payload = json.dumps({"vendor": "apache", "product": "airflow"})

    first = client.post(
        subscriptions_url(),
        data=payload,
        content_type="application/json",
        **bearer(write_token),
    )
    second = client.post(
        subscriptions_url(),
        data=payload,
        content_type="application/json",
        **bearer(write_token),
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json() == {
        "vendors": [],
        "products": {"apache": ["airflow"]},
    }
    project.refresh_from_db()
    assert project.subscriptions["products"] == [f"apache{PRODUCT_SEPARATOR}airflow"]
