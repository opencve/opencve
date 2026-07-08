import pytest
from rest_framework.exceptions import ValidationError

from cves.constants import PRODUCT_SEPARATOR
from cves.models import Product, Vendor
from projects.services.subscriptions import (
    replace_project_subscriptions,
    subscribe_project,
    subscriptions_to_api_format,
    subscriptions_to_api_format_from_project,
    unsubscribe_project,
    validate_and_normalize_subscriptions,
)


@pytest.mark.django_db
def test_validate_and_normalize_subscriptions(create_project, create_organization):
    """Validate vendors and products and return storage format."""
    organization = create_organization(name="acme")
    project = create_project(name="prod", organization=organization)
    vendor = Vendor.objects.create(name="python")
    Product.objects.create(vendor=vendor, name="django")

    storage = validate_and_normalize_subscriptions(
        ["python"],
        {"python": ["django"]},
    )
    assert storage == {
        "vendors": ["python"],
        "products": [f"python{PRODUCT_SEPARATOR}django"],
    }

    with pytest.raises(ValidationError):
        validate_and_normalize_subscriptions(["missing"], {})

    project.refresh_from_db()
    assert project.subscriptions == {"vendors": [], "products": []}


@pytest.mark.django_db
def test_validate_and_normalize_subscriptions_invalid_types():
    """Reject non-list vendors and non-dict products payloads."""
    with pytest.raises(ValidationError) as exc:
        validate_and_normalize_subscriptions("python", {})
    assert "vendors" in exc.value.detail

    with pytest.raises(ValidationError) as exc:
        validate_and_normalize_subscriptions([], "python")
    assert "products" in exc.value.detail


@pytest.mark.django_db
def test_validate_and_normalize_subscriptions_empty_strings(create_organization):
    """Reject empty vendor and product name strings."""
    Vendor.objects.create(name="python")

    with pytest.raises(ValidationError) as exc:
        validate_and_normalize_subscriptions(["  "], {})
    assert "vendors" in exc.value.detail

    with pytest.raises(ValidationError) as exc:
        validate_and_normalize_subscriptions([], {"python": ["  "]})
    assert "products" in exc.value.detail


@pytest.mark.django_db
def test_validate_and_normalize_subscriptions_dedup():
    """Deduplicate repeated vendors and products in the payload."""
    vendor = Vendor.objects.create(name="python")
    Product.objects.create(vendor=vendor, name="django")

    storage = validate_and_normalize_subscriptions(
        ["python", "python"],
        {"python": ["django", "django"]},
    )
    assert storage == {
        "vendors": ["python"],
        "products": [f"python{PRODUCT_SEPARATOR}django"],
    }


@pytest.mark.django_db
def test_replace_project_subscriptions_is_atomic(create_project, create_organization):
    """Keep existing subscriptions when replacement validation fails."""
    organization = create_organization(name="acme")
    project = create_project(
        name="prod",
        organization=organization,
        vendors=["python"],
    )
    Vendor.objects.create(name="python")

    with pytest.raises(ValidationError):
        replace_project_subscriptions(
            project,
            vendors=["python"],
            products_by_vendor={"python": ["missing"]},
        )

    project.refresh_from_db()
    assert project.subscriptions == {"vendors": ["python"], "products": []}


@pytest.mark.django_db
def test_subscriptions_to_api_format():
    """Convert stored subscriptions JSON to API response shape."""
    data = {
        "vendors": ["python"],
        "products": [f"apache{PRODUCT_SEPARATOR}airflow"],
    }
    assert subscriptions_to_api_format(data) == {
        "vendors": ["python"],
        "products": {"apache": ["airflow"]},
    }


@pytest.mark.django_db
def test_subscriptions_to_api_format_from_project(create_project, create_organization):
    """Convert a project's subscriptions to API response shape."""
    organization = create_organization(name="acme")
    project = create_project(
        name="prod",
        organization=organization,
        vendors=["python"],
        products=[f"apache{PRODUCT_SEPARATOR}airflow"],
    )

    assert subscriptions_to_api_format_from_project(project) == {
        "vendors": ["python"],
        "products": {"apache": ["airflow"]},
    }


@pytest.mark.django_db
def test_subscribe_project_vendor_only(create_project, create_organization):
    """Add a vendor-only subscription to a project."""
    organization = create_organization(name="acme")
    project = create_project(name="prod", organization=organization)
    Vendor.objects.create(name="python")

    subscribe_project(project, vendor_name="python")

    project.refresh_from_db()
    assert project.subscriptions == {"vendors": ["python"], "products": []}


@pytest.mark.django_db
def test_subscribe_project_idempotent_re_add(create_project, create_organization):
    """Re-adding an existing subscription does not duplicate entries."""
    organization = create_organization(name="acme")
    project = create_project(name="prod", organization=organization, vendors=["python"])
    Vendor.objects.create(name="python")

    subscribe_project(project, vendor_name="python")

    project.refresh_from_db()
    assert project.subscriptions == {"vendors": ["python"], "products": []}


@pytest.mark.django_db
def test_subscribe_project_rejects_missing_vendor(create_project, create_organization):
    """Reject subscribe when vendor name is missing."""
    organization = create_organization(name="acme")
    project = create_project(name="prod", organization=organization)

    with pytest.raises(ValidationError):
        subscribe_project(project, vendor_name=None)


@pytest.mark.django_db
def test_unsubscribe_project_vendor(create_project, create_organization):
    """Remove a vendor subscription from a project."""
    organization = create_organization(name="acme")
    project = create_project(name="prod", organization=organization, vendors=["python"])

    unsubscribe_project(project, vendor_name="python")

    project.refresh_from_db()
    assert project.subscriptions == {"vendors": [], "products": []}


@pytest.mark.django_db
def test_unsubscribe_project_vendor_and_product(create_project, create_organization):
    """Remove a vendor+product subscription from a project."""
    organization = create_organization(name="acme")
    project = create_project(
        name="prod",
        organization=organization,
        products=[f"apache{PRODUCT_SEPARATOR}airflow"],
    )

    unsubscribe_project(project, vendor_name="apache", product_name="airflow")

    project.refresh_from_db()
    assert project.subscriptions == {"vendors": [], "products": []}


@pytest.mark.django_db
def test_unsubscribe_project_rejects_missing_vendor(
    create_project, create_organization
):
    """Reject unsubscribe when vendor name is missing."""
    organization = create_organization(name="acme")
    project = create_project(name="prod", organization=organization)

    with pytest.raises(ValidationError):
        unsubscribe_project(project, vendor_name=None)
