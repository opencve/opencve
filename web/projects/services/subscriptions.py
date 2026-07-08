from django.db import transaction
from rest_framework.exceptions import ValidationError

from cves.constants import PRODUCT_SEPARATOR
from cves.models import Product, Vendor


def subscriptions_to_api_format(subscriptions_data):
    """Convert stored subscriptions JSON to the API response shape."""
    result = {
        "vendors": list(subscriptions_data.get("vendors", [])),
        "products": {},
    }
    for product in subscriptions_data.get("products", []):
        vendor_name, product_name = product.split(PRODUCT_SEPARATOR, 1)
        result["products"].setdefault(vendor_name, []).append(product_name)
    return result


def subscriptions_to_api_format_from_project(project):
    """Convert project subscriptions to the API response shape"""
    return subscriptions_to_api_format(project.subscriptions)


def validate_and_normalize_subscriptions(vendors, products_by_vendor):
    """
    Validate an API subscriptions payload and return the storage format.
    Raises ValidationError if any vendor or product is invalid.
    """
    if vendors is None:
        vendors = []
    if products_by_vendor is None:
        products_by_vendor = {}

    if not isinstance(vendors, list):
        raise ValidationError({"vendors": "Expected a list of vendor names."})
    if not isinstance(products_by_vendor, dict):
        raise ValidationError(
            {"products": "Expected an object mapping vendors to products."}
        )

    storage = {"vendors": [], "products": []}
    seen_vendors = set()

    # Check if the vendors are valid
    for vendor_name in vendors:
        if not isinstance(vendor_name, str) or not vendor_name.strip():
            raise ValidationError(
                {"vendors": "Vendor names must be non-empty strings."}
            )
        vendor_name = vendor_name.strip()
        if vendor_name in seen_vendors:
            continue
        if not Vendor.objects.filter(name=vendor_name).exists():
            raise ValidationError(
                {"vendors": [f"Vendor does not exist: {vendor_name!r}."]}
            )
        seen_vendors.add(vendor_name)
        storage["vendors"].append(vendor_name)

    # Check if the products are valid
    for vendor_name, product_names in products_by_vendor.items():
        if not isinstance(vendor_name, str) or not vendor_name.strip():
            raise ValidationError(
                {"products": "Vendor keys must be non-empty strings."}
            )
        vendor_name = vendor_name.strip()
        if not Vendor.objects.filter(name=vendor_name).exists():
            raise ValidationError(
                {"products": [f"Vendor does not exist: {vendor_name!r}."]}
            )
        if not isinstance(product_names, list):
            raise ValidationError(
                {
                    "products": (
                        f"Expected a list of products for vendor {vendor_name!r}."
                    )
                }
            )

        seen_products = set()
        for product_name in product_names:
            if not isinstance(product_name, str) or not product_name.strip():
                raise ValidationError(
                    {"products": "Product names must be non-empty strings."}
                )
            product_name = product_name.strip()
            key = f"{vendor_name}{PRODUCT_SEPARATOR}{product_name}"
            if key in seen_products:
                continue
            if not Product.objects.filter(
                vendor__name=vendor_name, name=product_name
            ).exists():
                raise ValidationError(
                    {
                        "products": [
                            f"Product does not exist: {vendor_name} / {product_name!r}."
                        ]
                    }
                )
            seen_products.add(key)
            storage["products"].append(key)

    return storage


def replace_project_subscriptions(project, vendors, products_by_vendor):
    """Replace all project subscriptions atomically after validation."""
    with transaction.atomic():
        project.subscriptions = validate_and_normalize_subscriptions(
            vendors, products_by_vendor
        )
        project.save(update_fields=["subscriptions", "updated_at"])
    return project


def subscribe_project(project, vendor_name=None, product_name=None):
    """Add a vendor or vendor+product subscription to a project."""
    if not vendor_name:
        raise ValidationError({"vendor": "This field is required."})

    vendor_name = vendor_name.strip()
    if product_name:
        product_name = product_name.strip()

    subscriptions = {
        "vendors": list(project.subscriptions.get("vendors", [])),
        "products": list(project.subscriptions.get("products", [])),
    }

    if product_name:
        validate_and_normalize_subscriptions([], {vendor_name: [product_name]})
        key = f"{vendor_name}{PRODUCT_SEPARATOR}{product_name}"
        if key not in subscriptions["products"]:
            subscriptions["products"].append(key)
    else:
        validate_and_normalize_subscriptions([vendor_name], {})
        if vendor_name not in subscriptions["vendors"]:
            subscriptions["vendors"].append(vendor_name)

    project.subscriptions = subscriptions
    project.save(update_fields=["subscriptions", "updated_at"])
    return project


def unsubscribe_project(project, vendor_name=None, product_name=None):
    """Remove a vendor or vendor+product subscription from a project."""
    if not vendor_name:
        raise ValidationError({"vendor": "This field is required."})

    vendor_name = vendor_name.strip()
    if product_name:
        product_name = product_name.strip()

    subscriptions = {
        "vendors": list(project.subscriptions.get("vendors", [])),
        "products": list(project.subscriptions.get("products", [])),
    }

    if product_name:
        key = f"{vendor_name}{PRODUCT_SEPARATOR}{product_name}"
        subscriptions["products"] = [p for p in subscriptions["products"] if p != key]
    else:
        subscriptions["vendors"] = [
            v for v in subscriptions["vendors"] if v != vendor_name
        ]

    project.subscriptions = subscriptions
    project.save(update_fields=["subscriptions", "updated_at"])
    return project
