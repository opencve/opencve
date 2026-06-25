from cves.constants import PRODUCT_SEPARATOR
from cves.models import Product, Vendor
from django.shortcuts import get_object_or_404


def subscribe_project(project, vendor_name=None, product_name=None):
    """Add a vendor or vendor+product subscription to a project."""
    subscriptions = {
        "vendors": list(project.subscriptions.get("vendors", [])),
        "products": list(project.subscriptions.get("products", [])),
    }

    if product_name:
        vendor = get_object_or_404(Vendor, name=vendor_name)
        product = get_object_or_404(Product, vendor=vendor, name=product_name)
        key = product.vendored_name
        if key not in subscriptions["products"]:
            subscriptions["products"].append(key)
    elif vendor_name:
        vendor = get_object_or_404(Vendor, name=vendor_name)
        if vendor.name not in subscriptions["vendors"]:
            subscriptions["vendors"].append(vendor.name)
    else:
        raise ValueError("vendor is required")

    project.subscriptions = subscriptions
    project.save(update_fields=["subscriptions", "updated_at"])
    return project


def unsubscribe_project(project, vendor_name=None, product_name=None):
    """Remove a vendor or vendor+product subscription from a project."""
    subscriptions = {
        "vendors": list(project.subscriptions.get("vendors", [])),
        "products": list(project.subscriptions.get("products", [])),
    }

    if product_name:
        key = f"{vendor_name}{PRODUCT_SEPARATOR}{product_name}"
        subscriptions["products"] = [p for p in subscriptions["products"] if p != key]
    elif vendor_name:
        subscriptions["vendors"] = [
            v for v in subscriptions["vendors"] if v != vendor_name
        ]
    else:
        raise ValueError("vendor is required")

    project.subscriptions = subscriptions
    project.save(update_fields=["subscriptions", "updated_at"])
    return project
