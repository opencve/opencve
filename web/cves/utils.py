from django.db.models import Q
from django.shortcuts import get_object_or_404
from nested_lookup import nested_lookup

from cves.constants import CVSS_VECTORS_MAPPING, PRODUCT_SEPARATOR


def convert_cpes(conf):
    """
    This function takes an object, extracts its CPE uris and transforms them into
    a dictionnary representing the vendors with their associated products.
    """
    uris = nested_lookup("criteria", conf)

    # Create a list of tuple (vendor, product)
    cpes_t = list(set([tuple(uri.split(":")[3:5]) for uri in uris]))

    # Transform it into nested dictionnary
    cpes = {}
    for vendor, product in cpes_t:
        if vendor not in cpes:
            cpes[vendor] = []
        cpes[vendor].append(product)

    return cpes


def list_to_dict_vendors(vendors):
    """
    Transform a flat list of vendors into a dictionary.

    >>> list_to_dict_vendors([
        "fedoraproject",
        "fedoraproject$PRODUCT$fedora",
        "linux",
        "linux$PRODUCT$linux_kernel"
    ])
    >>> {
        "fedoraproject": ["fedora"],
        "linux": ["linux_kernel"]
    }
    """
    data = {}
    _vendors = [v for v in vendors if PRODUCT_SEPARATOR not in v]
    _products = [v for v in vendors if PRODUCT_SEPARATOR in v]
    for vendor_name in _vendors:
        data[vendor_name] = []
    for product in _products:
        vendor_name, product_name = product.split(PRODUCT_SEPARATOR)
        data[vendor_name].append(product_name)
    return data


def flatten_vendors(vendors):
    """
    Takes a list of nested vendors and products and flat them.
    """
    data = []
    for vendor, products in vendors.items():
        data.append(vendor)
        for product in products:
            data.append(f"{vendor}{PRODUCT_SEPARATOR}{product}")
    return data


def list_weaknesses(cwe_names):
    """
    Takes a list of CWE names and return their objects.
    """
    from cves.models import Weakness

    weaknesses = {}
    for cwe_id in cwe_names:
        weaknesses[cwe_id] = None
        cwe = Weakness.objects.filter(cwe_id=cwe_id).first()
        if cwe:
            weaknesses[cwe_id] = cwe.name
    return weaknesses


def humanize(s):
    return " ".join(map(lambda x: x.capitalize(), s.split("_")))


# TODO: these utils are also in scheduler. Merge the code.


def vendors_conf_to_dict(conf):
    """
    This function takes an object, extracts its CPE uris and transforms them into
    a dictionary representing the vendors with their associated products.
    """
    uris = nested_lookup("criteria", conf)

    # Create a list of tuple (vendor, product)
    cpes_t = list(set([tuple(uri.split(":")[3:5]) for uri in uris]))

    # Transform it into nested dictionnary
    cpes = {}
    for vendor, product in cpes_t:
        if vendor not in cpes:
            cpes[vendor] = []
        cpes[vendor].append(product)

    return cpes


def vendors_dict_to_flat(vendors):
    """
    Takes a list of nested vendors and products and flat them.
    """
    data = []
    for vendor, products in vendors.items():
        data.append(vendor)
        for product in products:
            data.append(f"{vendor}{PRODUCT_SEPARATOR}{product}")
    return data


def vendors_conf_to_flat(conf=None):
    """
    Takes a list of CPEs configuration and returns it in a flat
    array with a vendor/product separator in each item.
    """
    if not conf:
        return []
    return vendors_dict_to_flat(vendors_conf_to_dict(conf))


def weaknesses_to_flat(weaknesses=None):
    if not weaknesses:
        return []
    return nested_lookup("value", weaknesses)


def get_metric_from_vector(vector, metric=None):
    metrics = vector.split("/")
    if metrics[0] in (
        "CVSS:3.1",
        "CVSS:3.0",
    ):
        version = "v3"
        metrics = metrics[1:]
    elif metrics[0] == "CVSS:4.0":
        version = "v4"
        metrics = metrics[1:]
    else:
        version = "v2"

    # Transform ['AV:N', 'AC:H', 'PR:N', 'UI:N', 'S:U', 'C:L', 'I:L', 'A:L']
    # into {'AV':'N', 'AC':'H', 'PR':'N', 'UI':'N', 'S':'U', 'C':'L', 'I':'L', 'A':'L'}
    metrics = dict([item.split(":") for item in metrics])
    data = {
        "version": version,
        "metrics": metrics,
    }

    if metric:
        metric_value = metrics[metric]
        weight = CVSS_VECTORS_MAPPING[version][metric][metric_value]["weight"]
        text = CVSS_VECTORS_MAPPING[version][metric][metric_value]["label"]

        data.update({"weight": weight, "text": text})

    return data


def list_filtered_cves(params, user):
    """
    This function filter the list of CVEs based
    on given filters (search, vendors, cvss, user tag...)
    """
    from cves.models import Cve, Vendor, Product
    from users.models import UserTag

    query = Cve.objects.order_by("-updated_at")

    search = params.get("search")
    if search:
        query = query.filter(
            Q(cve_id__icontains=search)
            | Q(description__icontains=search)
            | Q(vendors__contains=search)
        )

    # Filter by weakness
    weakness = params.get("weakness")
    if weakness:
        query = query.filter(weaknesses__contains=weakness)

    # Filter by CVSS score
    cvss = params.get("cvss", "").lower()
    if cvss in [
        "empty",
        "low",
        "medium",
        "high",
        "critical",
    ]:
        if cvss == "empty":
            query = query.filter(metrics__cvssV3_1__data__score__isnull=True)
        if cvss == "low":
            query = query.filter(
                Q(metrics__cvssV3_1__data__score__gte=0)
                & Q(metrics__cvssV3_1__data__score__lte=3.9)
            )
        if cvss == "medium":
            query = query.filter(
                Q(metrics__cvssV3_1__data__score__gte=4.0)
                & Q(metrics__cvssV3_1__data__score__lte=6.9)
            )
        if cvss == "high":
            query = query.filter(
                Q(metrics__cvssV3_1__data__score__gte=7.0)
                & Q(metrics__cvssV3_1__data__score__lte=8.9)
            )
        if cvss == "critical":
            query = query.filter(
                Q(metrics__cvssV3_1__data__score__gte=9.0)
                & Q(metrics__cvssV3_1__data__score__lte=10.0)
            )

    # Filter by Vendor and Product
    vendor_param = params.get("vendor", "").replace(" ", "").lower()
    product_param = params.get("product", "").replace(" ", "_").lower()

    if vendor_param:
        vendor = get_object_or_404(Vendor, name=vendor_param)
        query = query.filter(vendors__contains=vendor.name)

        if product_param:
            product = get_object_or_404(Product, name=product_param, vendor=vendor)
            query = query.filter(
                vendors__contains=f"{vendor.name}{PRODUCT_SEPARATOR}{product.name}"
            )

    # Filter by tag
    tag = params.get("tag", "")
    if tag and user.is_authenticated:
        tag = get_object_or_404(UserTag, name=tag, user=user)
        query = query.filter(cve_tags__tags__contains=tag.name, cve_tags__user=user)

    return query.all()
