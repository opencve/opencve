from nested_lookup import nested_lookup

from cves.constants import PRODUCT_SEPARATOR, CVSS_VECTORS_MAPPING


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
    if metrics[0] in ("CVSS:3.1", "CVSS:3.0",):
        version = "v3"
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

        data.update({
            "weight": weight,
            "text": text
        })

    return data
