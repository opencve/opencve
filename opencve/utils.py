import string

from nested_lookup import nested_lookup

from opencve.constants import PRODUCT_SEPARATOR
from opencve.models.cwe import Cwe


def convert_cpes(conf):
    """
    This function takes an object, extracts its CPE uris and transforms them into
    a dictionnary representing the vendors with their associated products.
    """
    uris = nested_lookup("cpe23Uri", conf) if not isinstance(conf, list) else conf

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


def get_cwes(problems):
    """
    Takes a list of problems and return the CWEs ID.
    """
    return list(set([p["value"] for p in problems]))


def get_cwes_details(problems):
    """
    Takes a list of problems and return the CWEs along
    with the name of the vulnerability.
    """
    cwes = {}
    for cwe_id in get_cwes(problems):
        cwes[cwe_id] = None
        cwe = Cwe.query.filter_by(cwe_id=cwe_id).first()
        if cwe:
            cwes[cwe_id] = cwe.name
    return cwes


def get_vendors_letters():
    """
    Returns a list of letters used to filter the vendors.
    """
    return list(string.ascii_lowercase + "@" + string.digits)
