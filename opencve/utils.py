from nested_lookup import nested_lookup
from difflib import HtmlDiff

from opencve.constants import PRODUCT_SEPARATOR
from opencve.models.cwe import Cwe


def convert_cpes(conf):
    """
    This function takes an object, extracts its CPE uris and transforms them into
    a dictionnary representing the vendors with their associated products.
    """
    uris = nested_lookup("criteria", conf)

    # Try old NVD CVE format if no criteria found
    if not uris:
        uris = nested_lookup("cpe23Uri", conf)

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
    # TODO: change references to it
    """
    Takes a list of problems and return the CWEs ID.
    """
    return list(set([p["value"] for p in problems]))


def weaknesses_to_flat(weaknesses=None):
    return nested_lookup("value", weaknesses)


def get_cwes_details(cve_json):
    """
    Takes a list of problems and return the CWEs along
    with the name of the vulnerability.
    """
    if "cve" in cve_json:
        problems = cve_json["cve"]["problemtype"]["problemtype_data"][0]["description"]
    else:
        problems = cve_json.get("weaknesses")

    cwes = {}
    for cwe_id in weaknesses_to_flat(problems):
        cwes[cwe_id] = None
        cwe = Cwe.query.filter_by(cwe_id=cwe_id).first()
        if cwe:
            cwes[cwe_id] = cwe.name
    return cwes


class CustomHtmlHTML(HtmlDiff):
    def __init__(self, *args, **kwargs):
        self._table_template = """
        <table class="table table-diff table-condensed">
            <thead>
                <tr>
                    <th colspan="2">Old JSON</th>
                    <th colspan="2">New JSON</th>
                </tr>
            </thead>
            <tbody>%(data_rows)s</tbody>
        </table>"""
        super().__init__(*args, **kwargs)

    def _format_line(self, side, flag, linenum, text):
        text = text.replace("&", "&amp;").replace(">", "&gt;").replace("<", "&lt;")
        text = text.replace(" ", "&nbsp;").rstrip()
        return '<td class="diff_header">%s</td><td class="break">%s</td>' % (
            linenum,
            text,
        )


def vendors_conf_to_dict(conf):
    """
    This function takes an object, extracts its CPE uris and transforms them into
    a dictionary representing the vendors with their associated products.
    """
    uris = nested_lookup("criteria", conf)

    # Create a list of tuple (vendor, product)
    cpes_t = list(set([tuple(uri.split(":")[3:5]) for uri in uris]))

    # Transform it into nested dictionary
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
