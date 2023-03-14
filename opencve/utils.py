from nested_lookup import nested_lookup
from difflib import HtmlDiff

from opencve.constants import PRODUCT_SEPARATOR, VULNERABLE_SEPARATOR
from opencve.models.cwe import Cwe


def convert_cpes(conf, mark_vulnerable=False):
    """
    This function takes an object, extracts its CPE uris and transforms them into
    a dictionnary representing the vendors with their associated products.
    """
    cpes = {}
    # CPE-conversion with duplicates for vulnerability-identification
    if mark_vulnerable:
        matches = (
            nested_lookup("cpe_match", conf) if not isinstance(conf, list) else conf
        )
        for match in matches:
            for cpe in match:
                if "cpe23Uri" not in cpe:
                    continue
                vendor_product = cpe["cpe23Uri"].split(":")[3:5]
                if vendor_product[0] not in cpes:
                    cpes[vendor_product[0]] = set()
                # If CPE is marked as vulnerable create a duplicate with string to identify vulnerability
                if cpe["vulnerable"]:
                    if VULNERABLE_SEPARATOR + vendor_product[0] not in cpes:
                        cpes[VULNERABLE_SEPARATOR + vendor_product[0]] = set()
                    cpes[VULNERABLE_SEPARATOR + vendor_product[0]].add(
                        vendor_product[1]
                    )
                # Insert regular CPE information
                cpes[vendor_product[0]].add(vendor_product[1])
        for vendor in cpes:
            cpes[vendor] = list(cpes[vendor])
    else:
        # Standard CPE-conversion
        uris = nested_lookup("cpe23Uri", conf) if not isinstance(conf, list) else conf
        # Create a list of tuple (vendor, product)
        cpes_t = list(set([tuple(uri.split(":")[3:5]) for uri in uris]))

        # Transform it into nested dictionnary
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
