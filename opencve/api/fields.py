import arrow
from flask_restful import fields

from opencve.context import _humanize_filter
from opencve.utils import convert_cpes


class HumanizedNameField(fields.Raw):
    """
    Returns a humanized name.
    """

    def format(self, value):
        return _humanize_filter(value)


class ProductsListField(fields.Raw):
    """
    Returns a list of products.
    """

    def format(self, products):
        return sorted([product.name for product in products])


class CveVendorsField(fields.Raw):
    """
    Returns a list of vendors and products for a given CVE.
    """

    def format(self, json):
        return convert_cpes(json["configurations"])


class DatetimeField(fields.Raw):
    def format(self, value):
        """
        Returns UTC datetime.
        """
        return str(arrow.get(value).to("utc").strftime("%Y-%m-%dT%H:%M:%SZ"))
