from flask import abort

from opencve.controllers.base import BaseController
from opencve.models.vendors import Vendor
from opencve.utils import get_vendors_letters


class VendorController(BaseController):
    model = Vendor
    order = Vendor.name.asc()
    per_page_param = "VENDORS_PER_PAGE"
    schema = {
        "letter": {"type": str},
        "search": {"type": str},
    }

    @classmethod
    def build_query(cls, args):
        letter = args.get("letter")

        query = cls.model.query

        # Search by term
        if args.get("search"):
            search = args.get("search").lower().replace("%", "").replace("_", "")
            query = query.filter(cls.model.name.like("%{}%".format(search)))

        # Search by letter
        if letter:
            if letter not in get_vendors_letters():
                abort(404)

            query = query.filter(cls.model.name.like("{}%".format(letter)))

        return query, {}
