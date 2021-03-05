from flask import abort

from opencve.controllers.base import BaseController
from opencve.controllers.vendors import VendorController
from opencve.models.products import Product


class ProductController(BaseController):
    model = Product
    order = Product.name.asc()
    per_page_param = "PRODUCTS_PER_PAGE"
    schema = {
        "vendor": {"type": str},
        "search": {"type": str},
    }

    @classmethod
    def build_query(cls, args):
        vendor = VendorController.get({"name": args.get("vendor")})

        query = Product.query.filter_by(vendor=vendor)

        # Search by term
        if args.get("search"):
            search = args.get("search").lower().replace("%", "").replace("_", "")
            query = query.filter(Product.name.like("%{}%".format(search)))

        return query, {}

    @classmethod
    def get(cls, filters):
        vendor = VendorController.get({"name": filters.get("vendor")})
        return super(ProductController, cls).get(
            {"vendor_id": vendor.id, "name": filters.get("product")}
        )
