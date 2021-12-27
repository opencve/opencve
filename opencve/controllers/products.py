from flask import current_app as app
from flask_paginate import Pagination

from opencve.controllers.base import BaseController
from opencve.controllers.vendors import VendorController
from opencve.models.products import Product


class ProductController(BaseController):
    model = Product
    order = Product.name.asc()
    per_page_param = "PRODUCTS_PER_PAGE"
    page_parameter = "product_page"
    schema = {
        "vendor": {"type": str},
        "search": {"type": str},
    }

    @classmethod
    def build_query(cls, args):
        if "vendor" in args:
            vendor = VendorController.get({"name": args.get("vendor")})
            query = cls.model.query.filter_by(vendor=vendor)
        else:
            query = cls.model.query

        # Search by term
        if args.get("search"):
            search = (
                args.get("search")
                .lower()
                .replace("%", "")
                .replace("_", "")
                .replace(" ", "_")
            )
            query = query.filter(Product.name.like("%{}%".format(search)))

        return query, {}

    @classmethod
    def get_pagination(cls, args, objects):
        return Pagination(
            product_page=args.get(cls.page_parameter),
            total=objects.total,
            per_page=app.config[cls.per_page_param],
            page_parameter=cls.page_parameter,
            record_name="objects",
            css_framework="bootstrap3",
        )

    @classmethod
    def get(cls, filters):
        vendor = VendorController.get({"name": filters.get("vendor")})
        return super(ProductController, cls).get(
            {"vendor_id": vendor.id, "name": filters.get("product")}
        )
