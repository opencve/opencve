from flask import request
from flask_restful import fields, marshal_with

from opencve.api.base import BaseResource
from opencve.api.cves import cves_fields
from opencve.api.fields import HumanizedNameField
from opencve.controllers.cves import CveController
from opencve.controllers.products import ProductController
from opencve.controllers.vendors import VendorController


product_fields = {
    "name": fields.String(attribute="name"),
    "human_name": HumanizedNameField(attribute="name"),
}


class ProductListResource(BaseResource):
    @marshal_with(product_fields)
    def get(self, vendor):
        return ProductController.list_items({**request.args, "vendor": vendor})


class ProductResource(BaseResource):
    @marshal_with(product_fields)
    def get(self, vendor, product):
        return ProductController.get({"vendor": vendor, "product": product})


class ProductCveResource(BaseResource):
    @marshal_with(cves_fields)
    def get(self, vendor, product):
        ProductController.get({"vendor": vendor, "product": product})
        return CveController.list_items(
            {**request.args, "vendor": vendor, "product": product}
        )
