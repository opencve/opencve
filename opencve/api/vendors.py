from flask import request
from flask_restful import fields, marshal_with

from opencve.api.base import BaseResource
from opencve.api.cves import cves_fields
from opencve.api.fields import HumanizedNameField, ProductsListField
from opencve.controllers.cves import CveController
from opencve.controllers.vendors import VendorController


vendor_list_fields = {
    "name": fields.String(attribute="name"),
    "human_name": HumanizedNameField(attribute="name"),
}

vendor_fields = dict(
    vendor_list_fields, **{"products": ProductsListField(attribute="products")}
)


class VendorListResource(BaseResource):
    @marshal_with(vendor_list_fields)
    def get(self):
        return VendorController.list_items(request.args)


class VendorResource(BaseResource):
    @marshal_with(vendor_fields)
    def get(self, name):
        return VendorController.get({"name": name})


class VendorCveResource(BaseResource):
    @marshal_with(cves_fields)
    def get(self, name):
        VendorController.get({"name": name})
        return CveController.list_items({**request.args, "vendor": name})
