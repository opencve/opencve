from flask import request
from flask_restful import fields, marshal_with
from flask_user import current_user
from opencve.api.base import BaseResource
from opencve.api.fields import HumanizedNameField


vendor_list_fields = {
    "name": fields.String(attribute="name"),
    "human_name": HumanizedNameField(attribute="name"),
}

product_list_fields = {
    "name": fields.String(attribute="name"),
    "human_name": HumanizedNameField(attribute="name"),
    "parent_vendor": fields.String(attribute="vendor.name"),
}

class SubscriptionListRessourceVendor(BaseResource):
    @marshal_with(vendor_list_fields)
    def get(self):
        if not current_user.is_authenticated:
            return json.dumps({"status": "error", "message": "not allowed"})
        return current_user.vendors


class SubscriptionListRessourceProduct(BaseResource):
    @marshal_with(product_list_fields)
    def get(self):
        if not current_user.is_authenticated:
            return json.dumps({"status": "error", "message": "not allowed"})
        return current_user.products
