from flask import request
from flask_restful import fields, marshal_with

from opencve.api.base import BaseResource
from opencve.api.fields import HumanizedNameField
from opencve.models.users import User


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
        user = User.query.filter_by(
            username=request.authorization.get("username")
        ).first()
        return user.vendors


class SubscriptionListRessourceProduct(BaseResource):
    @marshal_with(product_list_fields)
    def get(self):
        user = User.query.filter_by(
            username=request.authorization.get("username")
        ).first()
        return user.products
