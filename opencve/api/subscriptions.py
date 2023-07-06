from flask import request
from flask_restful import fields, marshal_with, reqparse

from opencve.api.base import BaseResource
from opencve.api.fields import HumanizedNameField
from opencve.models.users import User
from opencve.models.vendors import Vendor
from opencve.extensions import db
from opencve.models import is_valid_uuid

vendor_list_fields = {
    "name": fields.String(attribute="name"),
    "human_name": HumanizedNameField(attribute="name"),
    "vendor_id": fields.String(attribute="id"),
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


class SubscriptionAddVendor(BaseResource):
    def post(
        self,
    ):
        user = User.query.filter_by(
            username=request.authorization.get("username")
        ).first()
        vendor_id = request.form.get("id")
        if not is_valid_uuid(vendor_id):
            return {"status": "fail"}, 400
        vendor = Vendor.query.filter_by(id=vendor_id).first()
        if not vendor:
            return {"status": "fail"}, 400
        if vendor not in user.vendors:
            user.vendors.append(vendor)
            db.session.commit()
            return {"status": "ok"}, 200
