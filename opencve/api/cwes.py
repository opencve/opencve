from flask import request
from flask_restful import fields, marshal_with

from opencve.api.base import BaseResource
from opencve.api.cves import cves_fields
from opencve.controllers.cves import CveController
from opencve.controllers.cwes import CweController


cwes_fields = {
    "id": fields.String(attribute="cwe_id"),
    "name": fields.String(attribute="name"),
    "description": fields.String(attribute="description"),
}


class CweListResource(BaseResource):
    @marshal_with(cwes_fields)
    def get(self):
        return CweController.list_items(request.args)


class CweResource(BaseResource):
    @marshal_with(cwes_fields)
    def get(self, id):
        return CweController.get({"cwe_id": id})


class CweCveResource(BaseResource):
    @marshal_with(cves_fields)
    def get(self, id):
        CweController.get({"cwe_id": id})
        return CveController.list_items({**request.args, "cwe": id})
