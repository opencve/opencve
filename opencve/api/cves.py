from flask import abort, request
from flask_restful import fields, marshal_with

from opencve.api.base import BaseResource
from opencve.api.fields import CveVendorsField, DatetimeField
from opencve.controllers.cves import CveController


cves_fields = {
    "id": fields.String(attribute="cve_id"),
    "summary": fields.String(attribute="summary"),
    "created_at": DatetimeField(),
    "updated_at": DatetimeField(),
}

cve_fields = dict(
    cves_fields,
    **{
        "cvss": {
            "v2": fields.Float(attribute="cvss2"),
            "v3": fields.Float(attribute="cvss3"),
        },
        "vendors": CveVendorsField(attribute="json"),
        "cwes": fields.Raw(),
        "raw_nvd_data": fields.Raw(attribute="json"),
    }
)


class CveListResource(BaseResource):
    @marshal_with(cves_fields)
    def get(self):
        return CveController.list_items(request.args)


class CveResource(BaseResource):
    @marshal_with(cve_fields)
    def get(self, id):
        return CveController.get({"cve_id": id})
