from flask import request
from flask_restful import fields, marshal_with

from opencve.api.base import BaseResource
from opencve.api.cves import cves_fields
from opencve.api.fields import DatetimeField
from opencve.controllers.alerts import AlertController
from opencve.controllers.reports import ReportController
from opencve.models.users import User


alert_fields = {
    "id": fields.String(attribute="id"),
    "created_at": DatetimeField(),
    "cve": fields.String(attribute="cve.cve_id"),
    "details": fields.Raw(attribute="details"),
}

event_fields = {
    "cve": fields.String(attribute="cve.cve_id"),
    "type": fields.String(attribute="type.code"),
    "details": fields.Raw(attribute="details"),
}


class AlertListResource(BaseResource):
    @marshal_with(alert_fields)
    def get(self, link):
        report = ReportController.get({"public_link": link})
        return AlertController.list_items({"report_id": report.id})


class AlertResource(BaseResource):
    @marshal_with(event_fields)
    def get(self, link, id):
        report = ReportController.get({"public_link": link})
        alert = AlertController.get({"report_id": report.id, "id": id})
        return alert.events
