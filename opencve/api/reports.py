from flask import request
from flask_restful import fields, marshal_with

from opencve.api.alerts import alert_fields
from opencve.api.base import BaseResource
from opencve.api.cves import cves_fields
from opencve.api.fields import DatetimeField
from opencve.controllers.alerts import AlertController
from opencve.controllers.reports import ReportController
from opencve.models.users import User


report_list_fields = {
    "id": fields.String(attribute="public_link"),
    "created_at": DatetimeField(),
    "details": fields.Raw(attribute="details"),
}

report_fields = dict(
    report_list_fields, **{"alerts": fields.List(fields.Nested(alert_fields))}
)


class ReportListResource(BaseResource):
    @marshal_with(report_list_fields)
    def get(self):
        user = User.query.filter_by(
            username=request.authorization.get("username")
        ).first()
        return ReportController.list_items({**request.args, "user_id": user.id})


class ReportResource(BaseResource):
    @marshal_with(report_fields)
    def get(self, link):
        report = ReportController.get({"public_link": link})
        setattr(report, "alerts", AlertController.list_items({"report_id": report.id}))
        return report
