from flask import abort

from opencve.controllers.base import BaseController
from opencve.extensions import db
from opencve.models.alerts import Alert
from opencve.models.reports import Report


class ReportController(BaseController):
    model = Report
    order = Report.created_at.desc()
    per_page_param = "REPORTS_PER_PAGE"
    schema = {
        "user_id": {"type": str},
    }

    @classmethod
    def build_query(cls, args):
        query = Report.query.filter_by(user_id=args.get("user_id"))
        return query, {}

    @classmethod
    def get(cls, filters):
        report = super(ReportController, cls).get(filters)

        # The report is now seen
        report.seen = True
        db.session.commit()

        return report
