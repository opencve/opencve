from flask import abort
from sqlalchemy.orm import joinedload

from opencve.controllers.base import BaseController
from opencve.models.alerts import Alert


class AlertController(BaseController):
    model = Alert
    order = Alert.created_at.desc()
    per_page_param = "ALERTS_PER_PAGE"
    schema = {
        "user_id": {"type": str},
        "report_id": {"type": str},
    }

    @classmethod
    def build_query(cls, args):
        query = cls.model.query.options(joinedload("cve")).filter_by(
            report_id=args.get("report_id")
        )
        return query, {}
