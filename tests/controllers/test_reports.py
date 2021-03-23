import pytest
from werkzeug.exceptions import NotFound

from unittest.mock import patch

from opencve.extensions import db
from opencve.models.alerts import Alert
from opencve.models.reports import Report
from opencve.models.vendors import Vendor
from opencve.controllers.reports import ReportController
from opencve.tasks.alerts import handle_alerts
from opencve.tasks.reports import handle_reports


def test_metas(app):
    with app.test_request_context():
        _, metas, _ = ReportController.list()
    assert metas == {}


@patch("opencve.tasks.reports.user_manager.email_manager.send_user_report")
def test_list(mock_send, app, handle_events, create_user):
    handle_events("modified_cves/CVE-2018-18074.json")

    user = create_user()
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    db.session.commit()

    handle_alerts()
    handle_reports()

    with app.test_request_context():
        reports = ReportController.list_items({"user_id": user.id})
    assert len(reports) == 1
    assert reports[0].user.id == user.id
    assert reports[0].details == ["canonical"]
    assert reports[0].alerts == Alert.query.filter_by(user_id=user.id).all()


@patch("opencve.tasks.reports.user_manager.email_manager.send_user_report")
def test_list_paginated(mock_send, app, handle_events, create_user):
    old = app.config["REPORTS_PER_PAGE"]
    app.config["REPORTS_PER_PAGE"] = 2

    user = create_user()
    db.session.commit()

    handle_events("modified_cves/CVE-2018-18074.json")
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    db.session.commit()
    handle_alerts()
    handle_reports()

    handle_events("modified_cves/CVE-2019-17052.json")
    user.vendors.append(Vendor.query.filter_by(name="linux").first())
    db.session.commit()
    handle_alerts()
    handle_reports()

    handle_events("modified_cves/CVE-2020-26116.json")
    user.vendors.append(Vendor.query.filter_by(name="python").first())
    db.session.commit()
    handle_alerts()
    handle_reports()

    with app.test_request_context():
        reports = ReportController.list_items({"user_id": user.id})
        assert len(reports) == 2
        assert reports[0].details == ["python"]
        assert reports[1].details == ["linux"]

        reports = ReportController.list_items({"user_id": user.id, "page": 2})
        assert len(reports) == 1
        assert reports[0].details == ["canonical"]

    app.config["REPORTS_PER_PAGE"] = old


@patch("opencve.tasks.reports.user_manager.email_manager.send_user_report")
def test_get(mock_send, app, handle_events, create_user):
    handle_events("modified_cves/CVE-2018-18074.json")

    user = create_user()
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    db.session.commit()

    handle_alerts()
    handle_reports()

    report_1 = Report.query.first()
    assert report_1.seen == False

    with app.test_request_context():
        report_2 = ReportController.get({"public_link": report_1.public_link})
    assert report_1.id == report_2.id
    assert report_2.seen == True
