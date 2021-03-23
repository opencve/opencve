from datetime import datetime, timezone
from unittest.mock import patch

from flask import request

from opencve.extensions import db
from opencve.models.reports import Report
from opencve.models.users import User
from opencve.models.vendors import Vendor
from opencve.tasks.alerts import handle_alerts
from opencve.tasks.reports import handle_reports


def test_redirect_auth(client):
    response = client.get("/reports")
    assert response.status_code == 302

    with client:
        response = client.get("/reports", follow_redirects=True)
        assert response.status_code == 200
        assert request.path == "/login"


def test_no_reports(client, login):
    response = client.get("/reports")
    assert response.status_code == 200
    assert b"No report yet." in response.data


@patch("opencve.tasks.reports.user_manager.email_manager.send_user_report")
def test_list_reports(mock_send, client, login, handle_events):
    user = User.query.first()
    handle_events("modified_cves/CVE-2018-18074.json")
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    db.session.commit()
    handle_alerts()
    handle_reports()

    report = Report.query.first()
    report.created_at = datetime(2021, 1, 1, tzinfo=timezone.utc)

    response = client.get("/reports")
    assert response.status_code == 200
    assert b"Canonical" in response.data
    assert b"Jan 01 &#39;21 at 00:00" in response.data
    db.session.commit()


@patch("opencve.tasks.reports.user_manager.email_manager.send_user_report")
def test_get_report(mock_send, client, login, handle_events):
    user = User.query.first()
    handle_events("modified_cves/CVE-2018-18074.json")
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    db.session.commit()
    handle_alerts()
    handle_reports()

    report = Report.query.first()
    report.created_at = datetime(2021, 1, 1, tzinfo=timezone.utc)

    response = client.get(f"/reports/{report.public_link}")
    assert b"1 alert on 01/01/21" in response.data
    assert b"Canonical" in response.data
    assert b"CVE-2018-18074" in response.data
    assert b"9.8" in response.data
    assert b"New CVE" in response.data
    db.session.commit()
