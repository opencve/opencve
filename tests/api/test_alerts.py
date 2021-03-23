from datetime import datetime, timezone
from unittest.mock import patch

from opencve.extensions import db
from opencve.models.alerts import Alert
from opencve.models.vendors import Vendor
from opencve.models.reports import Report
from opencve.tasks.alerts import handle_alerts
from opencve.tasks.reports import handle_reports


@patch("opencve.tasks.reports.user_manager.email_manager.send_user_report")
def test_list_alerts_authentication(mock_send, client, create_user, handle_events):
    user = create_user("opencve")
    handle_events("modified_cves/CVE-2018-18074.json")
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    db.session.commit()
    handle_alerts()
    handle_reports()

    report = Report.query.first()
    alert = Alert.query.first()

    response = client.get(f"/api/reports/{report.public_link}/alerts")
    assert response.status_code == 401
    response = client.get(f"/api/reports/{report.public_link}/alerts/{alert.id}")
    assert response.status_code == 401

    client.login("opencve")
    response = client.get(f"/api/reports/{report.public_link}/alerts")
    assert response.status_code == 200
    response = client.get(f"/api/reports/{report.public_link}/alerts")
    assert response.status_code == 200


@patch("opencve.tasks.reports.user_manager.email_manager.send_user_report")
def test_list_alerts(mock_send, client, create_user, create_cve, handle_events):
    create_cve("CVE-2018-18074")
    handle_events("modified_cves/CVE-2018-18074_cvss.json")
    user = create_user("opencve")
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    db.session.commit()
    handle_alerts()
    handle_reports()

    report = Report.query.first()
    report.created_at = datetime(2021, 1, 1, tzinfo=timezone.utc)
    alert = Alert.query.first()
    alert.created_at = datetime(2021, 1, 1, tzinfo=timezone.utc)

    response = client.login("opencve").get(f"/api/reports/{report.public_link}/alerts")
    assert response.json == [
        {
            "created_at": "2021-01-01T00:00:00Z",
            "cve": "CVE-2018-18074",
            "details": {"filters": ["cvss"], "products": [], "vendors": ["canonical"]},
            "id": str(alert.id),
        },
    ]


@patch("opencve.tasks.reports.user_manager.email_manager.send_user_report")
def test_get_alert(mock_send, client, create_user, create_cve, handle_events):
    create_cve("CVE-2018-18074")
    handle_events("modified_cves/CVE-2018-18074_cvss.json")
    user = create_user("opencve")
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    db.session.commit()
    handle_alerts()
    handle_reports()

    report = Report.query.first()
    report.created_at = datetime(2021, 1, 1, tzinfo=timezone.utc)
    alert = Alert.query.first()
    alert.created_at = datetime(2021, 1, 1, tzinfo=timezone.utc)

    response = client.login("opencve").get(
        f"/api/reports/{report.public_link}/alerts/{alert.id}"
    )
    assert response.json == [
        {
            "cve": "CVE-2018-18074",
            "type": "cvss",
            "details": {"old": {"v2": 5.0, "v3": 9.8}, "new": {"v2": 6.0, "v3": 10}},
        }
    ]
