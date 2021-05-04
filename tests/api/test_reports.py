from datetime import datetime, timezone
from unittest.mock import patch

from opencve.extensions import db
from opencve.models.alerts import Alert
from opencve.models.reports import Report
from opencve.models.vendors import Vendor
from opencve.tasks.alerts import handle_alerts
from opencve.tasks.reports import handle_reports


def test_list_reports_authentication(client, create_user):
    create_user("opencve")
    response = client.get("/api/reports")
    assert response.status_code == 401
    response = client.login("john").get("/api/reports")
    assert response.status_code == 401
    response = client.login("opencve").get("/api/reports")
    assert response.status_code == 200


@patch("opencve.tasks.reports.user_manager.email_manager.send_user_report")
def test_list_reports(mock_send, client, create_user, handle_events):
    user = create_user("opencve")
    response = client.login("opencve").get("/api/reports")
    assert response.status_code == 200
    assert response.json == []

    handle_events("modified_cves/CVE-2018-18074.json")
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    db.session.commit()
    handle_alerts()
    handle_reports()

    report = Report.query.first()
    report.created_at = datetime(2021, 1, 1, tzinfo=timezone.utc)

    response = client.login("opencve").get("/api/reports")
    assert response.status_code == 200
    assert len(response.json) == 1
    assert response.json[0] == {
        "id": report.public_link,
        "details": ["canonical"],
        "created_at": "2021-01-01T00:00:00Z",
    }
    db.session.commit()


def test_get_report_not_found(client, create_user):
    create_user("opencve")
    response = client.login("opencve").get("/api/reports/404")
    assert response.status_code == 404
    assert response.json == {"message": "Not found."}


@patch("opencve.tasks.reports.user_manager.email_manager.send_user_report")
def test_get_report(mock_send, client, create_user, handle_events):
    user = create_user("opencve")
    handle_events("modified_cves/CVE-2018-18074.json")
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    db.session.commit()
    handle_alerts()
    handle_reports()

    report = Report.query.first()
    report.created_at = datetime(2021, 1, 1, tzinfo=timezone.utc)
    alert = Alert.query.first()
    alert.created_at = datetime(2021, 1, 1, tzinfo=timezone.utc)

    response = client.login("opencve").get("/api/reports")
    assert response.status_code == 200
    assert len(response.json) == 1
    assert response.json[0] == {
        "id": report.public_link,
        "details": ["canonical"],
        "created_at": "2021-01-01T00:00:00Z",
    }

    response = client.login("opencve").get(f"/api/reports/{report.public_link}")
    assert response.status_code == 200

    data = response.json
    alerts = data.pop("alerts")
    assert alerts == [
        {
            "id": str(alert.id),
            "created_at": "2021-01-01T00:00:00Z",
            "cve": "CVE-2018-18074",
            "details": {
                "products": [],
                "vendors": ["canonical"],
                "filters": ["new_cve"],
            },
        }
    ]
    assert data == {
        "id": report.public_link,
        "details": ["canonical"],
        "created_at": "2021-01-01T00:00:00Z",
    }
    db.session.commit()
