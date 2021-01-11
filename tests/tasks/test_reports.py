import pytest
from unittest.mock import patch, MagicMock
from flask_user import EmailError

from opencve.extensions import db
from opencve.models.alerts import Alert
from opencve.models.vendors import Vendor
from opencve.models.reports import Report
from opencve.tasks.alerts import handle_alerts
from opencve.tasks.reports import (
    get_top_alerts,
    get_sorted_alerts,
    get_users_with_alerts,
    get_vendors_products,
    handle_reports,
)


@pytest.mark.parametrize(
    "hour,count",
    [
        ("02:00:00", 1),
        ("10:59:00", 1),
        ("11:00:00", 2),
        ("11:15:00", 2),
        ("11:16:00", 1),
        ("20:00:00", 1),
    ],
)
def test_get_users_with_alerts(freezer, create_user, handle_events, hour, count):
    handle_events("modified_cves/CVE-2018-18074.json")

    # Create 2 users with different frequency notification
    user1 = create_user("user1")
    user1.vendors.append(Vendor.query.filter_by(name="canonical").first())
    user1.frequency_notifications = "always"
    db.session.commit()

    user2 = create_user("user2")
    user2.vendors.append(Vendor.query.filter_by(name="canonical").first())
    user2.frequency_notifications = "once"
    db.session.commit()

    handle_alerts()

    freezer.move_to(f"2021-01-01 {hour}")
    users = get_users_with_alerts()
    assert len(users) == count


def test_get_top_alerts(create_cve, create_user):
    user = create_user()
    db.session.add(Alert(cve=create_cve("CVE-2018-18074"), user=user, details={}))
    db.session.add(Alert(cve=create_cve("CVE-2020-9392"), user=user, details={}))
    db.session.add(Alert(cve=create_cve("CVE-2020-26116"), user=user, details={}))
    db.session.commit()

    # List of alerts is reduced and ordered by CVSS3 desc
    top_alerts = get_top_alerts(user, 1)
    assert [a.cve.cvss3 for a in top_alerts] == [9.8]

    top_alerts = get_top_alerts(user, 3)
    assert sorted([a.cve.cvss3 for a in top_alerts]) == sorted([9.8, 7.3, 7.2])

    top_alerts = get_top_alerts(user, 10)
    assert sorted([a.cve.cvss3 for a in top_alerts]) == sorted([9.8, 7.3, 7.2])


def test_get_sorted_alerts(create_cve, create_user):
    user = create_user()

    # Create an alert with the 'foo' vendor
    alert_26116 = Alert(
        cve=create_cve("CVE-2020-26116"),
        user=user,
        details={"vendors": ["foo"], "products": []},
    )
    db.session.add(alert_26116)
    db.session.commit()

    alerts = Alert.query.all()
    sorted_alerts = get_sorted_alerts(alerts)
    assert "foo" in sorted_alerts
    assert sorted_alerts["foo"]["name"] == "Foo"
    assert sorted_alerts["foo"]["max"] == 7.2
    assert [a.id for a in sorted_alerts["foo"]["alerts"]] == [alert_26116.id]

    # Add another alert for the same 'foo' vendor but with a higher score
    alert_28074 = Alert(
        cve=create_cve("CVE-2018-18074"),
        user=user,
        details={"vendors": ["foo"], "products": []},
    )
    db.session.add(alert_28074)
    db.session.commit()

    alerts = Alert.query.all()
    sorted_alerts = get_sorted_alerts(alerts)
    assert "foo" in sorted_alerts
    assert sorted_alerts["foo"]["name"] == "Foo"
    assert sorted_alerts["foo"]["max"] == 9.8
    assert sorted([a.id for a in sorted_alerts["foo"]["alerts"]]) == sorted(
        [alert_26116.id, alert_28074.id]
    )

    # Finally create an alert with the 'bar' product
    alert_9392 = Alert(
        cve=create_cve("CVE-2020-9392"),
        user=user,
        details={"vendors": [], "products": ["bar"]},
    )
    db.session.add(alert_9392)
    db.session.commit()

    alerts = Alert.query.all()
    sorted_alerts = get_sorted_alerts(alerts)
    assert "bar" in sorted_alerts
    assert sorted_alerts["bar"]["name"] == "Bar"
    assert sorted_alerts["bar"]["max"] == 7.3
    assert [a.id for a in sorted_alerts["bar"]["alerts"]] == [alert_9392.id]


def test_get_vendors_products(create_cve, create_user):
    user = create_user()
    db.session.add(
        Alert(
            cve=create_cve("CVE-2020-26116"),
            user=user,
            details={"vendors": ["foo"], "products": []},
        )
    )
    db.session.add(
        Alert(
            cve=create_cve("CVE-2018-18074"),
            user=user,
            details={"vendors": ["foo"], "products": []},
        )
    )
    db.session.add(
        Alert(
            cve=create_cve("CVE-2020-9392"),
            user=user,
            details={"vendors": [], "products": ["bar"]},
        )
    )
    db.session.commit()

    vendors_products = get_vendors_products(Alert.query.all())
    assert sorted(vendors_products) == sorted(["bar", "foo"])


def test_server_name_exceptions(app):
    old = app.config["SERVER_NAME"]
    app.config["SERVER_NAME"] = None

    with pytest.raises(ValueError):
        handle_reports()

    app.config["SERVER_NAME"] = old


@patch("opencve.tasks.reports.user_manager.email_manager.send_user_report")
def test_report_without_notification(mock_send, create_user, handle_events):
    handle_events("modified_cves/CVE-2018-18074.json")

    user = create_user()
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    user.enable_notifications = False
    db.session.commit()

    handle_alerts()
    handle_reports()

    reports = Report.query.all()
    assert len(reports) == 1
    assert reports[0].user.id == user.id
    assert reports[0].details == ["canonical"]
    assert reports[0].alerts == Alert.query.filter_by(user_id=user.id).all()

    assert not mock_send.called
    assert Alert.query.filter_by(notify=False).count() == 0


@patch("opencve.tasks.reports.user_manager.email_manager.send_user_report")
def test_report_with_notification(mock_send, create_user, handle_events):
    handle_events("modified_cves/CVE-2018-18074.json")

    user = create_user()
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    db.session.commit()

    handle_alerts()
    handle_reports()

    reports = Report.query.all()
    assert len(reports) == 1
    assert reports[0].user.id == user.id
    assert reports[0].details == ["canonical"]
    assert reports[0].alerts == Alert.query.filter_by(user_id=user.id).all()

    assert mock_send.called
    mock_send.assert_called_with(
        user,
        **{
            "subject": "1 alert on Canonical",
            "total_alerts": 1,
            "alerts_sorted": get_sorted_alerts(Alert.query.all()),
            "report_public_link": Report.query.first().public_link,
        },
    )
    assert Alert.query.filter_by(notify=False).count() == 0


@patch("opencve.tasks.reports.user_manager.email_manager.send_user_report")
def test_report_bad_smtp_config(mock_send, create_user, handle_events):
    mock_send.side_effect = EmailError("error")

    handle_events("modified_cves/CVE-2018-18074.json")

    user = create_user()
    user.vendors.append(Vendor.query.filter_by(name="canonical").first())
    db.session.commit()

    handle_alerts()
    handle_reports()

    reports = Report.query.all()
    assert len(reports) == 1
    assert reports[0].user.id == user.id
    assert reports[0].details == ["canonical"]
    assert reports[0].alerts == Alert.query.filter_by(user_id=user.id).all()
    assert len(reports[0].alerts) == 1
    assert Alert.query.filter_by(notify=False).count() == 0
