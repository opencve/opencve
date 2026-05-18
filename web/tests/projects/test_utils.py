from django.test import RequestFactory, override_settings

from projects.utils import (
    build_impact_chart_data_from_cves_table,
    send_notification_confirmation_email,
    RESULT_TYPE_ICONS,
)


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
def test_send_notification_confirmation_email_sends_email(
    create_organization, create_user, create_project, create_notification
):
    """Send one email with correct subject, recipient and body."""
    user = create_user()
    org = create_organization(name="MyOrg", user=user)
    project = create_project(name="MyProject", organization=org)
    notification = create_notification(
        name="notif1",
        project=project,
        type="email",
        configuration={
            "types": [],
            "metrics": {},
            "extras": {
                "email": "recipient@example.com",
                "created_by_email": "creator@example.com",
                "confirmation_token": "secret-token-123",
            },
        },
    )

    from django.core.mail import outbox

    outbox.clear()
    request = RequestFactory().get("/")
    request.META["SERVER_NAME"] = "example.com"
    request.META["SERVER_PORT"] = "80"

    send_notification_confirmation_email(notification, request)

    assert len(outbox) == 1
    msg = outbox[0]
    assert msg.to == ["recipient@example.com"]
    assert "Notification subscription confirmation" in msg.subject
    assert "creator@example.com" in msg.body
    assert "MyOrg" in msg.body
    assert "MyProject" in msg.body
    assert "/notifications/confirm/secret-token-123/" in msg.body


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
def test_send_notification_confirmation_email_does_nothing_when_email_missing(
    create_organization, create_project, create_notification
):
    """Return without sending when extras.email is missing."""
    org = create_organization(name="Org")
    project = create_project(name="Project", organization=org)
    notification = create_notification(
        name="notif1",
        project=project,
        type="email",
        configuration={
            "types": [],
            "metrics": {},
            "extras": {
                "created_by_email": "creator@example.com",
                "confirmation_token": "token",
            },
        },
    )

    from django.core.mail import outbox

    outbox.clear()
    request = RequestFactory().get("/")

    send_notification_confirmation_email(notification, request)

    assert len(outbox) == 0


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
def test_send_notification_confirmation_email_does_nothing_when_token_missing(
    create_organization, create_project, create_notification
):
    """Return without sending when confirmation_token is missing."""
    org = create_organization(name="Org")
    project = create_project(name="Project", organization=org)
    notification = create_notification(
        name="notif1",
        project=project,
        type="email",
        configuration={
            "types": [],
            "metrics": {},
            "extras": {
                "email": "recipient@example.com",
                "created_by_email": "creator@example.com",
            },
        },
    )

    from django.core.mail import outbox

    outbox.clear()
    request = RequestFactory().get("/")

    send_notification_confirmation_email(notification, request)

    assert len(outbox) == 0


def test_build_impact_chart_data_returns_none_for_empty():
    """Return None when cves_table_data is empty or None."""
    assert build_impact_chart_data_from_cves_table(None) is None
    assert build_impact_chart_data_from_cves_table([]) is None


def test_build_impact_chart_data_single_cve():
    """Compute stats for a single CVE row with CVSS 3.1, EPSS, and KEV."""
    data = [
        {
            "cve_id": "CVE-2025-0001",
            "cvss_31": 9.8,
            "epss": 0.95,
            "kev": True,
            "matched_vendors_or_products": ["vendor1"],
        }
    ]
    result = build_impact_chart_data_from_cves_table(data)

    assert result["cves_count"] == 1
    assert result["highest_cvss"] == 9.8
    assert result["average_cvss"] == 9.8
    assert result["cvss_distribution"]["Critical"] == 1
    assert result["cvss_distribution"]["High"] == 0
    assert result["kev_count"] == 1
    assert result["kev_percent"] == 100
    assert result["epss_avg"] == 0.95
    assert result["epss_max"] == 0.95
    assert result["epss_distribution"]["high"] == 1
    assert result["top_vendors_products"] == [{"name": "vendor1", "count": 1}]


def test_build_impact_chart_data_multiple_cves():
    """Compute distribution and averages across several CVEs."""
    data = [
        {
            "cve_id": "CVE-2025-0001",
            "cvss_31": 9.0,
            "epss": 0.91,
            "kev": True,
            "matched_vendors_or_products": ["vendorA"],
        },
        {
            "cve_id": "CVE-2025-0002",
            "cvss_31": 7.5,
            "epss": 0.75,
            "kev": False,
            "matched_vendors_or_products": ["vendorA"],
        },
        {
            "cve_id": "CVE-2025-0003",
            "cvss_31": 5.0,
            "epss": 0.50,
            "kev": False,
            "matched_vendors_or_products": ["vendorB"],
        },
        {
            "cve_id": "CVE-2025-0004",
            "cvss_31": 3.0,
            "epss": 0.10,
            "kev": False,
            "matched_vendors_or_products": ["vendorB"],
        },
    ]
    result = build_impact_chart_data_from_cves_table(data)

    assert result["cves_count"] == 4
    assert result["highest_cvss"] == 9.0
    assert result["cvss_distribution"]["Critical"] == 1
    assert result["cvss_distribution"]["High"] == 1
    assert result["cvss_distribution"]["Medium"] == 1
    assert result["cvss_distribution"]["Low"] == 1
    assert result["kev_count"] == 1
    assert result["kev_percent"] == 25
    assert result["epss_distribution"]["high"] == 1
    assert result["epss_distribution"]["medium"] == 1
    assert result["epss_distribution"]["low"] == 2


def test_build_impact_chart_data_no_cvss():
    """Handle rows without any CVSS score gracefully."""
    data = [
        {"cve_id": "CVE-2025-0001", "kev": False, "matched_vendors_or_products": []},
    ]
    result = build_impact_chart_data_from_cves_table(data)

    assert result["cves_count"] == 1
    assert result["highest_cvss"] is None
    assert result["average_cvss"] is None
    assert result["cvss_distribution"]["Critical"] == 0


def test_build_impact_chart_data_top_vendors_limited_to_five():
    """Only the top 5 vendors are returned, sorted by count descending."""
    data = [
        {
            "cve_id": f"CVE-2025-{i:04d}",
            "cvss_31": 7.0,
            "matched_vendors_or_products": [f"vendor{i}"],
        }
        for i in range(7)
    ]
    data[0]["matched_vendors_or_products"] = ["top1"]
    data[1]["matched_vendors_or_products"] = ["top1"]
    data[2]["matched_vendors_or_products"] = ["top1"]

    result = build_impact_chart_data_from_cves_table(data)
    assert len(result["top_vendors_products"]) <= 5
    assert result["top_vendors_products"][0]["name"] == "top1"
    assert result["top_vendors_products"][0]["count"] == 3


def test_build_impact_chart_data_prefers_highest_cvss_version():
    """When multiple CVSS versions exist, report the one with the highest score."""
    data = [
        {
            "cve_id": "CVE-2025-0001",
            "cvss_31": 7.5,
            "cvss_40": 8.5,
            "matched_vendors_or_products": [],
        }
    ]
    result = build_impact_chart_data_from_cves_table(data)

    assert result["highest_cvss"] == 8.5


def test_result_type_icons_mapping():
    """RESULT_TYPE_ICONS covers the standard output types."""
    assert "notification_sent" in RESULT_TYPE_ICONS
    assert "report" in RESULT_TYPE_ICONS
    assert "assignment" in RESULT_TYPE_ICONS
    assert "status_change" in RESULT_TYPE_ICONS
