import pytest
from django.urls import reverse

from organizations.models import OrganizationAPIToken


def assert_v2_error(response, code, status_code=400, **extra_fields):
    """Assert a v2 API error envelope matches the expected code and status."""
    assert response.status_code == status_code
    error = response.json()["error"]
    assert error["code"] == code
    for key, value in extra_fields.items():
        assert error[key] == value


def org_url(name="acme"):
    return reverse("v2-organization-detail", kwargs={"name": name})


def org_list_url():
    return reverse("v2-organization-list")


def members_url(org_name="acme"):
    return reverse(
        "v2-organization-member-list",
        kwargs={"organization_name": org_name},
    )


def member_detail_url(member_id, org_name="acme"):
    return reverse(
        "v2-organization-member-detail",
        kwargs={"organization_name": org_name, "id": member_id},
    )


def audit_logs_url(org_name="acme"):
    return reverse(
        "v2-organization-audit-log-list",
        kwargs={"organization_name": org_name},
    )


def projects_url(org_name="acme"):
    return reverse(
        "v2-organization-project-list",
        kwargs={"organization_name": org_name},
    )


def project_detail_url(project_name="prod", org_name="acme"):
    return reverse(
        "v2-organization-project-detail",
        kwargs={"organization_name": org_name, "name": project_name},
    )


def subscriptions_url(org_name="acme", project_name="prod"):
    return reverse(
        "v2-project-subscriptions",
        kwargs={"organization_name": org_name, "project_name": project_name},
    )


def notification_list_url(org_name="acme", project_name="prod"):
    return reverse(
        "v2-project-notification-list",
        kwargs={"organization_name": org_name, "project_name": project_name},
    )


def notification_detail_url(name, org_name="acme", project_name="prod"):
    return reverse(
        "v2-project-notification-detail",
        kwargs={
            "organization_name": org_name,
            "project_name": project_name,
            "notification_name": name,
        },
    )


def automation_list_url(org_name="acme", project_name="prod"):
    return reverse(
        "v2-project-automation-list",
        kwargs={"organization_name": org_name, "project_name": project_name},
    )


def automation_detail_url(name, org_name="acme", project_name="prod"):
    return reverse(
        "v2-project-automation-detail",
        kwargs={
            "organization_name": org_name,
            "project_name": project_name,
            "name": name,
        },
    )


def automation_execution_list_url(
    automation_name, org_name="acme", project_name="prod"
):
    return reverse(
        "v2-project-automation-execution-list",
        kwargs={
            "organization_name": org_name,
            "project_name": project_name,
            "automation_name": automation_name,
        },
    )


def automation_execution_detail_url(
    automation_name, execution_id, org_name="acme", project_name="prod"
):
    return reverse(
        "v2-project-automation-execution-detail",
        kwargs={
            "organization_name": org_name,
            "project_name": project_name,
            "automation_name": automation_name,
            "execution_id": execution_id,
        },
    )


def report_list_url(org_name="acme", project_name="prod"):
    return reverse(
        "v2-project-report-list",
        kwargs={"organization_name": org_name, "project_name": project_name},
    )


def report_detail_url(report_id, org_name="acme", project_name="prod"):
    return reverse(
        "v2-project-report-detail",
        kwargs={
            "organization_name": org_name,
            "project_name": project_name,
            "report_id": report_id,
        },
    )


def project_cves_url(org_name="acme", project_name="prod"):
    return reverse(
        "v2-organization-project-cves",
        kwargs={"organization_name": org_name, "project_name": project_name},
    )


def project_cve_detail_url(cve_id, org_name="acme", project_name="prod"):
    return reverse(
        "v2-organization-project-cve-detail",
        kwargs={
            "organization_name": org_name,
            "project_name": project_name,
            "cve_id": cve_id,
        },
    )


@pytest.fixture
def write_token(api_context):
    """Return a write-mode Bearer token string for the default api_context org."""
    _user, _organization, create_token = api_context
    return create_token(access_mode=OrganizationAPIToken.AccessMode.WRITE)


@pytest.fixture
def read_token(api_context):
    """Return a read-only Bearer token string for the default api_context org."""
    _user, _organization, create_token = api_context
    return create_token(access_mode=OrganizationAPIToken.AccessMode.READ)


def bearer(token_string):
    """Build the Authorization header for a Bearer token."""
    return {"HTTP_AUTHORIZATION": f"Bearer {token_string}"}
