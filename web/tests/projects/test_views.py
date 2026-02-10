import json
from datetime import date, timedelta
from unittest.mock import Mock, PropertyMock, patch

import pytest
from django.contrib.messages import get_messages
from django.test import RequestFactory, override_settings
from django.urls import reverse
from django.utils.timezone import now

from changes.models import Change, Report
from cves.models import Cve
from cves.search import BadQueryException, MaxFieldsExceededException
from organizations.models import Membership
from projects.models import CveTracker, Notification, Project
from projects.views import ProjectVulnerabilitiesView


@override_settings(ENABLE_ONBOARDING=False)
def test_projects_list_view_requires_authentication(client):
    """Test that ProjectsListView requires authentication"""
    response = client.get(reverse("list_projects", kwargs={"org_name": "test-org"}))
    assert response.status_code == 302


@override_settings(ENABLE_ONBOARDING=False)
def test_projects_list_view_organization_member_access(
    create_organization, create_user, create_project, auth_client
):
    """Test that only organization members can access the projects list"""
    user1 = create_user()
    org1 = create_organization(name="org1", user=user1)
    create_project(name="project1", organization=org1)

    user2 = create_user()
    create_organization(name="org2", user=user2)

    # User1 can access org1's projects
    client = auth_client(user1)
    response = client.get(reverse("list_projects", kwargs={"org_name": "org1"}))
    assert response.status_code == 200

    # User2 cannot access org1's projects
    client = auth_client(user2)
    response = client.get(reverse("list_projects", kwargs={"org_name": "org1"}))
    assert response.status_code == 302
    assert response.url == reverse("list_organizations")


@override_settings(ENABLE_ONBOARDING=False)
def test_projects_list_view_displays_projects(
    create_organization, create_user, create_project, auth_client
):
    """Test that ProjectsListView displays all projects for the organization"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project1 = create_project(name="project1", organization=org)
    project2 = create_project(name="project2", organization=org)

    client = auth_client(user)
    response = client.get(reverse("list_projects", kwargs={"org_name": "org1"}))
    assert response.status_code == 200
    assert project1 in response.context["projects"]
    assert project2 in response.context["projects"]
    assert len(response.context["projects"]) == 2


@override_settings(ENABLE_ONBOARDING=False)
def test_projects_list_view_ordered_by_name(
    create_organization, create_user, create_project, auth_client
):
    """Test that projects are ordered by name"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    create_project(name="zebra", organization=org)
    create_project(name="alpha", organization=org)
    create_project(name="beta", organization=org)

    client = auth_client(user)
    response = client.get(reverse("list_projects", kwargs={"org_name": "org1"}))
    assert response.status_code == 200
    projects = list(response.context["projects"])
    assert projects[0].name == "alpha"
    assert projects[1].name == "beta"
    assert projects[2].name == "zebra"


@override_settings(ENABLE_ONBOARDING=False)
def test_project_detail_view_requires_authentication(client):
    """Test that ProjectDetailView requires authentication"""
    response = client.get(
        reverse(
            "project", kwargs={"org_name": "test-org", "project_name": "test-project"}
        )
    )
    assert response.status_code == 302


@override_settings(ENABLE_ONBOARDING=False)
def test_project_detail_view_organization_member_access(
    create_organization, create_user, create_project, auth_client
):
    """Test that only organization members can access project details"""
    user1 = create_user()
    org1 = create_organization(name="org1", user=user1)
    project = create_project(name="project1", organization=org1)

    user2 = create_user()
    create_organization(name="org2", user=user2)

    # User1 can access project
    client = auth_client(user1)
    response = client.get(
        reverse("project", kwargs={"org_name": "org1", "project_name": "project1"})
    )
    assert response.status_code == 200

    # User2 cannot access project
    client = auth_client(user2)
    response = client.get(
        reverse("project", kwargs={"org_name": "org1", "project_name": "project1"})
    )
    assert response.status_code == 302
    assert response.url == reverse("list_organizations")


@override_settings(ENABLE_ONBOARDING=False)
def test_project_detail_view_inactive_project(
    create_organization, create_user, create_project, auth_client
):
    """Test that inactive projects return 404"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org, active=False)

    client = auth_client(user)
    response = client.get(
        reverse("project", kwargs={"org_name": "org1", "project_name": "project1"})
    )
    assert response.status_code == 404


@override_settings(ENABLE_ONBOARDING=False)
def test_project_detail_view_context_data(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Test that ProjectDetailView provides correct context data"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(
        name="project1",
        organization=org,
        vendors=["git-scm"],
        products=["git"],
    )
    cve = create_cve("CVE-2023-22490")  # git-scm vendor

    client = auth_client(user)
    response = client.get(
        reverse("project", kwargs={"org_name": "org1", "project_name": "project1"})
    )
    assert response.status_code == 200
    assert response.context["project"] == project
    assert "changes" in response.context
    assert "reports" in response.context
    assert "cve_tracking_stats" in response.context


@override_settings(ENABLE_ONBOARDING=False)
def test_project_detail_view_tracking_stats(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Test that CVE tracking statistics are displayed correctly"""
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")
    org = create_organization(name="org1", user=user1)
    Membership.objects.create(
        user=user2,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )

    project = create_project(
        name="project1",
        organization=org,
        vendors=["git-scm"],
    )
    cve1 = create_cve("CVE-2023-22490")
    cve2 = create_cve("CVE-2021-44228")

    # Create trackers
    CveTracker.update_tracker(
        project=project, cve=cve1, assignee=user1, status="to_evaluate"
    )
    CveTracker.update_tracker(
        project=project, cve=cve2, assignee=user2, status="resolved"
    )

    client = auth_client(user1)
    response = client.get(
        reverse("project", kwargs={"org_name": "org1", "project_name": "project1"})
    )
    assert response.status_code == 200

    stats = response.context["cve_tracking_stats"]
    assert "assignee_stats" in stats
    assert "status_stats" in stats

    # Check assignee stats
    assignee_stats = stats["assignee_stats"]
    assert len(assignee_stats) == 2
    usernames = [stat["assignee__username"] for stat in assignee_stats]
    assert "user1" in usernames
    assert "user2" in usernames

    # Check status stats
    status_stats = stats["status_stats"]
    status_keys = [stat["status"] for stat in status_stats]
    assert "to_evaluate" in status_keys
    assert "resolved" in status_keys


@override_settings(ENABLE_ONBOARDING=False)
def test_project_create_view_requires_authentication(client):
    """Test that ProjectCreateView requires authentication"""
    response = client.get(reverse("create_project", kwargs={"org_name": "test-org"}))
    assert response.status_code == 302


@override_settings(ENABLE_ONBOARDING=False)
def test_project_create_view_requires_owner(
    create_organization, create_user, auth_client
):
    """Test that only organization owners can create projects"""
    user1 = create_user()
    org = create_organization(name="org1", user=user1, owner=True)

    user2 = create_user()
    Membership.objects.create(
        user=user2,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )

    # Owner can access
    client = auth_client(user1)
    response = client.get(reverse("create_project", kwargs={"org_name": "org1"}))
    assert response.status_code == 200

    # Member cannot access
    client = auth_client(user2)
    response = client.get(reverse("create_project", kwargs={"org_name": "org1"}))
    assert response.status_code == 302
    assert response.url == reverse("list_organizations")


@override_settings(ENABLE_ONBOARDING=False)
def test_project_create_view_valid_form(create_organization, create_user, auth_client):
    """Test creating a project with valid form data"""
    user = create_user()
    org = create_organization(name="org1", user=user)

    client = auth_client(user)
    response = client.post(
        reverse("create_project", kwargs={"org_name": "org1"}),
        data={
            "name": "my-project",
            "description": "My project description",
            "active": "on",
        },
        follow=True,
    )

    assert response.status_code == 200
    assert Project.objects.filter(name="my-project", organization=org).exists()

    # Check success message
    messages = list(get_messages(response.wsgi_request))
    assert any("successfully created" in str(m) for m in messages)


@override_settings(ENABLE_ONBOARDING=False)
def test_project_create_view_invalid_form(
    create_organization, create_user, auth_client
):
    """Test creating a project with invalid form data"""
    user = create_user()
    org = create_organization(name="org1", user=user)

    client = auth_client(user)
    response = client.post(
        reverse("create_project", kwargs={"org_name": "org1"}),
        data={"name": "project|invalid", "description": "My description"},
    )

    assert response.status_code == 200
    assert not Project.objects.filter(name="project|invalid", organization=org).exists()
    assert response.context["form"].errors == {
        "name": ["Special characters (except dash) are not accepted"]
    }


@override_settings(ENABLE_ONBOARDING=False)
def test_project_edit_view_requires_authentication(client):
    """Test that ProjectEditView requires authentication"""
    response = client.get(
        reverse(
            "edit_project",
            kwargs={"org_name": "test-org", "project_name": "test-project"},
        )
    )
    assert response.status_code == 302


@override_settings(ENABLE_ONBOARDING=False)
def test_project_edit_view_requires_owner(
    create_organization, create_user, create_project, auth_client
):
    """Test that only organization owners can edit projects"""
    user1 = create_user()
    org = create_organization(name="org1", user=user1)
    project = create_project(name="project1", organization=org)

    user2 = create_user()
    Membership.objects.create(
        user=user2,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )

    # Owner can access
    client = auth_client(user1)
    response = client.get(
        reverse("edit_project", kwargs={"org_name": "org1", "project_name": "project1"})
    )
    assert response.status_code == 200

    # Member cannot access
    client = auth_client(user2)
    response = client.get(
        reverse("edit_project", kwargs={"org_name": "org1", "project_name": "project1"})
    )
    assert response.status_code == 302
    assert response.url == reverse("list_organizations")


@override_settings(ENABLE_ONBOARDING=False)
def test_project_edit_view_valid_form(
    create_organization, create_user, create_project, auth_client
):
    """Test editing a project with valid form data"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(
        name="project1", organization=org, description="Old description"
    )

    client = auth_client(user)
    response = client.post(
        reverse(
            "edit_project", kwargs={"org_name": "org1", "project_name": "project1"}
        ),
        data={
            "name": "project1",
            "description": "New description",
            "active": "on",
        },
        follow=True,
    )

    assert response.status_code == 200
    project.refresh_from_db()
    assert project.description == "New description"

    # Check success message
    messages = list(get_messages(response.wsgi_request))
    assert any("successfully updated" in str(m) for m in messages)


@override_settings(ENABLE_ONBOARDING=False)
def test_project_edit_view_rename_project(
    create_organization, create_user, create_project, auth_client
):
    """Test renaming a project updates its name"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(
        name="project1", organization=org, description="Some description"
    )

    client = auth_client(user)
    response = client.post(
        reverse(
            "edit_project", kwargs={"org_name": "org1", "project_name": "project1"}
        ),
        data={
            "name": "project-renamed",
            "description": "Some description",
            "active": "on",
        },
        follow=True,
    )

    assert response.status_code == 200
    project.refresh_from_db()
    assert project.name == "project-renamed"

    messages = list(get_messages(response.wsgi_request))
    assert any("successfully updated" in str(m) for m in messages)


@override_settings(ENABLE_ONBOARDING=False)
def test_project_edit_view_rename_project_name_conflict(
    create_organization, create_user, create_project, auth_client
):
    """Test renaming a project fails when the name already exists"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(
        name="project1", organization=org, description="Some description"
    )
    create_project(name="existing", organization=org)

    client = auth_client(user)
    response = client.post(
        reverse(
            "edit_project", kwargs={"org_name": "org1", "project_name": "project1"}
        ),
        data={
            "name": "existing",
            "description": "Some description",
            "active": "on",
        },
    )

    assert response.status_code == 200
    form = response.context["form"]
    assert form.errors == {"name": ["This project already exists."]}

    project.refresh_from_db()
    assert project.name == "project1"


@override_settings(ENABLE_ONBOARDING=False)
def test_project_delete_view_requires_authentication(client):
    """Test that ProjectDeleteView requires authentication"""
    response = client.get(
        reverse(
            "delete_project",
            kwargs={"org_name": "test-org", "project_name": "test-project"},
        )
    )
    assert response.status_code == 302


@override_settings(ENABLE_ONBOARDING=False)
def test_project_delete_view_requires_owner(
    create_organization, create_user, create_project, auth_client
):
    """Test that only organization owners can delete projects"""
    user1 = create_user()
    org = create_organization(name="org1", user=user1)
    project = create_project(name="project1", organization=org)

    user2 = create_user()
    Membership.objects.create(
        user=user2,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )

    # Owner can access
    client = auth_client(user1)
    response = client.get(
        reverse(
            "delete_project", kwargs={"org_name": "org1", "project_name": "project1"}
        )
    )
    assert response.status_code == 200

    # Member cannot access
    client = auth_client(user2)
    response = client.get(
        reverse(
            "delete_project", kwargs={"org_name": "org1", "project_name": "project1"}
        )
    )
    assert response.status_code == 302
    assert response.url == reverse("list_organizations")


@override_settings(ENABLE_ONBOARDING=False)
def test_project_delete_view_deletes_project(
    create_organization, create_user, create_project, auth_client
):
    """Test that deleting a project actually deletes it"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)

    client = auth_client(user)
    response = client.post(
        reverse(
            "delete_project", kwargs={"org_name": "org1", "project_name": "project1"}
        ),
        follow=True,
    )

    assert response.status_code == 200
    assert not Project.objects.filter(id=project.id).exists()

    # Check success message
    messages = list(get_messages(response.wsgi_request))
    assert any("deleted" in str(m) for m in messages)


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_view_requires_authentication(client):
    """Test that ProjectVulnerabilitiesView requires authentication"""
    response = client.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "test-org", "project_name": "test-project"},
        )
    )
    assert response.status_code == 302


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_view_organization_member_access(
    create_organization, create_user, create_project, auth_client
):
    """Test that only organization members can access vulnerabilities"""
    user1 = create_user()
    org1 = create_organization(name="org1", user=user1)
    project = create_project(name="project1", organization=org1, vendors=["git-scm"])

    user2 = create_user()
    create_organization(name="org2", user=user2)

    # User1 can access
    client = auth_client(user1)
    response = client.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )
    assert response.status_code == 200

    # User2 cannot access
    client = auth_client(user2)
    response = client.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )
    assert response.status_code == 302
    assert response.url == reverse("list_organizations")


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_view_displays_cves(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Test that ProjectVulnerabilitiesView displays CVEs matching project subscriptions"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(
        name="project1",
        organization=org,
        vendors=["git-scm"],
    )
    cve1 = create_cve("CVE-2023-22490")  # git-scm vendor
    create_cve("CVE-2021-44228")  # apache vendor (not subscribed)

    client = auth_client(user)
    response = client.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )
    assert response.status_code == 200
    cves = list(response.context["cves"])
    assert len(cves) == 1
    assert cves[0].cve_id == "CVE-2023-22490"


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_view_filter_by_assignee(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Test filtering vulnerabilities by assignee"""
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")
    org = create_organization(name="org1", user=user1)
    Membership.objects.create(
        user=user2,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )

    project = create_project(
        name="project1",
        organization=org,
        vendors=["git-scm"],
    )
    cve1 = create_cve("CVE-2023-22490")
    cve2 = create_cve("CVE-2021-44228")

    # Create trackers
    CveTracker.update_tracker(project=project, cve=cve1, assignee=user1)
    CveTracker.update_tracker(project=project, cve=cve2, assignee=user2)

    client = auth_client(user1)
    response = client.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        data={"assignee": user1.username},
    )
    assert response.status_code == 200
    cves = list(response.context["cves"])
    assert len(cves) == 1
    assert cves[0].cve_id == "CVE-2023-22490"


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_view_filter_by_status(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Test filtering vulnerabilities by status"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(
        name="project1",
        organization=org,
        vendors=["git-scm"],
    )
    cve1 = create_cve("CVE-2023-22490")
    cve2 = create_cve("CVE-2021-44228")

    # Create trackers with different statuses
    CveTracker.update_tracker(project=project, cve=cve1, status="to_evaluate")
    CveTracker.update_tracker(project=project, cve=cve2, status="resolved")

    client = auth_client(user)
    response = client.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        data={"status": "to_evaluate"},
    )
    assert response.status_code == 200
    cves = list(response.context["cves"])
    assert len(cves) == 1
    assert cves[0].cve_id == "CVE-2023-22490"


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_view_filter_by_query(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Test filtering vulnerabilities by query parameter"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(
        name="project1",
        organization=org,
        vendors=["git-scm", "apache"],
    )
    cve1 = create_cve("CVE-2023-22490")  # git-scm vendor
    cve2 = create_cve("CVE-2021-44228")  # apache vendor
    cve3 = create_cve("CVE-2022-22965")  # vmware vendor (not subscribed)

    client = auth_client(user)

    # Test without query (should return all subscribed CVEs)
    response = client.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )
    assert response.status_code == 200
    cves = list(response.context["cves"])
    cve_ids = [cve.cve_id for cve in cves]
    assert "CVE-2023-22490" in cve_ids
    assert "CVE-2021-44228" in cve_ids
    assert "CVE-2022-22965" not in cve_ids  # Not subscribed

    # Test with query filtering by specific CVE ID
    response = client.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        data={"query": "cve:CVE-2023-22490"},
    )
    assert response.status_code == 200
    cves = list(response.context["cves"])
    assert len(cves) == 1
    assert cves[0].cve_id == "CVE-2023-22490"
    assert cve2 not in cves
    assert cve3 not in cves

    # Test with query that matches no CVE
    response = client.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        data={"query": "cve:CVE-9999-99999"},
    )
    assert response.status_code == 200
    cves = list(response.context["cves"])
    assert len(cves) == 0


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_view_pagination(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Test that ProjectVulnerabilitiesView paginates results"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(
        name="project1",
        organization=org,
        vendors=["cisco"],  # CVE-2021-44228, CVE-2022-22965
    )

    # Create multiple CVEs that match the vendor
    cve_ids = [
        "CVE-2021-44228",
        "CVE-2022-22965",
        "CVE-2022-20698",
        "CVE-2022-48703",
        "CVE-2023-22490",
        "CVE-2024-31331",
        "CVE-2021-34181",
        "CVE-2025-2239",
        "CVE-2025-48543",
    ]
    for cve_id in cve_ids:
        create_cve(cve_id)

    client = auth_client(user)
    response = client.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )
    assert response.status_code == 200
    assert response.context["page_obj"].paginator.num_pages >= 1


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_export_csv_returns_csv(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Export CSV returns 200, text/csv, and contains header + CVE rows."""
    user = create_user()
    org = create_organization(name="org1", user=user)
    create_project(
        name="project1",
        organization=org,
        vendors=["git-scm"],
    )
    create_cve("CVE-2023-22490")
    client = auth_client(user)
    response = client.get(
        reverse(
            "project_vulnerabilities_export_csv",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )
    assert response.status_code == 200
    assert "text/csv" in response["Content-Type"]
    content = b"".join(response.streaming_content).decode("utf-8")
    lines = content.strip().split("\r\n")
    assert len(lines) == 2  # header + 1 CVE
    assert (
        lines[0]
        == "cve_id,title,description,vendors,weaknesses,created_at,updated_at,kev,epss,cvss_v4_0,cvss_v3_1,cvss_v3_0,cvss_v2_0"
    )
    assert (
        lines[1]
        == 'CVE-2023-22490,Git vulnerable to local clone-based data exfiltration with non-local transports,"Git is a revision control system. Using a specially-crafted repository, Git prior to versions 2.39.2, 2.38.4, 2.37.6, 2.36.5, 2.35.7, 2.34.7, 2.33.7, 2.32.6, 2.31.7, and 2.30.8 can be tricked into using its local clone optimization even when using a non-local transport. Though Git will abort local clones whose source `$GIT_DIR/objects` directory contains symbolic links, the `objects` directory itself may still be a symbolic link. These two may be combined to include arbitrary files based on known paths on the victim\'s filesystem within the malicious repository\'s working copy, allowing for data exfiltration in a similar manner as CVE-2022-39253. A fix has been prepared and will appear in v2.39.2 v2.38.4 v2.37.6 v2.36.5 v2.35.7 v2.34.7 v2.33.7 v2.32.6, v2.31.7 and v2.30.8. If upgrading is impractical, two short-term workarounds are available. Avoid cloning repositories from untrusted sources with `--recurse-submodules`. Instead, consider cloning repositories without recursively cloning their submodules, and instead run `git submodule update` at each layer. Before doing so, inspect each new `.gitmodules` file to ensure that it does not contain suspicious module URLs.","git-scm (git), redhat (enterprise_linux, rhel_eus)","CWE-402, CWE-59",2023-02-14T00:00:00Z,2024-08-02T10:13:48Z,false,,,5.5,,'
    )


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_export_csv_redirects_when_over_limit(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """When result count exceeds limit, redirect with error message."""
    user = create_user()
    org = create_organization(name="org1", user=user)
    create_project(
        name="project1",
        organization=org,
        vendors=["git-scm"],
    )
    create_cve("CVE-2023-22490")
    client = auth_client(user)
    with patch("projects.views.CVE_CSV_EXPORT_MAX_ROWS", 0):
        response = client.get(
            reverse(
                "project_vulnerabilities_export_csv",
                kwargs={"org_name": "org1", "project_name": "project1"},
            ),
            follow=False,
        )
    assert response.status_code == 302
    expected_redirect = reverse(
        "project_vulnerabilities",
        kwargs={"org_name": "org1", "project_name": "project1"},
    )
    assert response.url.startswith(expected_redirect)
    response = client.get(
        reverse(
            "project_vulnerabilities_export_csv",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        follow=True,
    )
    messages_list = list(get_messages(response.wsgi_request))

    # First message is "You are now connected to the organization org1."
    assert (
        messages_list[1].message
        == "Export limit exceeded: 1 CVEs match your query. Please refine your search to export 10,000 CVEs or fewer."
    )


@override_settings(ENABLE_ONBOARDING=False)
def test_reports_view_requires_authentication(client):
    """Test that ReportsView requires authentication"""
    response = client.get(
        reverse(
            "reports", kwargs={"org_name": "test-org", "project_name": "test-project"}
        )
    )
    assert response.status_code == 302


@override_settings(ENABLE_ONBOARDING=False)
def test_reports_view_organization_member_access(
    create_organization, create_user, create_project, auth_client
):
    """Test that only organization members can access reports"""
    user1 = create_user()
    org1 = create_organization(name="org1", user=user1)
    project = create_project(name="project1", organization=org1)

    user2 = create_user()
    create_organization(name="org2", user=user2)

    # User1 can access
    client = auth_client(user1)
    response = client.get(
        reverse("reports", kwargs={"org_name": "org1", "project_name": "project1"})
    )
    assert response.status_code == 200

    # User2 cannot access
    client = auth_client(user2)
    response = client.get(
        reverse("reports", kwargs={"org_name": "org1", "project_name": "project1"})
    )
    assert response.status_code == 302
    assert response.url == reverse("list_organizations")


@override_settings(ENABLE_ONBOARDING=False)
def test_reports_view_displays_reports(
    create_organization, create_user, create_project, auth_client
):
    """Test that ReportsView displays project reports"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    report = Report.objects.create(project=project, day=date.today())

    client = auth_client(user)
    response = client.get(
        reverse("reports", kwargs={"org_name": "org1", "project_name": "project1"})
    )
    assert response.status_code == 200
    assert report in response.context["reports"]


@override_settings(ENABLE_ONBOARDING=False)
def test_report_view_requires_authentication(client):
    """Test that ReportView requires authentication"""
    response = client.get(
        reverse(
            "report",
            kwargs={
                "org_name": "test-org",
                "project_name": "test-project",
                "day": date.today(),
            },
        )
    )
    assert response.status_code == 302


@override_settings(ENABLE_ONBOARDING=False)
def test_report_view_organization_member_access(
    create_organization, create_user, create_project, auth_client
):
    """Test that only organization members can access a report"""
    user1 = create_user()
    org1 = create_organization(name="org1", user=user1)
    project = create_project(name="project1", organization=org1)
    report = Report.objects.create(project=project, day=date.today())

    user2 = create_user()
    create_organization(name="org2", user=user2)

    # User1 can access
    client = auth_client(user1)
    response = client.get(
        reverse(
            "report",
            kwargs={
                "org_name": "org1",
                "project_name": "project1",
                "day": date.today(),
            },
        )
    )
    assert response.status_code == 200

    # User2 cannot access
    client = auth_client(user2)
    response = client.get(
        reverse(
            "report",
            kwargs={
                "org_name": "org1",
                "project_name": "project1",
                "day": date.today(),
            },
        )
    )
    assert response.status_code == 302
    assert response.url == reverse("list_organizations")


@override_settings(ENABLE_ONBOARDING=False)
def test_report_view_not_found(
    create_organization, create_user, create_project, auth_client
):
    """Test that ReportView returns 404 for non-existent report"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    create_project(name="project1", organization=org)

    client = auth_client(user)
    response = client.get(
        reverse(
            "report",
            kwargs={
                "org_name": "org1",
                "project_name": "project1",
                "day": date.today() - timedelta(days=1),
            },
        )
    )
    assert response.status_code == 404


@override_settings(ENABLE_ONBOARDING=False)
def test_report_view_statistics(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Test that ReportView returns statistics with report and changes"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    cve = create_cve("CVE-2024-31331")

    # Create a report with a change
    report = Report.objects.create(project=project, day=date.today())
    change = Change.objects.create(
        cve=cve,
        path=f"2024/CVE-2024-31331.json",
        commit="a" * 40,
        types=["created"],
    )
    report.changes.add(change)

    client = auth_client(user)
    response = client.get(
        reverse(
            "report",
            kwargs={
                "org_name": "org1",
                "project_name": "project1",
                "day": date.today(),
            },
        )
    )

    assert response.status_code == 200
    context_object = response.context["object"]
    assert "report" in context_object
    assert "changes" in context_object
    assert context_object["report"] == report

    # Verify changes structure
    changes = list(context_object["changes"])
    assert len(changes) == 1
    change_data = changes[0]
    assert change_data["cve"] == cve
    assert "score" in change_data
    assert "kb_changes" in change_data
    assert isinstance(change_data["kb_changes"], list)


@override_settings(ENABLE_ONBOARDING=False)
def test_subscriptions_view_requires_authentication(client):
    """Test that SubscriptionsView requires authentication"""
    response = client.get(
        reverse(
            "subscriptions",
            kwargs={"org_name": "test-org", "project_name": "test-project"},
        )
    )
    assert response.status_code == 302


@override_settings(ENABLE_ONBOARDING=False)
def test_subscriptions_view_organization_member_access(
    create_organization, create_user, create_project, auth_client
):
    """Test that only organization members can access subscriptions"""
    user1 = create_user()
    org1 = create_organization(name="org1", user=user1)
    project = create_project(name="project1", organization=org1)

    user2 = create_user()
    create_organization(name="org2", user=user2)

    # User1 can access
    client = auth_client(user1)
    response = client.get(
        reverse(
            "subscriptions",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )
    assert response.status_code == 200

    # User2 cannot access
    client = auth_client(user2)
    response = client.get(
        reverse(
            "subscriptions",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )
    assert response.status_code == 302
    assert response.url == reverse("list_organizations")


@override_settings(ENABLE_ONBOARDING=False)
def test_notifications_view_requires_authentication(client):
    """Test that NotificationsView requires authentication"""
    response = client.get(
        reverse(
            "notifications",
            kwargs={"org_name": "test-org", "project_name": "test-project"},
        )
    )
    assert response.status_code == 302


@override_settings(ENABLE_ONBOARDING=False)
def test_notifications_view_organization_member_access(
    create_organization, create_user, create_project, auth_client
):
    """Test that only organization members can access notifications"""
    user1 = create_user()
    org1 = create_organization(name="org1", user=user1)
    project = create_project(name="project1", organization=org1)

    user2 = create_user()
    create_organization(name="org2", user=user2)

    # User1 can access
    client = auth_client(user1)
    response = client.get(
        reverse(
            "notifications",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )
    assert response.status_code == 200

    # User2 cannot access
    client = auth_client(user2)
    response = client.get(
        reverse(
            "notifications",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )
    assert response.status_code == 302
    assert response.url == reverse("list_organizations")


@override_settings(ENABLE_ONBOARDING=False)
def test_notifications_view_displays_notifications(
    create_organization, create_user, create_project, create_notification, auth_client
):
    """Test that NotificationsView displays project notifications"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    notification1 = create_notification(name="notif1", project=project)
    notification2 = create_notification(name="notif2", project=project)

    client = auth_client(user)
    response = client.get(
        reverse(
            "notifications",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )
    assert response.status_code == 200
    notifications = list(response.context["notifications"])
    assert notification1 in notifications
    assert notification2 in notifications


@override_settings(ENABLE_ONBOARDING=False)
def test_notification_create_view_requires_authentication(client):
    """Test that NotificationCreateView requires authentication"""
    response = client.get(
        reverse(
            "create_notification",
            kwargs={"org_name": "test-org", "project_name": "test-project"},
        )
    )
    assert response.status_code == 302


@override_settings(ENABLE_ONBOARDING=False)
def test_notification_create_view_requires_owner(
    create_organization, create_user, create_project, auth_client
):
    """Test that only organization owners can create notifications"""
    user1 = create_user()
    org = create_organization(name="org1", user=user1)
    project = create_project(name="project1", organization=org)

    user2 = create_user()
    Membership.objects.create(
        user=user2,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )

    # Owner can access
    client = auth_client(user1)
    response = client.get(
        reverse(
            "create_notification",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
        + "?type=email",
    )
    assert response.status_code == 200

    # Member cannot access
    client = auth_client(user2)
    response = client.get(
        reverse(
            "create_notification",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
        + "?type=email",
    )
    assert response.status_code == 302
    assert response.url == reverse("list_organizations")


@override_settings(ENABLE_ONBOARDING=False)
def test_notification_create_view_invalid_type(
    create_organization, create_user, create_project, auth_client
):
    """Test that NotificationCreateView requires a valid type"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    create_project(name="project1", organization=org)

    client = auth_client(user)
    response = client.get(
        reverse(
            "create_notification",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
        + "?type=invalid",
    )
    assert response.status_code == 404


@override_settings(
    ENABLE_ONBOARDING=False,
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
)
def test_notification_create_view_email(
    create_organization, create_user, create_project, auth_client
):
    """Test creating an email notification: disabled until confirmed, sends confirmation email."""
    user = create_user(email="owner@example.com")
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)

    from django.core.mail import outbox

    outbox.clear()

    client = auth_client(user)
    response = client.post(
        reverse(
            "create_notification",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
        + "?type=email",
        data={
            "name": "my-email-notif",
            "email": "test@example.com",
            "cvss31_score": 7,
            "created": True,
        },
        follow=True,
    )

    assert response.status_code == 200
    assert Notification.objects.filter(name="my-email-notif", project=project).exists()

    notification = Notification.objects.get(name="my-email-notif", project=project)
    assert notification.type == "email"
    assert notification.is_enabled is False
    assert "extras" in notification.configuration
    assert notification.configuration["extras"]["email"] == "test@example.com"
    assert (
        notification.configuration["extras"]["created_by_email"] == "owner@example.com"
    )
    assert "confirmation_token" in notification.configuration["extras"]
    assert "unsubscribe_token" not in notification.configuration["extras"]

    assert len(outbox) == 1
    assert outbox[0].to == ["test@example.com"]
    assert "Notification subscription confirmation" in outbox[0].subject
    assert "owner@example.com" in outbox[0].body
    assert "notifications/confirm/" in outbox[0].body


@override_settings(ENABLE_ONBOARDING=False)
def test_notification_create_view_webhook_and_slack_enabled_without_tokens(
    create_organization, create_user, create_project, auth_client
):
    """Webhook and Slack notifications are created enabled and have no confirmation/unsubscribe tokens."""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)

    client = auth_client(user)
    base_url = reverse(
        "create_notification",
        kwargs={"org_name": "org1", "project_name": "project1"},
    )
    common_data = {"cvss31_score": 5, "created": True}

    response_webhook = client.post(
        base_url + "?type=webhook",
        data={
            "name": "my-webhook-notif",
            "url": "https://example.com/webhook",
            "headers": "{}",
            **common_data,
        },
        follow=True,
    )
    assert response_webhook.status_code == 200
    notif_webhook = Notification.objects.get(name="my-webhook-notif", project=project)
    assert notif_webhook.type == "webhook"
    assert notif_webhook.is_enabled is True
    extras_webhook = notif_webhook.configuration.get("extras", {})
    assert "confirmation_token" not in extras_webhook
    assert "unsubscribe_token" not in extras_webhook

    response_slack = client.post(
        base_url + "?type=slack",
        data={
            "name": "my-slack-notif",
            "webhook_url": "https://hooks.slack.com/services/T00/B00/xxx",
            **common_data,
        },
        follow=True,
    )
    assert response_slack.status_code == 200
    notif_slack = Notification.objects.get(name="my-slack-notif", project=project)
    assert notif_slack.type == "slack"
    assert notif_slack.is_enabled is True
    extras_slack = notif_slack.configuration.get("extras", {})
    assert "confirmation_token" not in extras_slack
    assert "unsubscribe_token" not in extras_slack


@override_settings(ENABLE_ONBOARDING=False)
def test_notification_update_view_requires_authentication(client):
    """Test that NotificationUpdateView requires authentication"""
    response = client.get(
        reverse(
            "edit_notification",
            kwargs={
                "org_name": "test-org",
                "project_name": "test-project",
                "notification": "test-notif",
            },
        )
    )
    assert response.status_code == 302


@override_settings(ENABLE_ONBOARDING=False)
def test_notification_update_view_requires_owner(
    create_organization, create_user, create_project, create_notification, auth_client
):
    """Test that only organization owners can update notifications"""
    user1 = create_user()
    org = create_organization(name="org1", user=user1)
    project = create_project(name="project1", organization=org)
    notification = create_notification(
        name="notif1",
        project=project,
        type="email",
        configuration={
            "types": [],
            "metrics": {"cvss31": 0},
            "extras": {"email": "test@example.com"},
        },
    )

    user2 = create_user()
    Membership.objects.create(
        user=user2,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )

    # Owner can access
    client = auth_client(user1)
    response = client.get(
        reverse(
            "edit_notification",
            kwargs={
                "org_name": "org1",
                "project_name": "project1",
                "notification": "notif1",
            },
        )
    )
    assert response.status_code == 200

    # Member cannot access
    client = auth_client(user2)
    response = client.get(
        reverse(
            "edit_notification",
            kwargs={
                "org_name": "org1",
                "project_name": "project1",
                "notification": "notif1",
            },
        )
    )
    assert response.status_code == 302
    assert response.url == reverse("list_organizations")


@override_settings(ENABLE_ONBOARDING=False)
def test_notification_update_view_valid_form(
    create_organization, create_user, create_project, create_notification, auth_client
):
    """Test updating a notification with valid form data; preserves created_by_email and unsubscribe_token."""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    notification = create_notification(
        name="notif1",
        project=project,
        type="email",
        configuration={
            "types": ["created"],
            "metrics": {"cvss31": 5},
            "extras": {
                "email": "old@example.com",
                "created_by_email": "creator@example.com",
                "unsubscribe_token": "some-unsubscribe-token",
            },
        },
    )

    client = auth_client(user)
    response = client.post(
        reverse(
            "edit_notification",
            kwargs={
                "org_name": "org1",
                "project_name": "project1",
                "notification": "notif1",
            },
        ),
        data={
            "name": "notif1",
            "email": "old@example.com",
            "cvss31_score": 7,
        },
        follow=True,
    )

    assert response.status_code == 200
    notification.refresh_from_db()
    assert notification.configuration["extras"]["email"] == "old@example.com"
    assert notification.configuration["metrics"]["cvss31"] == "7"
    assert (
        notification.configuration["extras"]["created_by_email"]
        == "creator@example.com"
    )
    assert (
        notification.configuration["extras"]["unsubscribe_token"]
        == "some-unsubscribe-token"
    )


@override_settings(ENABLE_ONBOARDING=False)
def test_notification_resend_confirmation_view_requires_authentication(db, client):
    """Require authentication."""
    response = client.get(
        reverse(
            "resend_notification_confirmation",
            kwargs={
                "org_name": "test-org",
                "project_name": "test-project",
                "notification": "test-notif",
            },
        ),
        follow=True,
    )
    assert response.status_code == 200
    assert response.redirect_chain == [
        (
            reverse("account_login")
            + "?next="
            + reverse(
                "resend_notification_confirmation",
                kwargs={
                    "org_name": "test-org",
                    "project_name": "test-project",
                    "notification": "test-notif",
                },
            ),
            302,
        )
    ]


@override_settings(
    ENABLE_ONBOARDING=False,
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
)
def test_notification_resend_confirmation_view_sends_email(
    create_organization, create_user, create_project, create_notification, auth_client
):
    """Send confirmation email and redirect with success message."""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    create_notification(
        name="notif1",
        project=project,
        type="email",
        is_enabled=False,
        configuration={
            "types": ["created"],
            "metrics": {"cvss31": "5"},
            "extras": {
                "email": "recipient@example.com",
                "created_by_email": "owner@example.com",
                "confirmation_token": "resend-test-token",
            },
        },
    )

    from django.core.mail import outbox

    outbox.clear()
    client = auth_client(user)
    response = client.get(
        reverse(
            "resend_notification_confirmation",
            kwargs={
                "org_name": "org1",
                "project_name": "project1",
                "notification": "notif1",
            },
        ),
        follow=True,
    )

    assert response.status_code == 200
    assert response.redirect_chain[-1][0] == reverse(
        "edit_notification",
        kwargs={
            "org_name": "org1",
            "project_name": "project1",
            "notification": "notif1",
        },
    )
    assert len(outbox) == 1
    assert outbox[0].to == ["recipient@example.com"]
    assert "confirmation" in outbox[0].subject.lower()
    assert "resend-test-token" in outbox[0].body
    messages = list(get_messages(response.wsgi_request))
    assert any("new confirmation email" in str(m).lower() for m in messages)
    assert any("recipient@example.com" in str(m) for m in messages)


@override_settings(ENABLE_ONBOARDING=False)
def test_notification_resend_confirmation_view_not_email_type(
    create_organization, create_user, create_project, create_notification, auth_client
):
    """Return error when notification is not email type."""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    create_notification(
        name="notif1",
        project=project,
        type="webhook",
        configuration={
            "types": [],
            "metrics": {"cvss31": "0"},
            "extras": {
                "url": "https://example.com/hook",
                "headers": {},
            },
        },
    )

    from django.core.mail import outbox

    outbox.clear()
    client = auth_client(user)
    response = client.get(
        reverse(
            "resend_notification_confirmation",
            kwargs={
                "org_name": "org1",
                "project_name": "project1",
                "notification": "notif1",
            },
        ),
        follow=True,
    )

    assert response.status_code == 200
    assert len(outbox) == 0
    messages = list(get_messages(response.wsgi_request))
    assert any("not an email notification" in str(m).lower() for m in messages)


@override_settings(
    ENABLE_ONBOARDING=False,
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
)
def test_notification_resend_confirmation_view_already_confirmed(
    create_organization, create_user, create_project, create_notification, auth_client
):
    """Do not send email when notification is already confirmed."""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    create_notification(
        name="notif1",
        project=project,
        type="email",
        is_enabled=True,
        configuration={
            "types": ["created"],
            "metrics": {"cvss31": "5"},
            "extras": {
                "email": "recipient@example.com",
                "unsubscribe_token": "unsub-token",
            },
        },
    )

    from django.core.mail import outbox

    outbox.clear()
    client = auth_client(user)
    response = client.get(
        reverse(
            "resend_notification_confirmation",
            kwargs={
                "org_name": "org1",
                "project_name": "project1",
                "notification": "notif1",
            },
        ),
        follow=True,
    )

    assert response.status_code == 200
    assert len(outbox) == 0
    messages = list(get_messages(response.wsgi_request))
    assert any("already confirmed" in str(m).lower() for m in messages)


def test_notification_confirm_view_valid_token(
    create_organization, create_user, create_project, create_notification, client
):
    """NotificationConfirmView: valid token enables the notification and removes confirmation_token."""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    notification = create_notification(
        name="notif1",
        project=project,
        type="email",
        is_enabled=False,
        configuration={
            "types": ["created"],
            "metrics": {"cvss31": "5"},
            "extras": {
                "email": "target@example.com",
                "confirmation_token": "valid-confirm-token",
            },
        },
    )

    response = client.get(
        reverse("notification_confirm", kwargs={"token": "valid-confirm-token"})
    )

    assert response.status_code == 200
    notification.refresh_from_db()
    assert notification.is_enabled is True

    # confirmation_token has been removed
    assert "confirmation_token" not in notification.configuration.get("extras", {})

    # unsubscribe_token has been created
    assert "unsubscribe_token" in notification.configuration.get("extras", {})


@pytest.mark.django_db
def test_notification_confirm_view_invalid_token(client):
    """NotificationConfirmView: invalid token returns 404."""
    response = client.get(
        reverse("notification_confirm", kwargs={"token": "invalid-token"})
    )
    assert response.status_code == 404


def test_notification_confirm_view_accessible_without_authentication(
    create_organization, create_user, create_project, create_notification, client
):
    """NotificationConfirmView: confirm URL is accessible without authentication."""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    create_notification(
        name="notif1",
        project=project,
        type="email",
        is_enabled=False,
        configuration={
            "types": ["created"],
            "metrics": {"cvss31": "5"},
            "extras": {
                "email": "target@example.com",
                "confirmation_token": "public-confirm-token",
                "unsubscribe_token": "unsub-token",
            },
        },
    )

    response = client.get(
        reverse(
            "notification_confirm",
            kwargs={"token": "public-confirm-token"},
        )
    )

    assert response.status_code == 200


def test_notification_unsubscribe_view_valid_token(
    create_organization, create_user, create_project, create_notification, client
):
    """NotificationUnsubscribeView: valid token disables the notification (on POST)."""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    notification = create_notification(
        name="notif1",
        project=project,
        type="email",
        is_enabled=True,
        configuration={
            "types": ["created"],
            "metrics": {"cvss31": "5"},
            "extras": {
                "email": "target@example.com",
                "unsubscribe_token": "valid-unsub-token",
            },
        },
    )

    response = client.post(
        reverse("notification_unsubscribe", kwargs={"token": "valid-unsub-token"})
    )

    assert response.status_code == 200
    notification.refresh_from_db()
    assert notification.is_enabled is False

    # unsubscribe_token has been removed
    assert "unsubscribe_token" not in notification.configuration.get("extras", {})

    # confirmation_token has been created
    assert "confirmation_token" in notification.configuration.get("extras", {})


@pytest.mark.django_db
def test_notification_unsubscribe_view_invalid_token(client):
    """NotificationUnsubscribeView: invalid token returns 404."""
    response = client.get(
        reverse("notification_unsubscribe", kwargs={"token": "invalid-token"})
    )
    assert response.status_code == 404


def test_notification_unsubscribe_view_accessible_without_authentication(
    create_organization, create_user, create_project, create_notification, client
):
    """NotificationUnsubscribeView: unsubscribe URL (GET and POST) is accessible without authentication."""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    create_notification(
        name="notif1",
        project=project,
        type="email",
        is_enabled=True,
        configuration={
            "types": ["created"],
            "metrics": {"cvss31": "5"},
            "extras": {
                "email": "target@example.com",
                "unsubscribe_token": "public-unsub-token",
            },
        },
    )

    url = reverse(
        "notification_unsubscribe",
        kwargs={"token": "public-unsub-token"},
    )

    get_response = client.get(url)
    assert get_response.status_code == 200

    post_response = client.post(url)
    assert post_response.status_code == 200


@override_settings(ENABLE_ONBOARDING=False)
def test_notification_delete_view_requires_authentication(client):
    """Test that NotificationDeleteView requires authentication"""
    response = client.get(
        reverse(
            "delete_notification",
            kwargs={
                "org_name": "test-org",
                "project_name": "test-project",
                "notification": "test-notif",
            },
        )
    )
    assert response.status_code == 302


@override_settings(ENABLE_ONBOARDING=False)
def test_notification_delete_view_requires_owner(
    create_organization, create_user, create_project, create_notification, auth_client
):
    """Test that only organization owners can delete notifications"""
    user1 = create_user()
    org = create_organization(name="org1", user=user1)
    project = create_project(name="project1", organization=org)
    notification = create_notification(name="notif1", project=project)

    user2 = create_user()
    Membership.objects.create(
        user=user2,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )

    # Owner can access
    client = auth_client(user1)
    response = client.get(
        reverse(
            "delete_notification",
            kwargs={
                "org_name": "org1",
                "project_name": "project1",
                "notification": "notif1",
            },
        )
    )
    assert response.status_code == 200

    # Member cannot access
    client = auth_client(user2)
    response = client.get(
        reverse(
            "delete_notification",
            kwargs={
                "org_name": "org1",
                "project_name": "project1",
                "notification": "notif1",
            },
        )
    )
    assert response.status_code == 302
    assert response.url == reverse("list_organizations")


@override_settings(ENABLE_ONBOARDING=False)
def test_notification_delete_view_deletes_notification(
    create_organization, create_user, create_project, create_notification, auth_client
):
    """Test that deleting a notification actually deletes it"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    notification = create_notification(name="notif1", project=project)

    client = auth_client(user)
    response = client.post(
        reverse(
            "delete_notification",
            kwargs={
                "org_name": "org1",
                "project_name": "project1",
                "notification": "notif1",
            },
        ),
        follow=True,
    )

    assert response.status_code == 200
    assert not Notification.objects.filter(id=notification.id).exists()

    # Check success message
    messages = list(get_messages(response.wsgi_request))
    assert any("removed" in str(m) for m in messages)


@override_settings(ENABLE_ONBOARDING=False)
def test_assign_cve_user_view_requires_authentication(client):
    """Test that AssignCveUserView requires authentication"""
    response = client.post(
        reverse(
            "assign_cve_user",
            kwargs={"org_name": "test-org", "project_name": "test-project"},
        ),
        content_type="application/json",
        data=json.dumps({"cve_id": "CVE-2023-22490", "assignee_id": None}),
    )
    assert response.status_code == 302


@override_settings(ENABLE_ONBOARDING=False)
def test_assign_cve_user_view_organization_member_access(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Test that only organization members can assign CVEs"""
    user1 = create_user()
    org1 = create_organization(name="org1", user=user1)
    project = create_project(name="project1", organization=org1)
    cve = create_cve("CVE-2023-22490")

    user2 = create_user()
    create_organization(name="org2", user=user2)

    # User1 can assign
    client = auth_client(user1)
    response = client.post(
        reverse(
            "assign_cve_user",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        content_type="application/json",
        data=json.dumps({"cve_id": "CVE-2023-22490", "assignee_id": None}),
    )
    assert response.status_code == 200

    # User2 cannot assign
    client = auth_client(user2)
    response = client.post(
        reverse(
            "assign_cve_user",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        content_type="application/json",
        data=json.dumps({"cve_id": "CVE-2023-22490", "assignee_id": None}),
    )
    assert response.status_code == 302
    assert response.url == reverse("list_organizations")


@override_settings(ENABLE_ONBOARDING=False)
def test_assign_cve_user_view_assign_user(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Test assigning a user to a CVE"""
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")
    org = create_organization(name="org1", user=user1)
    Membership.objects.create(
        user=user2,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project = create_project(name="project1", organization=org)
    cve = create_cve("CVE-2023-22490")

    client = auth_client(user1)
    response = client.post(
        reverse(
            "assign_cve_user",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        content_type="application/json",
        data=json.dumps({"cve_id": "CVE-2023-22490", "assignee_id": str(user2.id)}),
    )

    assert response.status_code == 200
    data = json.loads(response.content)
    assert data["success"] is True
    assert data["assignee_username"] == "user2"

    # Verify tracker was created
    tracker = CveTracker.objects.get(project=project, cve=cve)
    assert tracker.assignee == user2


@override_settings(ENABLE_ONBOARDING=False)
def test_assign_cve_user_view_clear_assignee(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Test clearing an assignee from a CVE"""
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")
    org = create_organization(name="org1", user=user1)
    Membership.objects.create(
        user=user2,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project = create_project(name="project1", organization=org)
    cve = create_cve("CVE-2023-22490")

    # First assign
    CveTracker.update_tracker(project=project, cve=cve, assignee=user2)

    client = auth_client(user1)
    response = client.post(
        reverse(
            "assign_cve_user",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        content_type="application/json",
        data=json.dumps({"cve_id": "CVE-2023-22490", "assignee_id": None}),
    )

    assert response.status_code == 200
    data = json.loads(response.content)
    assert data["success"] is True
    assert data["assignee_username"] is None

    # Verify tracker was deleted (no status, no assignee)
    assert not CveTracker.objects.filter(project=project, cve=cve).exists()


@override_settings(ENABLE_ONBOARDING=False)
def test_assign_cve_user_view_invalid_cve(
    create_organization, create_user, create_project, auth_client
):
    """Test assigning to a non-existent CVE"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    create_project(name="project1", organization=org)

    client = auth_client(user)
    response = client.post(
        reverse(
            "assign_cve_user",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        content_type="application/json",
        data=json.dumps({"cve_id": "CVE-9999-99999", "assignee_id": None}),
    )

    assert response.status_code == 404


@override_settings(ENABLE_ONBOARDING=False)
def test_assign_cve_user_view_invalid_assignee(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Test assigning to a user from a different organization"""
    user1 = create_user()
    org1 = create_organization(name="org1", user=user1)
    project = create_project(name="project1", organization=org1)
    cve = create_cve("CVE-2023-22490")

    user2 = create_user()
    create_organization(name="org2", user=user2)

    client = auth_client(user1)
    response = client.post(
        reverse(
            "assign_cve_user",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        content_type="application/json",
        data=json.dumps({"cve_id": "CVE-2023-22490", "assignee_id": str(user2.id)}),
    )
    assert response.status_code == 404


@override_settings(ENABLE_ONBOARDING=False)
def test_assign_cve_user_view_invalid_json(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Test assigning with invalid JSON payload"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    cve = create_cve("CVE-2023-22490")

    client = auth_client(user)
    response = client.post(
        reverse(
            "assign_cve_user",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        content_type="application/json",
        data="invalid json{",
    )

    assert response.status_code == 400
    data = json.loads(response.content)
    assert data["success"] is False
    assert "Invalid JSON payload" in data["error"]


@override_settings(ENABLE_ONBOARDING=False)
def test_assign_cve_user_view_unjoined_assignee(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Test assigning to a user who hasn't joined the organization yet"""
    user1 = create_user()
    org = create_organization(name="org1", user=user1)
    project = create_project(name="project1", organization=org)
    cve = create_cve("CVE-2023-22490")

    # Create membership but don't set date_joined (user hasn't accepted invitation)
    user2 = create_user()
    Membership.objects.create(
        user=user2,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=None,
    )

    client = auth_client(user1)
    response = client.post(
        reverse(
            "assign_cve_user",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        content_type="application/json",
        data=json.dumps({"cve_id": "CVE-2023-22490", "assignee_id": str(user2.id)}),
    )

    assert response.status_code == 404


@override_settings(ENABLE_ONBOARDING=False)
def test_update_cve_status_view_requires_authentication(client):
    """Test that UpdateCveStatusView requires authentication"""
    response = client.post(
        reverse(
            "update_cve_status",
            kwargs={"org_name": "test-org", "project_name": "test-project"},
        ),
        content_type="application/json",
        data=json.dumps({"cve_id": "CVE-2023-22490", "status": "to_evaluate"}),
    )
    assert response.status_code == 302


@override_settings(ENABLE_ONBOARDING=False)
def test_update_cve_status_view_organization_member_access(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Test that only organization members can update CVE status"""
    user1 = create_user()
    org1 = create_organization(name="org1", user=user1)
    project = create_project(name="project1", organization=org1)
    cve = create_cve("CVE-2023-22490")

    user2 = create_user()
    create_organization(name="org2", user=user2)

    # User1 can update
    client = auth_client(user1)
    response = client.post(
        reverse(
            "update_cve_status",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        content_type="application/json",
        data=json.dumps({"cve_id": "CVE-2023-22490", "status": "to_evaluate"}),
    )
    assert response.status_code == 200

    # User2 cannot update
    client = auth_client(user2)
    response = client.post(
        reverse(
            "update_cve_status",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        content_type="application/json",
        data=json.dumps({"cve_id": "CVE-2023-22490", "status": "to_evaluate"}),
    )
    assert response.status_code == 302
    assert response.url == reverse("list_organizations")


@override_settings(ENABLE_ONBOARDING=False)
def test_update_cve_status_view_set_status(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Test setting a status on a CVE"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    cve = create_cve("CVE-2023-22490")

    client = auth_client(user)
    response = client.post(
        reverse(
            "update_cve_status",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        content_type="application/json",
        data=json.dumps({"cve_id": "CVE-2023-22490", "status": "to_evaluate"}),
    )

    assert response.status_code == 200
    data = json.loads(response.content)
    assert data["success"] is True
    assert data["status"] == "To evaluate"

    # Verify tracker was created
    tracker = CveTracker.objects.get(project=project, cve=cve)
    assert tracker.status == "to_evaluate"


@override_settings(ENABLE_ONBOARDING=False)
def test_update_cve_status_view_clear_status(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Test clearing a status from a CVE"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    cve = create_cve("CVE-2023-22490")

    # First set status
    CveTracker.update_tracker(project=project, cve=cve, status="to_evaluate")

    client = auth_client(user)
    response = client.post(
        reverse(
            "update_cve_status",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        content_type="application/json",
        data=json.dumps({"cve_id": "CVE-2023-22490", "status": ""}),
    )

    assert response.status_code == 200
    data = json.loads(response.content)
    assert data["success"] is True
    assert data["status"] is None

    # Verify tracker was deleted (no status, no assignee)
    assert not CveTracker.objects.filter(project=project, cve=cve).exists()


@override_settings(ENABLE_ONBOARDING=False)
def test_update_cve_status_view_invalid_status(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Test updating with an invalid status"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    create_project(name="project1", organization=org)
    cve = create_cve("CVE-2023-22490")

    client = auth_client(user)
    response = client.post(
        reverse(
            "update_cve_status",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        content_type="application/json",
        data=json.dumps({"cve_id": "CVE-2023-22490", "status": "invalid_status"}),
    )

    assert response.status_code == 400
    data = json.loads(response.content)
    assert data["success"] is False
    assert "Invalid status" in data["error"]


@override_settings(ENABLE_ONBOARDING=False)
def test_update_cve_status_view_invalid_cve(
    create_organization, create_user, create_project, auth_client
):
    """Test updating status for a non-existent CVE"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    create_project(name="project1", organization=org)

    client = auth_client(user)
    response = client.post(
        reverse(
            "update_cve_status",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        content_type="application/json",
        data=json.dumps({"cve_id": "CVE-9999-99999", "status": "to_evaluate"}),
    )

    assert response.status_code == 404


@override_settings(ENABLE_ONBOARDING=False)
def test_update_cve_status_view_all_valid_statuses(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Test that all valid status choices can be set"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)

    valid_statuses = [
        "to_evaluate",
        "pending_review",
        "analysis_in_progress",
        "remediation_in_progress",
        "evaluated",
        "resolved",
        "not_applicable",
        "risk_accepted",
    ]

    cve_ids = [
        "CVE-2021-34181",
        "CVE-2021-44228",
        "CVE-2022-20698",
        "CVE-2022-22965",
        "CVE-2022-48703",
        "CVE-2023-22490",
        "CVE-2024-31331",
        "CVE-2025-2239",
    ]

    client = auth_client(user)

    for status, cve_id in zip(valid_statuses, cve_ids):
        cve = create_cve(cve_id)
        response = client.post(
            reverse(
                "update_cve_status",
                kwargs={"org_name": "org1", "project_name": "project1"},
            ),
            content_type="application/json",
            data=json.dumps({"cve_id": cve_id, "status": status}),
        )

        assert response.status_code == 200
        data = json.loads(response.content)
        assert data["success"] is True

        # Verify tracker was created with correct status
        tracker = CveTracker.objects.get(project=project, cve=cve)
        assert tracker.status == status


@override_settings(ENABLE_ONBOARDING=False)
def test_update_cve_status_view_invalid_json(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Test updating status with invalid JSON payload"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)
    cve = create_cve("CVE-2023-22490")

    client = auth_client(user)
    response = client.post(
        reverse(
            "update_cve_status",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        content_type="application/json",
        data="invalid json{",
    )

    assert response.status_code == 400
    data = json.loads(response.content)
    assert data["success"] is False
    assert "Invalid JSON payload" in data["error"]


@override_settings(ENABLE_ONBOARDING=False)
def test_apply_search_query_empty_query(
    create_organization, create_user, create_project, create_cve
):
    """Test that _apply_search_query returns base_queryset when query is empty"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org, vendors=["git-scm"])
    cve = create_cve("CVE-2023-22490")  # git-scm vendor

    rf = RequestFactory()
    request = rf.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )
    request.user = user
    request.current_organization = org

    view = ProjectVulnerabilitiesView()
    view.request = request
    view.project = project

    # Create base queryset
    base_queryset = Cve.objects.filter(vendors__has_any_keys=["git-scm"])

    # Test with empty query
    result = view._apply_search_query(base_queryset, "")
    assert result == base_queryset

    # Test with None query
    result = view._apply_search_query(base_queryset, None)
    assert result == base_queryset


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_apply_search_query_valid_query(
    create_organization, create_user, create_project, create_cve
):
    """Test that _apply_search_query applies valid query correctly"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org, vendors=["git-scm"])
    cve1 = create_cve("CVE-2023-22490")  # git-scm vendor
    cve2 = create_cve("CVE-2021-44228")  # apache vendor (not subscribed)

    rf = RequestFactory()
    request = rf.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )
    request.user = user
    request.current_organization = org

    view = ProjectVulnerabilitiesView()
    view.request = request
    view.project = project

    # Create base queryset
    base_queryset = Cve.objects.filter(vendors__has_any_keys=["git-scm"])

    # Test with valid queries
    result = view._apply_search_query(base_queryset, "cve:CVE-2023-22490")
    assert cve1 in result
    assert cve2 not in result

    result = view._apply_search_query(base_queryset, "cve:CVE-2021-44228")
    assert cve1 not in result
    assert cve2 not in result


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_apply_search_query_invalid_parse_exception(
    create_organization, create_user, create_project, create_cve
):
    """Test that _apply_search_query returns base_queryset on ParseException"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org, vendors=["git-scm"])
    cve = create_cve("CVE-2023-22490")

    rf = RequestFactory()
    request = rf.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )
    request.user = user
    request.current_organization = org

    view = ProjectVulnerabilitiesView()
    view.request = request
    view.project = project

    base_queryset = Cve.objects.filter(vendors__has_any_keys=["git-scm"])

    # Test with invalid syntax that causes ParseException
    result = view._apply_search_query(base_queryset, "invalid(syntax")
    assert result == base_queryset


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_apply_search_query_bad_query_exception(
    create_organization, create_user, create_project, create_cve
):
    """Test that _apply_search_query returns base_queryset on BadQueryException"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org, vendors=["git-scm"])
    cve = create_cve("CVE-2023-22490")

    rf = RequestFactory()
    request = rf.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )
    request.user = user
    request.current_organization = org

    view = ProjectVulnerabilitiesView()
    view.request = request
    view.project = project

    base_queryset = Cve.objects.filter(vendors__has_any_keys=["git-scm"])

    # Mock Search to raise BadQueryException
    with patch("projects.views.Search") as mock_search:
        mock_instance = Mock()
        mock_instance.validate_parsing.return_value = True
        type(mock_instance).query = PropertyMock(
            side_effect=BadQueryException("Invalid field")
        )
        mock_search.return_value = mock_instance

        result = view._apply_search_query(base_queryset, "invalidField:value")
        assert result == base_queryset


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_apply_search_query_max_fields_exceeded_exception(
    create_organization, create_user, create_project, create_cve
):
    """Test that _apply_search_query returns base_queryset on MaxFieldsExceededException"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org, vendors=["git-scm"])
    cve = create_cve("CVE-2023-22490")

    rf = RequestFactory()
    request = rf.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )
    request.user = user
    request.current_organization = org

    view = ProjectVulnerabilitiesView()
    view.request = request
    view.project = project

    base_queryset = Cve.objects.filter(vendors__has_any_keys=["git-scm"])

    # Mock Search to raise MaxFieldsExceededException
    with patch("projects.views.Search") as mock_search:
        mock_instance = Mock()
        mock_instance.validate_parsing.return_value = True
        type(mock_instance).query = PropertyMock(
            side_effect=MaxFieldsExceededException("Too many fields")
        )
        mock_search.return_value = mock_instance

        result = view._apply_search_query(base_queryset, "cvss31>=7 AND cvss31>=8")
        assert result == base_queryset


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_apply_search_query_validation_fails(
    create_organization, create_user, create_project, create_cve
):
    """Test that _apply_search_query returns base_queryset when validation fails"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org, vendors=["git-scm"])
    cve = create_cve("CVE-2023-22490")

    rf = RequestFactory()
    request = rf.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )
    request.user = user
    request.current_organization = org

    view = ProjectVulnerabilitiesView()
    view.request = request
    view.project = project

    base_queryset = Cve.objects.filter(vendors__has_any_keys=["git-scm"])

    # Mock Search to return False for validate_parsing
    with patch("projects.views.Search") as mock_search:
        mock_instance = Mock()
        mock_instance.validate_parsing.return_value = False
        mock_search.return_value = mock_instance

        result = view._apply_search_query(base_queryset, "some query")
        assert result == base_queryset


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_get_context_data_basic_context(
    create_organization, create_user, create_project, auth_client
):
    """Test that get_context_data returns all required context variables"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org, vendors=["git-scm"])

    client = auth_client(user)
    response = client.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )

    assert response.status_code == 200
    context = response.context

    # Check basic context variables
    assert "project" in context
    assert context["project"] == project
    assert "filter_form" in context
    assert "organization_members" in context
    assert "status_choices" in context
    assert "views_data" in context
    assert context["status_choices"] == CveTracker.STATUS_CHOICES
    members = list(context["organization_members"])
    assert user in members


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_get_context_data_organization_members_filtering(
    create_organization, create_user, create_project, auth_client
):
    """Test that organization_members only includes users who have joined"""
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")
    user3 = create_user(username="user3")
    org = create_organization(name="org1", user=user1)

    # User2 has joined
    Membership.objects.create(
        user=user2,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )

    # User3 has been invited but hasn't joined yet
    Membership.objects.create(
        user=user3,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=None,
    )

    project = create_project(name="project1", organization=org)

    client = auth_client(user1)
    response = client.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )

    assert response.status_code == 200
    members = list(response.context["organization_members"])
    usernames = [m.username for m in members]

    # Should include user1 (owner) and user2 (joined member)
    assert "user1" in usernames
    assert "user2" in usernames
    # Should NOT include user3 (not joined)
    assert "user3" not in usernames


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_get_context_data_views_data_public_and_private(
    create_organization, create_user, create_project, create_view, auth_client
):
    """Test that views_data includes both public and user's private views"""
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")
    org = create_organization(name="org1", user=user1)
    Membership.objects.create(
        user=user2,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )

    project = create_project(name="project1", organization=org)

    # Create public view
    public_view = create_view(
        name="Public View",
        query="cvss31>=7",
        organization=org,
        privacy="public",
    )

    # Create private view for user1
    private_view_user1 = create_view(
        name="Private View User1",
        query="cvss31>=8",
        organization=org,
        privacy="private",
        user=user1,
    )

    # Create private view for user2 (should not appear for user1)
    private_view_user2 = create_view(
        name="Private View User2",
        query="cvss31>=9",
        organization=org,
        privacy="private",
        user=user2,
    )

    client = auth_client(user1)
    response = client.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )

    assert response.status_code == 200
    views_data = response.context["views_data"]
    view_ids = [v["id"] for v in views_data]
    view_names = [v["name"] for v in views_data]

    # Should include public view
    assert str(public_view.id) in view_ids
    assert "Public View" in view_names

    # Should include user1's private view
    assert str(private_view_user1.id) in view_ids
    assert "Private View User1" in view_names

    # Should NOT include user2's private view
    assert str(private_view_user2.id) not in view_ids
    assert "Private View User2" not in view_names


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_get_context_data_filter_form_with_valid_query(
    create_organization, create_user, create_project, auth_client
):
    """Test that filter_form is created correctly with valid query"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org, vendors=["git-scm"])

    client = auth_client(user)
    response = client.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        data={"query": "cve:CVE-2023-22490"},
    )

    assert response.status_code == 200
    filter_form = response.context["filter_form"]
    assert filter_form is not None
    # Valid query should not have errors
    assert not filter_form.errors


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_get_context_data_filter_form_with_invalid_query(
    create_organization, create_user, create_project, auth_client
):
    """Test that filter_form has errors with invalid query"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org, vendors=["git-scm"])

    client = auth_client(user)
    response = client.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        data={"query": "invalid(syntax"},
    )

    assert response.status_code == 200
    filter_form = response.context["filter_form"]
    assert filter_form is not None
    # Invalid query should have errors
    assert "query" in filter_form.errors
    assert filter_form.errors["query"] == ["Invalid query syntax."]


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_get_context_data_filter_form_with_bad_query_exception(
    create_organization, create_user, create_project, auth_client
):
    """Test that filter_form handles BadQueryException"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org, vendors=["git-scm"])

    client = auth_client(user)
    # Use a query that might trigger BadQueryException
    response = client.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        data={"query": "invalidField:value"},
    )

    assert response.status_code == 200
    filter_form = response.context["filter_form"]
    assert hasattr(filter_form, "errors")
    assert filter_form.errors["query"][0].startswith(
        "The field 'invalidField' is not valid"
    )


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_get_context_data_filter_form_with_empty_query(
    create_organization, create_user, create_project, auth_client
):
    """Test that filter_form works correctly with empty query"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org, vendors=["git-scm"])

    client = auth_client(user)
    response = client.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        data={"query": ""},
    )

    assert response.status_code == 200
    filter_form = response.context["filter_form"]
    assert filter_form is not None
    assert not filter_form.errors


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_get_context_data_views_data_ordered_by_name(
    create_organization, create_user, create_project, create_view, auth_client
):
    """Test that views_data is ordered by name"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)

    # Create views in non-alphabetical order
    view_c = create_view(
        name="C View", query="cvss31>=7", organization=org, privacy="public"
    )
    view_a = create_view(
        name="A View", query="cvss31>=8", organization=org, privacy="public"
    )
    view_b = create_view(
        name="B View", query="cvss31>=9", organization=org, privacy="public"
    )

    client = auth_client(user)
    response = client.get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )

    assert response.status_code == 200
    views_data = response.context["views_data"]
    view_names = [v["name"] for v in views_data]
    assert view_names == ["A View", "B View", "C View"]
