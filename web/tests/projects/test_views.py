import json
from datetime import date, timedelta

from django.contrib.messages import get_messages
from django.test import override_settings
from django.urls import reverse
from django.utils.timezone import now

from changes.models import Change, Report
from organizations.models import Membership
from projects.models import CveTracker, Notification, Project


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


@override_settings(ENABLE_ONBOARDING=False)
def test_notification_create_view_email(
    create_organization, create_user, create_project, auth_client
):
    """Test creating an email notification"""
    user = create_user()
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)

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
    assert "extras" in notification.configuration
    assert notification.configuration["extras"]["email"] == "test@example.com"


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
    """Test updating a notification with valid form data"""
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
            "extras": {"email": "old@example.com"},
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
            "email": "new@example.com",
            "cvss31_score": 7,
        },
        follow=True,
    )

    assert response.status_code == 200
    notification.refresh_from_db()
    assert notification.configuration["extras"]["email"] == "new@example.com"
    assert notification.configuration["metrics"]["cvss31"] == "7"


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
