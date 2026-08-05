import json

import pytest
from django.test import override_settings
from django.urls import reverse
from django.utils.timezone import now

from cves.models import Cve
from organizations.models import Membership
from projects.models import CveTracker, ProjectMembership


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_view_viewer_sees_read_only_tracker_badges(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Viewer sees static tracker badges without editable controls."""
    owner = create_user(username="owner")
    viewer = create_user(username="viewer")
    org = create_organization(name="org1", user=owner)
    viewer_membership = Membership.objects.create(
        user=viewer,
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
    ProjectMembership.objects.create(
        project=project,
        membership=viewer_membership,
        role=ProjectMembership.VIEWER,
    )
    cve = create_cve("CVE-2023-22490")
    CveTracker.update_tracker(
        project=project,
        cve=cve,
        assignee=owner,
        status="to_evaluate",
    )

    response = auth_client(viewer).get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )

    assert response.status_code == 200
    content = response.content.decode()
    assert "editable-assignee" not in content
    assert "editable-status" not in content
    assert owner.username in content
    assert "To evaluate" in content


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_view_contributor_sees_editable_tracker_badges(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Contributor sees editable tracker badges on the vulnerabilities page."""
    owner = create_user(username="owner")
    contributor = create_user(username="contributor")
    org = create_organization(name="org1", user=owner)
    contributor_membership = Membership.objects.create(
        user=contributor,
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
    ProjectMembership.objects.create(
        project=project,
        membership=contributor_membership,
        role=ProjectMembership.CONTRIBUTOR,
    )
    create_cve("CVE-2023-22490")
    CveTracker.update_tracker(
        project=project,
        cve=Cve.objects.get(cve_id="CVE-2023-22490"),
        assignee=owner,
        status="to_evaluate",
    )

    response = auth_client(contributor).get(
        reverse(
            "project_vulnerabilities",
            kwargs={"org_name": "org1", "project_name": "project1"},
        )
    )

    assert response.status_code == 200
    content = response.content.decode()
    assert "editable-assignee" in content
    assert "editable-status" in content


@override_settings(ENABLE_ONBOARDING=False)
def test_project_vulnerabilities_get_context_data_assignable_members(
    create_organization, create_user, create_project, auth_client
):
    """Assignee choices only include explicit project contributors/admins."""
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")
    user3 = create_user(username="user3")
    org = create_organization(name="org1", user=user1)

    user2_membership = Membership.objects.create(
        user=user2,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )

    Membership.objects.create(
        user=user3,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=None,
    )

    project = create_project(name="project1", organization=org)
    ProjectMembership.objects.create(
        project=project,
        membership=user2_membership,
        role=ProjectMembership.CONTRIBUTOR,
    )

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

    assert usernames == ["user2"]
    assert "user1" not in usernames
    assert "user3" not in usernames


@override_settings(ENABLE_ONBOARDING=False)
def test_assign_cve_user_view_rejects_non_assignable_org_owner(
    create_organization, create_user, create_project, create_cve, auth_client
):
    """Org owner without explicit project membership cannot be set as assignee."""
    owner = create_user(username="owner")
    contributor = create_user(username="contributor")
    org = create_organization(name="org1", user=owner)
    contributor_membership = Membership.objects.create(
        user=contributor,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project = create_project(name="project1", organization=org)
    ProjectMembership.objects.create(
        project=project,
        membership=contributor_membership,
        role=ProjectMembership.CONTRIBUTOR,
    )
    create_cve("CVE-2023-22490")

    response = auth_client(owner).post(
        reverse(
            "assign_cve_user",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        content_type="application/json",
        data=json.dumps({"cve_id": "CVE-2023-22490", "assignee_id": str(owner.id)}),
    )

    assert response.status_code == 400
    assert response.json()["error"] == "Invalid assignee"


@override_settings(ENABLE_ONBOARDING=False)
def test_automation_configuration_view_viewer_is_redirected(
    create_organization,
    create_user,
    create_project,
    create_automation,
    auth_client,
    set_current_org,
):
    """Viewer is redirected from automation configuration to overview."""
    owner = create_user(username="owner")
    viewer = create_user(username="viewer")
    org = create_organization(name="org1", user=owner)
    viewer_membership = Membership.objects.create(
        user=viewer,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project = create_project(name="project1", organization=org)
    ProjectMembership.objects.create(
        project=project,
        membership=viewer_membership,
        role=ProjectMembership.VIEWER,
    )
    create_automation(name="my-alert", project=project)

    client = set_current_org(auth_client(viewer), org)
    response = client.get(
        reverse(
            "automation_configuration",
            kwargs={
                "org_name": "org1",
                "project_name": "project1",
                "automation": "my-alert",
            },
        ),
        follow=True,
    )

    assert response.status_code == 200
    assert response.redirect_chain == [
        (
            reverse(
                "automation_overview",
                kwargs={
                    "org_name": "org1",
                    "project_name": "project1",
                    "automation": "my-alert",
                },
            ),
            302,
        )
    ]
    assert (
        "You do not have permission to perform this action."
        in response.content.decode()
    )


@override_settings(ENABLE_ONBOARDING=False)
def test_edit_notification_view_viewer_is_redirected(
    create_organization,
    create_user,
    create_project,
    create_notification,
    auth_client,
    set_current_org,
):
    """Viewer is redirected from notification edit to the notifications list."""
    owner = create_user(username="owner")
    viewer = create_user(username="viewer")
    org = create_organization(name="org1", user=owner)
    viewer_membership = Membership.objects.create(
        user=viewer,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project = create_project(name="project1", organization=org)
    ProjectMembership.objects.create(
        project=project,
        membership=viewer_membership,
        role=ProjectMembership.VIEWER,
    )
    create_notification(name="email-notif", project=project, type="email")

    client = set_current_org(auth_client(viewer), org)
    response = client.get(
        reverse(
            "edit_notification",
            kwargs={
                "org_name": "org1",
                "project_name": "project1",
                "notification": "email-notif",
            },
        ),
        follow=True,
    )

    assert response.status_code == 200
    assert response.redirect_chain[0][0] == reverse(
        "notifications",
        kwargs={"org_name": "org1", "project_name": "project1"},
    )
    assert (
        "You do not have permission to perform this action."
        in response.content.decode()
    )


@override_settings(ENABLE_ONBOARDING=False)
def test_viewer_tracker_assign_ajax_returns_403(
    create_organization,
    create_user,
    create_project,
    create_cve,
    auth_client,
):
    """Viewer receives 403 when posting to the tracker assign endpoint."""
    owner = create_user(username="owner")
    viewer = create_user(username="viewer")
    org = create_organization(name="org1", user=owner)
    viewer_m = Membership.objects.create(
        user=viewer,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project = create_project(name="project1", organization=org, vendors=["git-scm"])
    ProjectMembership.objects.create(
        project=project, membership=viewer_m, role=ProjectMembership.VIEWER
    )
    create_cve("CVE-2023-22490")

    response = auth_client(viewer).post(
        reverse(
            "assign_cve_user",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        content_type="application/json",
        data=json.dumps({"cve_id": "CVE-2023-22490", "assignee_id": str(owner.id)}),
        HTTP_X_REQUESTED_WITH="XMLHttpRequest",
    )

    assert response.status_code == 403


@override_settings(ENABLE_ONBOARDING=False)
def test_member_without_project_membership_cannot_access_project(
    create_organization, create_user, create_project, auth_client
):
    """Org member without project membership is redirected to the project list."""
    owner = create_user(username="owner")
    member = create_user(username="member")
    org = create_organization(name="org1", user=owner)
    Membership.objects.create(
        user=member,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    create_project(name="project1", organization=org)

    response = auth_client(member).get(
        reverse("project", kwargs={"org_name": "org1", "project_name": "project1"}),
    )

    assert response.status_code == 302
    assert response.url == reverse("list_projects", kwargs={"org_name": "org1"})


@override_settings(ENABLE_ONBOARDING=False)
def test_inactive_project_returns_404_for_direct_access(
    create_organization,
    create_user,
    create_project,
    create_project_membership,
    auth_client,
):
    """Direct access to an inactive project returns 404 even with membership."""
    owner = create_user(username="owner")
    member = create_user(username="member")
    org = create_organization(name="org1", user=owner)
    member_m = Membership.objects.create(
        user=member,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project = create_project(name="gamma", organization=org, active=False)
    create_project_membership(
        project=project, membership=member_m, role=ProjectMembership.CONTRIBUTOR
    )

    response = auth_client(member).get(
        reverse("project", kwargs={"org_name": "org1", "project_name": "gamma"}),
    )

    assert response.status_code == 404


@override_settings(ENABLE_ONBOARDING=False)
def test_org_member_with_no_projects_sees_empty_list(
    create_organization, create_user, create_project, auth_client
):
    """Org member without any project membership sees an empty project list."""
    owner = create_user(username="owner")
    member = create_user(username="member")
    org = create_organization(name="org1", user=owner)
    Membership.objects.create(
        user=member,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    create_project(name="alpha", organization=org)

    response = auth_client(member).get(
        reverse("list_projects", kwargs={"org_name": "org1"}),
    )

    assert response.status_code == 200
    assert list(response.context["projects"]) == []


@override_settings(ENABLE_ONBOARDING=False)
def test_project_members_view_viewer_sees_list_without_add_form(
    create_organization,
    create_user,
    create_project,
    create_project_membership,
    auth_client,
):
    """Viewer can list project members but cannot see the add-member form."""
    owner = create_user(username="owner")
    viewer = create_user(username="viewer")
    org = create_organization(name="org1", user=owner)
    viewer_m = Membership.objects.create(
        user=viewer,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project = create_project(name="project1", organization=org)
    create_project_membership(
        project=project, membership=viewer_m, role=ProjectMembership.VIEWER
    )

    response = auth_client(viewer).get(
        reverse(
            "project_members",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
    )

    assert response.status_code == 200
    assert response.context["can_manage_members"] is False
    assert "members_form" not in response.context


@override_settings(ENABLE_ONBOARDING=False)
def test_project_members_view_admin_sees_add_form(
    create_organization,
    create_user,
    create_project,
    create_project_membership,
    auth_client,
):
    """Project admin sees the add-member form on the members page."""
    owner = create_user(username="owner")
    admin_user = create_user(username="padmin")
    org = create_organization(name="org1", user=owner)
    admin_m = Membership.objects.create(
        user=admin_user,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project = create_project(name="project1", organization=org)
    create_project_membership(
        project=project, membership=admin_m, role=ProjectMembership.PROJECT_ADMIN
    )

    response = auth_client(admin_user).get(
        reverse(
            "project_members",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
    )

    assert response.status_code == 200
    assert response.context["can_manage_members"] is True
    assert "members_form" in response.context


@override_settings(ENABLE_ONBOARDING=False)
def test_contributor_cannot_post_project_member_add(
    create_organization,
    create_user,
    create_project,
    create_project_membership,
    auth_client,
):
    """Contributor receives 403 when posting to add a project member."""
    owner = create_user(username="owner")
    contributor = create_user(username="contributor")
    newbie = create_user(username="newbie")
    org = create_organization(name="org1", user=owner)
    contributor_m = Membership.objects.create(
        user=contributor,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    newbie_m = Membership.objects.create(
        user=newbie,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project = create_project(name="project1", organization=org)
    create_project_membership(
        project=project, membership=contributor_m, role=ProjectMembership.CONTRIBUTOR
    )

    response = auth_client(contributor).post(
        reverse(
            "project_members",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
        data={
            "membership_id": str(newbie_m.pk),
            "role": ProjectMembership.VIEWER,
        },
    )

    assert response.status_code == 403


@override_settings(ENABLE_ONBOARDING=False)
def test_viewer_can_export_cves_csv(
    create_organization,
    create_user,
    create_project,
    create_cve,
    create_project_membership,
    auth_client,
):
    """Viewer can access the CVE CSV export endpoint."""
    owner = create_user(username="owner")
    viewer = create_user(username="viewer")
    org = create_organization(name="org1", user=owner)
    viewer_m = Membership.objects.create(
        user=viewer,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    project = create_project(name="project1", organization=org, vendors=["git-scm"])
    create_project_membership(
        project=project, membership=viewer_m, role=ProjectMembership.VIEWER
    )
    create_cve("CVE-2023-22490")

    response = auth_client(viewer).get(
        reverse(
            "project_vulnerabilities_export_csv",
            kwargs={"org_name": "org1", "project_name": "project1"},
        ),
    )

    assert response.status_code == 200
    assert response["Content-Type"] == "text/csv"
