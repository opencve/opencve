from unittest.mock import Mock

import pytest
from django.utils.timezone import now

from organizations.models import Membership
from projects.forms import (
    EmailForm,
    WebhookForm,
    NotificationForm,
    ProjectForm,
    CveTrackerFilterForm,
)


def test_project_form_valid(create_organization):
    org = create_organization(name="my-orga")
    request = Mock(current_organization=org.id)
    form = ProjectForm(
        data={"name": "my-project", "description": "my description", "active": "on"},
        request=request,
    )
    assert form.errors == {}


def test_project_form_special_characters(create_organization):
    org = create_organization(name="my-orga")
    request = Mock(current_organization=org.id)
    form = ProjectForm(
        data={"name": "foo|bar", "description": "my description", "active": "on"},
        request=request,
    )
    assert form.errors == {
        "name": ["Special characters (except dash) are not accepted"]
    }


def test_project_form_reserved_names(create_organization):
    org = create_organization(name="my-orga")
    request = Mock(current_organization=org.id)
    form = ProjectForm(
        data={"name": "add", "description": "my description", "active": "on"},
        request=request,
    )
    assert form.errors == {"name": ["This project is reserved."]}


def test_project_form_update_instance(create_organization, create_project):
    org = create_organization(name="my-orga")
    project = create_project(name="my-project", organization=org)
    request = Mock(current_organization=org.id)
    form = ProjectForm(
        data={"name": "renamed", "description": "my description", "active": "on"},
        request=request,
        instance=project,
    )
    assert form.errors == {}


def test_project_form_rename_with_existing_name_in_other_org(
    create_organization, create_project
):
    org1 = create_organization(name="org1")
    org2 = create_organization(name="org2")
    project1 = create_project(name="project1", organization=org1)
    create_project(name="existing", organization=org2)
    request = Mock(current_organization=org1.id)
    form = ProjectForm(
        data={"name": "existing", "description": "my description", "active": "on"},
        request=request,
        instance=project1,
    )
    assert form.errors == {}


def test_project_form_name_already_exists(create_organization, create_project):
    org1 = create_organization(name="org1")
    create_project(name="foo", organization=org1)
    request = Mock(current_organization=org1.id)
    form = ProjectForm(
        data={"name": "foo", "description": "my description", "active": "on"},
        request=request,
    )
    assert form.errors == {"name": ["This project already exists."]}

    # Same name is valid for another organization
    org2 = create_organization(name="org2")
    request = Mock(current_organization=org2.id)
    form = ProjectForm(
        data={"name": "foo", "description": "my description", "active": "on"},
        request=request,
    )
    assert form.errors == {}


def test_notification_form_valid(create_organization, create_project):
    org = create_organization(name="my-orga")
    project = create_project(name="my-project", organization=org)
    request = Mock(current_organization=org.id)
    form = NotificationForm(
        data={
            "name": "foo",
            "cvss31_score": 0,
        },
        request=request,
        project=project,
    )
    assert form.errors == {}


def test_notification_form_special_characters(create_organization, create_project):
    org = create_organization(name="my-orga")
    project = create_project(name="my-project", organization=org)
    request = Mock(current_organization=org.id)
    form = NotificationForm(
        data={
            "name": "foo|bar",
            "cvss31_score": 0,
        },
        request=request,
        project=project,
    )
    assert form.errors == {
        "name": ["Special characters (except dash and underscore) are not accepted"]
    }


def test_notification_form_reserved_name(create_organization, create_project):
    org = create_organization(name="my-orga")
    project = create_project(name="my-project", organization=org)
    request = Mock(current_organization=org.id)
    form = NotificationForm(
        data={
            "name": "add",
            "cvss31_score": 0,
        },
        request=request,
        project=project,
    )
    assert form.errors == {"name": ["This name is reserved."]}


def test_notification_form_already_exists(
    create_organization, create_project, create_notification
):
    org = create_organization(name="my-orga")
    project1 = create_project(name="project1", organization=org)
    create_notification(name="foo", project=project1)

    request = Mock(current_organization=org.id)
    form = NotificationForm(
        data={
            "name": "foo",
            "cvss31_score": 0,
        },
        request=request,
        project=project1,
    )
    assert form.errors == {"name": ["This name already exists."]}

    # Same name is valid for another project
    project2 = create_project(name="project2", organization=org)
    form = NotificationForm(
        data={
            "name": "foo",
            "cvss31_score": 0,
        },
        request=request,
        project=project2,
    )
    assert form.errors == {}


def test_email_notification_form(create_organization, create_project):
    org = create_organization(name="my-orga")
    project = create_project(name="my-project", organization=org)
    request = Mock(current_organization=org.id)

    form = EmailForm(
        data={
            "name": "my-notification",
            "cvss31_score": 0,
        },
        request=request,
        project=project,
    )
    assert form.errors == {"email": ["This field is required."]}

    form = EmailForm(
        data={
            "name": "my-notification",
            "email": "foobar",
            "cvss31_score": 0,
        },
        request=request,
        project=project,
    )
    assert form.errors == {"email": ["Enter a valid email address."]}

    form = EmailForm(
        data={
            "name": "my-notification",
            "email": "foo@bar.com",
            "cvss31_score": 0,
        },
        request=request,
        project=project,
    )
    assert form.errors == {}


def test_webhook_notification_form(create_organization, create_project):
    org = create_organization(name="my-orga")
    project = create_project(name="my-project", organization=org)
    request = Mock(current_organization=org.id)

    form = WebhookForm(
        data={
            "name": "my-notification",
            "cvss31_score": 0,
        },
        request=request,
        project=project,
    )
    assert form.errors == {"url": ["This field is required."]}

    form = WebhookForm(
        data={
            "name": "my-notification",
            "url": "foobar",
            "cvss31_score": 0,
        },
        request=request,
        project=project,
    )
    assert form.errors == {"url": ["Enter a valid URL."]}

    form = WebhookForm(
        data={
            "name": "my-notification",
            "url": "https://www.example.com",
            "headers": "foobar",
            "cvss31_score": 0,
        },
        request=request,
        project=project,
    )
    assert form.errors == {"headers": ["Enter a valid JSON."]}

    form = WebhookForm(
        data={
            "name": "my-notification",
            "url": "https://www.example.com",
            "headers": {"foo": "bar"},
            "cvss31_score": 0,
        },
        request=request,
        project=project,
    )
    assert form.errors == {}


@pytest.mark.parametrize(
    "headers,valid",
    [
        ({"foo": True}, False),
        ({"foo": 100}, False),
        ({"foo": ["bar"]}, False),
        ({"foo": {"bar": "nested"}}, False),
        ({10: "bar"}, False),
        ({10: ["foo", "bar"]}, False),
        ({True: "bar"}, False),
        ({"foo": "bar"}, True),
        ({"foo": "bar", "bar": "foo"}, True),
    ],
)
def test_webhook_notification_valid_headers(
    create_organization, create_project, headers, valid
):
    org = create_organization(name="my-orga")
    project = create_project(name="my-project", organization=org)
    request = Mock(current_organization=org.id)

    form = WebhookForm(
        data={
            "name": "my-notification",
            "cvss31_score": 0,
            "url": "https://www.example.com",
            "headers": headers,
        },
        request=request,
        project=project,
    )

    if valid:
        assert form.errors == {}
    else:
        assert form.errors == {
            "headers": ["HTTP headers must be in a simple key-value format"]
        }


def test_cve_tracker_filter_form_valid_empty(create_organization):
    """Test that form is valid with no data"""
    org = create_organization(name="my-orga")
    form = CveTrackerFilterForm(data={}, organization=org)
    assert form.errors == {}
    assert form.is_valid()


def test_cve_tracker_filter_form_valid_with_assignee(create_organization, create_user):
    """Test that form is valid with assignee only"""
    user = create_user(username="testuser")
    org = create_organization(name="my-orga-with-member", user=user)

    form = CveTrackerFilterForm(
        data={"assignee": user.username},
        organization=org,
    )
    assert form.errors == {}
    assert form.is_valid()


def test_cve_tracker_filter_form_valid_with_status(create_organization):
    """Test that form is valid with status only"""
    org = create_organization(name="my-orga")
    form = CveTrackerFilterForm(
        data={"status": "to_evaluate"},
        organization=org,
    )
    assert form.errors == {}
    assert form.is_valid()


def test_cve_tracker_filter_form_valid_with_both(create_organization, create_user):
    """Test that form is valid with both assignee and status"""
    user = create_user(username="testuser")
    org = create_organization(name="my-orga-with-member", user=user)

    form = CveTrackerFilterForm(
        data={"assignee": user.username, "status": "pending_review"},
        organization=org,
    )
    assert form.errors == {}
    assert form.is_valid()


def test_cve_tracker_filter_form_assignee_queryset_filtered_by_organization(
    create_organization, create_user
):
    """Test that assignee choices only contain members of the organization"""
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")
    user3 = create_user(username="user3")

    org1 = create_organization(name="org1", user=user1)
    org2 = create_organization(name="org2", user=user2)
    # user3 is not a member of any organization

    form = CveTrackerFilterForm(organization=org1)
    assignee_usernames = [
        choice[0] for choice in form.fields["assignee"].choices if choice[0]
    ]

    assert user1.username in assignee_usernames
    assert user2.username not in assignee_usernames
    assert user3.username not in assignee_usernames

    form = CveTrackerFilterForm(organization=org2)
    assignee_usernames = [
        choice[0] for choice in form.fields["assignee"].choices if choice[0]
    ]

    assert user1.username not in assignee_usernames
    assert user2.username in assignee_usernames
    assert user3.username not in assignee_usernames


def test_cve_tracker_filter_form_assignee_queryset_empty_without_organization():
    """Test that assignee choices only contain empty option when no organization is provided"""
    form = CveTrackerFilterForm()
    # Should only have the empty label choice
    assert len(form.fields["assignee"].choices) == 0


def test_cve_tracker_filter_form_invalid_assignee_from_different_organization(
    create_organization, create_user
):
    """Test that selecting an assignee from a different organization is invalid"""
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")

    org1 = create_organization(name="org1", user=user1)
    org2 = create_organization(name="org2", user=user2)

    # Try to use user2 in org1's form
    form = CveTrackerFilterForm(
        data={"assignee": user2.username},
        organization=org1,
    )
    assert not form.is_valid()
    assert "assignee" in form.errors


def test_cve_tracker_filter_form_invalid_status(create_organization):
    """Test that invalid status values are rejected"""
    org = create_organization(name="my-orga")
    form = CveTrackerFilterForm(
        data={"status": "invalid_status"},
        organization=org,
    )
    assert not form.is_valid()
    assert "status" in form.errors


@pytest.mark.parametrize(
    "status",
    [
        "to_evaluate",
        "pending_review",
        "analysis_in_progress",
        "remediation_in_progress",
        "evaluated",
        "resolved",
        "not_applicable",
        "risk_accepted",
    ],
)
def test_cve_tracker_filter_form_valid_statuses(create_organization, status):
    """Test that all valid status values are accepted"""
    org = create_organization(name="my-orga")
    form = CveTrackerFilterForm(
        data={"status": status},
        organization=org,
    )
    assert form.errors == {}
    assert form.is_valid()


def test_cve_tracker_filter_form_assignee_queryset_ordered_by_username(
    create_organization, create_user
):
    """Test that assignee choices are ordered by username"""
    user_c = create_user(username="charlie")
    user_a = create_user(username="alice")
    user_b = create_user(username="bob")
    org = create_organization(name="org", user=user_a)

    # Add multiple users to org
    Membership.objects.create(
        user=user_b,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    Membership.objects.create(
        user=user_c,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )

    form = CveTrackerFilterForm(organization=org)
    # Extract usernames from choices (skip empty label)
    usernames = [choice[0] for choice in form.fields["assignee"].choices if choice[0]]

    assert usernames == ["alice", "bob", "charlie"]


def test_cve_tracker_filter_form_valid_with_query(create_organization):
    """Test that form is valid with query only"""
    org = create_organization(name="my-orga")
    form = CveTrackerFilterForm(
        data={"query": "kev:true AND cvss31>=8"},
        organization=org,
    )
    assert form.errors == {}
    assert form.is_valid()


def test_cve_tracker_filter_form_valid_with_query_and_other_fields(
    create_organization, create_user
):
    """Test that form is valid with query and other fields"""
    user = create_user(username="testuser")
    org = create_organization(name="my-orga-with-member", user=user)

    form = CveTrackerFilterForm(
        data={
            "query": "kev:true",
            "assignee": user.username,
            "status": "to_evaluate",
        },
        organization=org,
    )
    assert form.errors == {}
    assert form.is_valid()


def test_cve_tracker_filter_form_valid_with_view(
    create_organization, create_user, create_view
):
    """Test that form is valid with view only"""
    user = create_user(username="testuser")
    org = create_organization(name="my-orga", user=user)
    view = create_view(
        name="my-view", query="kev:true", organization=org, privacy="public"
    )

    form = CveTrackerFilterForm(
        data={"view": str(view.id)},
        organization=org,
        user=user,
    )
    assert form.errors == {}
    assert form.is_valid()


def test_cve_tracker_filter_form_valid_with_view_and_other_fields(
    create_organization, create_user, create_view
):
    """Test that form is valid with view and other fields"""
    user = create_user(username="testuser")
    org = create_organization(name="my-orga", user=user)
    view = create_view(
        name="my-view", query="kev:true", organization=org, privacy="public"
    )

    form = CveTrackerFilterForm(
        data={
            "view": str(view.id),
            "assignee": user.username,
            "status": "to_evaluate",
            "query": "cvss31>=7",
        },
        organization=org,
        user=user,
    )
    assert form.errors == {}
    assert form.is_valid()


def test_cve_tracker_filter_form_view_queryset_includes_public_views(
    create_organization, create_user, create_view
):
    """Test that view choices include public views from the organization"""
    user = create_user(username="testuser")
    org = create_organization(name="my-orga", user=user)
    view1 = create_view(
        name="public-view-1", query="kev:true", organization=org, privacy="public"
    )
    view2 = create_view(
        name="public-view-2", query="cvss31>=8", organization=org, privacy="public"
    )

    form = CveTrackerFilterForm(organization=org, user=user)
    view_ids = [choice[0] for choice in form.fields["view"].choices if choice[0]]

    assert str(view1.id) in view_ids
    assert str(view2.id) in view_ids


def test_cve_tracker_filter_form_view_queryset_includes_user_private_views(
    create_organization, create_user, create_view
):
    """Test that view choices include private views of the user"""
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")
    org = create_organization(name="my-orga", user=user1)

    # Add user2 to org
    Membership.objects.create(
        user=user2,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )

    # Create private views for both users
    private_view_user1 = create_view(
        name="private-view-user1",
        query="kev:true",
        organization=org,
        privacy="private",
        user=user1,
    )
    private_view_user2 = create_view(
        name="private-view-user2",
        query="cvss31>=8",
        organization=org,
        privacy="private",
        user=user2,
    )

    # Form for user1 should only show user1's private view
    form = CveTrackerFilterForm(organization=org, user=user1)
    view_ids = [choice[0] for choice in form.fields["view"].choices if choice[0]]

    assert str(private_view_user1.id) in view_ids
    assert str(private_view_user2.id) not in view_ids

    # Form for user2 should only show user2's private view
    form = CveTrackerFilterForm(organization=org, user=user2)
    view_ids = [choice[0] for choice in form.fields["view"].choices if choice[0]]

    assert str(private_view_user1.id) not in view_ids
    assert str(private_view_user2.id) in view_ids


def test_cve_tracker_filter_form_view_queryset_filtered_by_organization(
    create_organization, create_user, create_view
):
    """Test that view choices only contain views from the organization"""
    user = create_user(username="testuser")
    org1 = create_organization(name="org1", user=user)
    org2 = create_organization(name="org2", user=user)

    view_org1 = create_view(
        name="view-org1", query="kev:true", organization=org1, privacy="public"
    )
    view_org2 = create_view(
        name="view-org2", query="cvss31>=8", organization=org2, privacy="public"
    )

    form = CveTrackerFilterForm(organization=org1, user=user)
    view_ids = [choice[0] for choice in form.fields["view"].choices if choice[0]]

    assert str(view_org1.id) in view_ids
    assert str(view_org2.id) not in view_ids

    form = CveTrackerFilterForm(organization=org2, user=user)
    view_ids = [choice[0] for choice in form.fields["view"].choices if choice[0]]

    assert str(view_org1.id) not in view_ids
    assert str(view_org2.id) in view_ids


def test_cve_tracker_filter_form_view_queryset_empty_without_organization():
    """Test that view choices are empty when no organization is provided"""
    form = CveTrackerFilterForm()
    assert len(form.fields["view"].choices) == 0


def test_cve_tracker_filter_form_view_queryset_only_public_without_user(
    create_organization, create_user, create_view
):
    """Test that without user, only public views are shown"""
    user = create_user(username="testuser")
    org = create_organization(name="my-orga", user=user)

    public_view = create_view(
        name="public-view", query="kev:true", organization=org, privacy="public"
    )
    private_view = create_view(
        name="private-view",
        query="cvss31>=8",
        organization=org,
        privacy="private",
        user=user,
    )

    form = CveTrackerFilterForm(organization=org)
    view_ids = [choice[0] for choice in form.fields["view"].choices if choice[0]]

    assert str(public_view.id) in view_ids
    assert str(private_view.id) not in view_ids


def test_cve_tracker_filter_form_view_queryset_ordered_by_name(
    create_organization, create_user, create_view
):
    """Test that view choices are ordered by name"""
    user = create_user(username="testuser")
    org = create_organization(name="my-orga", user=user)

    view_c = create_view(
        name="charlie-view", query="kev:true", organization=org, privacy="public"
    )
    view_a = create_view(
        name="alice-view", query="cvss31>=8", organization=org, privacy="public"
    )
    view_b = create_view(
        name="bob-view", query="cvss31>=7", organization=org, privacy="public"
    )

    form = CveTrackerFilterForm(organization=org, user=user)
    view_names = [choice[1] for choice in form.fields["view"].choices]

    # Should be ordered: "All views", "alice-view", "bob-view", "charlie-view"
    assert view_names == ["All views", "alice-view", "bob-view", "charlie-view"]


def test_cve_tracker_filter_form_invalid_view_from_different_organization(
    create_organization, create_user, create_view
):
    """Test that selecting a view from a different organization is invalid"""
    user = create_user(username="testuser")
    org1 = create_organization(name="org1", user=user)
    org2 = create_organization(name="org2", user=user)

    view_org2 = create_view(
        name="view-org2", query="kev:true", organization=org2, privacy="public"
    )

    # Try to use view from org2 in org1's form
    form = CveTrackerFilterForm(
        data={"view": str(view_org2.id)},
        organization=org1,
        user=user,
    )
    assert not form.is_valid()
    assert "view" in form.errors


def test_cve_tracker_filter_form_invalid_view_private_from_different_user(
    create_organization, create_user, create_view
):
    """Test that selecting a private view from a different user is invalid"""
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")
    org = create_organization(name="my-orga", user=user1)

    # Add user2 to org
    Membership.objects.create(
        user=user2,
        organization=org,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )

    private_view_user2 = create_view(
        name="private-view-user2",
        query="kev:true",
        organization=org,
        privacy="private",
        user=user2,
    )

    # Try to use user2's private view in user1's form
    form = CveTrackerFilterForm(
        data={"view": str(private_view_user2.id)},
        organization=org,
        user=user1,
    )
    assert not form.is_valid()
    assert "view" in form.errors
