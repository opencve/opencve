from unittest.mock import Mock

import pytest

from projects.forms import EmailForm, WebhookForm, NotificationForm, ProjectForm


def test_project_form_valid(create_organization):
    org = create_organization(name="my-orga")
    request = Mock(user_organization=org.id)
    form = ProjectForm(
        data={"name": "my-project", "description": "my description", "active": "on"},
        request=request,
    )
    assert form.errors == {}


def test_project_form_special_characters(create_organization):
    org = create_organization(name="my-orga")
    request = Mock(user_organization=org.id)
    form = ProjectForm(
        data={"name": "foo|bar", "description": "my description", "active": "on"},
        request=request,
    )
    assert form.errors == {
        "name": ["Special characters (except dash) are not accepted"]
    }


def test_project_form_reserved_names(create_organization):
    org = create_organization(name="my-orga")
    request = Mock(user_organization=org.id)
    form = ProjectForm(
        data={"name": "add", "description": "my description", "active": "on"},
        request=request,
    )
    assert form.errors == {"name": ["This project is reserved."]}


def test_project_form_update_instance(create_organization, create_project):
    org = create_organization(name="my-orga")
    project = create_project(name="my-project", organization=org)
    request = Mock(user_organization=org.id)
    form = ProjectForm(
        data={"name": "renamed", "description": "my description", "active": "on"},
        request=request,
        instance=project,
    )
    assert form.errors == {"name": ["Existing projects can't be renamed."]}


def test_project_form_name_already_exists(create_organization, create_project):
    org1 = create_organization(name="org1")
    create_project(name="foo", organization=org1)
    request = Mock(user_organization=org1.id)
    form = ProjectForm(
        data={"name": "foo", "description": "my description", "active": "on"},
        request=request,
    )
    assert form.errors == {"name": ["This project already exists."]}

    # Same name is valid for another organization
    org2 = create_organization(name="org2")
    request = Mock(user_organization=org2.id)
    form = ProjectForm(
        data={"name": "foo", "description": "my description", "active": "on"},
        request=request,
    )
    assert form.errors == {}


def test_notification_form_valid(create_organization, create_project):
    org = create_organization(name="my-orga")
    project = create_project(name="my-project", organization=org)
    request = Mock(user_organization=org.id)
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
    request = Mock(user_organization=org.id)
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
    request = Mock(user_organization=org.id)
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

    request = Mock(user_organization=org.id)
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
    request = Mock(user_organization=org.id)

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
    request = Mock(user_organization=org.id)

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
    request = Mock(user_organization=org.id)

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
