import re
import uuid
from unittest.mock import patch, MagicMock
from datetime import date

import pytest
from django.utils import timezone
from changes.models import Change, Report
from organizations.models import Membership
from projects.models import CveTracker
from users.models import UserTag

from dashboards.widgets import (
    list_widgets,
    Widget,
    ActivityWidget,
    ViewsWidget,
    ViewCvesWidget,
    ProjectCvesWidget,
    TagsWidget,
    ProjectsWidget,
    LastReportsWidget,
    MyAssignedCvesWidget,
    AssignmentCvesWidget,
)


def test_list_widgets():
    """
    Test the list_widgets function.
    """
    mock_widget1 = MagicMock()
    mock_widget1.id = "widget1"
    mock_widget1.name = "Widget 1"
    mock_widget1.description = "Description 1"

    mock_widget2 = MagicMock()
    mock_widget2.id = "widget2"
    mock_widget2.name = "Widget 2"
    mock_widget2.description = "Description 2"

    # Mock Widget.__subclasses__ to return fake widgets
    with patch(
        "dashboards.widgets.Widget.__subclasses__",
        return_value=[mock_widget1, mock_widget2],
    ):
        result = list_widgets()

        assert len(result) == 2
        assert "widget1" in result
        assert "widget2" in result

        assert result["widget1"]["type"] == "widget1"
        assert result["widget1"]["name"] == "Widget 1"
        assert result["widget1"]["description"] == "Description 1"
        assert result["widget1"]["class"] == mock_widget1

        assert result["widget2"]["type"] == "widget2"
        assert result["widget2"]["name"] == "Widget 2"
        assert result["widget2"]["description"] == "Description 2"
        assert result["widget2"]["class"] == mock_widget2


## Widget class


def test_widget_init():
    """
    Test the Widget.__init__ method.
    """
    mock_request = MagicMock()
    data = {
        "id": "296862cf-664d-4724-84d6-ffd91c1f83d1",
        "type": "activity",
        "title": "Test Widget",
        "config": {"key": "value"},
    }

    with patch("dashboards.widgets.Widget.allowed_config_keys", ["key"]):
        widget = Widget(mock_request, data)

        assert widget.request == mock_request
        assert widget.id == "296862cf-664d-4724-84d6-ffd91c1f83d1"
        assert widget.type == "activity"
        assert widget.title == "Test Widget"
        assert widget.configuration == {"key": "value"}

        # Test without config and no default value raises an error
        with pytest.raises(
            ValueError, match="Missing required configuration keys: key"
        ):
            data_no_config = {
                "id": "296862cf-664d-4724-84d6-ffd91c1f83d1",
                "type": "activity",
                "title": "Test Widget",
            }
            Widget(mock_request, data_no_config)

        # Test without config and with default value
        with patch("dashboards.widgets.Widget.default_config_values", {"key": "value"}):
            data_no_config = {
                "id": "296862cf-664d-4724-84d6-ffd91c1f83d1",
                "type": "activity",
                "title": "Test Widget",
            }
            widget = Widget(mock_request, data_no_config)
            assert widget.configuration == {"key": "value"}


def test_widget_validate_id():
    """
    Test the Widget.validate_id method.
    """
    # Valid UUID
    valid_uuid = "296862cf-664d-4724-84d6-ffd91c1f83d1"
    assert Widget.validate_id(valid_uuid) == valid_uuid

    # Invalid UUID
    invalid_uuid = "not-a-uuid"
    with pytest.raises(
        ValueError, match=re.escape(f"Invalid widget ID ({invalid_uuid})")
    ):
        Widget.validate_id(invalid_uuid)


def test_widget_validate_type():
    """
    Test the Widget.validate_type method.
    """
    mock_widgets = {
        "widget1": {
            "type": "activity",
            "name": "Widget 1",
            "description": "Description 1",
            "class": MagicMock(),
        },
        "widget2": {
            "type": "views",
            "name": "Widget 2",
            "description": "Description 2",
            "class": MagicMock(),
        },
    }

    with patch("dashboards.widgets.list_widgets", return_value=mock_widgets):
        # Valid types
        assert Widget.validate_type("activity") == "activity"
        assert Widget.validate_type("views") == "views"

        # Invalid type
        with pytest.raises(
            ValueError, match=re.escape(f"Invalid widget type (invalid_type)")
        ):
            Widget.validate_type("invalid_type")


def test_widget_validate_config():
    """
    Test the Widget.validate_config method.
    """
    # Mock allowed_config_keys
    with patch("dashboards.widgets.Widget.allowed_config_keys", ["key1", "key2"]):
        widget = Widget(
            MagicMock(),
            {
                "id": "296862cf-664d-4724-84d6-ffd91c1f83d1",
                "type": "activity",
                "title": "Test",
                "config": {"key1": "value1", "key2": "value2"},
            },
        )

        # Test with all allowed keys
        config = {"key1": "value1", "key2": "value2"}
        assert widget.validate_config(config) == config

        # Test with some allowed keys
        config = {"key1": "value1", "key2": "value2", "key3": "value3"}
        assert widget.validate_config(config) == {"key1": "value1", "key2": "value2"}

        # Test with no allowed keys
        config = {"key3": "value3", "key4": "value4"}
        with pytest.raises(
            ValueError, match="Missing required configuration keys: key1, key2"
        ):
            widget.validate_config(config)

        # Test with no allowed keys and default values
        with patch(
            "dashboards.widgets.Widget.default_config_values",
            {"key1": "value1", "key2": "value2"},
        ):
            config = {}
            assert widget.validate_config(config) == {
                "key1": "value1",
                "key2": "value2",
            }


def test_widget_index_config_methods():
    """
    Test that index() and config() call their respective render methods.
    """
    widget = Widget(
        MagicMock(),
        {
            "id": "296862cf-664d-4724-84d6-ffd91c1f83d1",
            "type": "activity",
            "title": "Test",
        },
    )

    with patch.object(widget, "render_index") as mock_render_index:
        widget.index()
        mock_render_index.assert_called_once()

    with patch.object(widget, "render_config") as mock_render_config:
        widget.config()
        mock_render_config.assert_called_once()


def test_widget_render_index_config_methods():
    """
    Test that render_index and render_config call render_to_string with correct arguments.
    """
    mock_request = MagicMock()
    widget = Widget(
        mock_request,
        {
            "id": "296862cf-664d-4724-84d6-ffd91c1f83d1",
            "type": "activity",
            "title": "Test Widget",
            "config": {"key": "value"},
        },
    )

    with patch("dashboards.widgets.render_to_string") as mock_render:
        widget.render_index()
        mock_render.assert_called_with(
            "dashboards/widgets/activity/index.html",
            {
                "widget_id": "296862cf-664d-4724-84d6-ffd91c1f83d1",
                "widget_type": "activity",
                "title": "Test Widget",
                "config": {},
                "request": mock_request,
            },
        )

        widget.render_config()
        mock_render.assert_called_with(
            "dashboards/widgets/activity/config.html",
            {
                "widget_id": "296862cf-664d-4724-84d6-ffd91c1f83d1",
                "widget_type": "activity",
                "title": "Test Widget",
                "config": {},
                "request": mock_request,
            },
        )

        # Test with additional kwargs
        widget.render_index(extra="value")
        mock_render.assert_called_with(
            "dashboards/widgets/activity/index.html",
            {
                "widget_id": "296862cf-664d-4724-84d6-ffd91c1f83d1",
                "widget_type": "activity",
                "title": "Test Widget",
                "config": {},
                "request": mock_request,
                "extra": "value",
            },
        )


# ActivityWidget class


def test_activity_widget_validate_config():
    """
    Test the ActivityWidget.validate_config method.
    """
    widget = ActivityWidget(
        MagicMock(),
        {
            "id": "296862cf-664d-4724-84d6-ffd91c1f83d1",
            "type": "activity",
            "title": "Test",
            "config": {"activities_view": "all"},
        },
    )

    # Test valid values
    assert widget.validate_config({"activities_view": "all"}) == {
        "activities_view": "all"
    }
    assert widget.validate_config({"activities_view": "subscriptions"}) == {
        "activities_view": "subscriptions"
    }

    # Test invalid value
    with pytest.raises(
        ValueError, match=re.escape(f"Invalid activities view (invalid)")
    ):
        widget.validate_config({"activities_view": "invalid"})

    # Test with empty config and default value
    assert widget.validate_config({}) == {"activities_view": "all"}


@pytest.mark.django_db
def test_activity_widget_index(
    create_user,
    create_organization,
    create_project,
    create_cve,
):
    """
    Test ActivityWidget.index when activities_view is 'all'.
    """
    user = create_user()
    organization = create_organization("orga1", user)
    create_project(name="P_TomExam", organization=organization, vendors=["tomexam"])

    # Create CVEs known to have associated changes
    create_cve("CVE-2021-34181")  # tomexam
    create_cve("CVE-2022-20698")  # clamav

    mock_request = MagicMock()
    mock_request.user = user
    mock_request.current_organization = organization

    # All changes
    widget_data = {
        "id": "296862cf-664d-4724-84d6-ffd91c1f83d1",
        "type": "activity",
        "title": "Test Activity All",
        "config": {"activities_view": "all"},
    }
    widget = ActivityWidget(mock_request, widget_data)
    with patch("dashboards.widgets.render_to_string") as mock_render:
        widget.index()

    mock_render.assert_called_once()

    actual_call_args, _ = mock_render.call_args
    actual_template_name = actual_call_args[0]
    assert actual_template_name == "dashboards/widgets/activity/index.html"

    actual_context = actual_call_args[1]
    actual_changes = actual_context.pop("changes")
    assert actual_context == {
        "widget_id": "296862cf-664d-4724-84d6-ffd91c1f83d1",
        "widget_type": "activity",
        "title": "Test Activity All",
        "config": {"activities_view": "all"},
        "request": mock_request,
    }
    assert list(actual_changes) == list(Change.objects.all())

    # Subscriptions' changes
    widget_data["config"]["activities_view"] = "subscriptions"
    widget = ActivityWidget(mock_request, widget_data)
    with patch("dashboards.widgets.render_to_string") as mock_render:
        widget.index()

    mock_render.assert_called_once()

    actual_call_args, _ = mock_render.call_args
    actual_template_name = actual_call_args[0]
    assert actual_template_name == "dashboards/widgets/activity/index.html"

    actual_context = actual_call_args[1]
    actual_changes = actual_context.pop("changes")
    assert actual_context == {
        "widget_id": "296862cf-664d-4724-84d6-ffd91c1f83d1",
        "widget_type": "activity",
        "title": "Test Activity All",
        "config": {"activities_view": "subscriptions"},
        "request": mock_request,
    }
    assert list(actual_changes) == list(
        Change.objects.filter(cve__cve_id="CVE-2021-34181")
    )


@pytest.mark.django_db
def test_views_widget_index(
    create_user,
    create_organization,
    create_view,
):
    """
    Test ViewsWidget.index to ensure correct views are returned.
    """
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")
    org1 = create_organization("org1", user=user1)
    org2 = create_organization("org2", user=user2)

    view_public_org1 = create_view(
        name="Public Org1", query="test", organization=org1, privacy="public"
    )
    view_private_user1_org1 = create_view(
        name="Private User1 Org1",
        query="test",
        organization=org1,
        privacy="private",
        user=user1,
    )

    view_public_org2 = create_view(
        name="Public Org2", query="test", organization=org2, privacy="public"
    )
    view_private_user1_org2 = create_view(
        name="Private User1 Org2",
        query="test",
        organization=org2,
        privacy="private",
        user=user1,
    )
    view_private_user2_org1 = create_view(
        name="Private User2 Org1",
        query="test",
        organization=org1,
        privacy="private",
        user=user2,
    )

    mock_request = MagicMock()
    mock_request.user = user1
    mock_request.current_organization = org1

    widget = ViewsWidget(
        mock_request,
        {
            "id": "a7b8c9d0-e1f2-a3b4-c5d6-e7f8a9b0c1d2",
            "type": "views",
            "title": "Test Views Widget",
            "config": {},
        },
    )

    with patch("dashboards.widgets.render_to_string") as mock_render:
        widget.index()

    # Assertions
    actual_call_args, _ = mock_render.call_args
    actual_template_name = actual_call_args[0]
    assert actual_template_name == "dashboards/widgets/views/index.html"

    actual_context = actual_call_args[1]
    actual_views = actual_context.pop("views")
    assert actual_context == {
        "widget_id": "a7b8c9d0-e1f2-a3b4-c5d6-e7f8a9b0c1d2",
        "widget_type": "views",
        "title": "Test Views Widget",
        "config": {},
        "request": mock_request,
    }
    assert list(actual_views) == [view_private_user1_org1, view_public_org1]

    # Explicitly check that excluded views are not present
    returned_view_ids = {v.id for v in actual_views}
    assert view_public_org2.id not in returned_view_ids
    assert view_private_user1_org2.id not in returned_view_ids
    assert view_private_user2_org1.id not in returned_view_ids


@pytest.mark.django_db
def test_view_cves_widget_validate_config(
    create_user,
    create_organization,
    create_view,
):
    """
    Test ViewCvesWidget.validate_config for various scenarios:
    - Invalid view_id format
    - View not found
    - Private view owned by another user
    - Correct handling of show_view_info
    """
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")
    org1 = create_organization("org1", user=user1)
    org2 = create_organization("org2", user=user2)

    public_view_org1 = create_view(
        name="Public Org1", query="test", organization=org1, privacy="public"
    )
    public_view_org2 = create_view(
        name="Public Org2", query="test", organization=org2, privacy="public"
    )
    private_view_user1_org1 = create_view(
        name="Private User1 Org1",
        query="test",
        organization=org1,
        privacy="private",
        user=user1,
    )
    private_view_user2_org1 = create_view(
        name="Private User2 Org1",
        query="test",
        organization=org1,
        privacy="private",
        user=user2,
    )

    mock_request = MagicMock()
    mock_request.user = user1
    mock_request.current_organization = org1

    widget = ViewCvesWidget(
        mock_request,
        {
            "id": "d8e9f0a1-b2c3-d4e5-f6a7-b8c9d0e1f2a3",
            "type": "view_cves",
            "title": "Test View CVEs",
            "config": {"view_id": str(public_view_org1.id), "show_view_info": True},
        },
    )

    # Invalid view_id format (not UUID)
    with pytest.raises(
        ValueError, match=re.escape("Invalid view ID (not-a-valid-uuid)")
    ):
        widget.validate_config({"view_id": "not-a-valid-uuid", "show_view_info": True})

    # View does not exist
    non_existent_uuid = str(uuid.uuid4())
    with pytest.raises(
        ValueError, match=re.escape(f"View not found ({non_existent_uuid})")
    ):
        widget.validate_config({"view_id": non_existent_uuid, "show_view_info": True})

    # View is public but in another organization
    with pytest.raises(
        ValueError, match=re.escape(f"View not found ({public_view_org2.id})")
    ):
        widget.validate_config(
            {"view_id": str(public_view_org2.id), "show_view_info": True}
        )

    # View is private but belongs to another user (user2)
    with pytest.raises(
        ValueError, match=re.escape(f"View not found ({private_view_user2_org1.id})")
    ):
        widget.validate_config(
            {"view_id": str(private_view_user2_org1.id), "show_view_info": True}
        )

    # Public View with show_view_info=True
    valid_config_public_show = widget.validate_config(
        {"view_id": str(public_view_org1.id), "show_view_info": True}
    )
    assert valid_config_public_show == {
        "view_id": str(public_view_org1.id),
        "show_view_info": 1,
    }

    # Public View with missing show_view_info and default value
    assert widget.validate_config({"view_id": str(public_view_org1.id)}) == {
        "view_id": str(public_view_org1.id),
        "show_view_info": 0,
    }

    # Public View with show_view_info=False
    valid_config_public_noshow_explicit = widget.validate_config(
        {"view_id": str(public_view_org1.id), "show_view_info": False}
    )
    assert valid_config_public_noshow_explicit == {
        "view_id": str(public_view_org1.id),
        "show_view_info": 0,
    }

    # Private View (user1) with show_view_info=True
    valid_config_private_show = widget.validate_config(
        {"view_id": str(private_view_user1_org1.id), "show_view_info": True}
    )
    assert valid_config_private_show == {
        "view_id": str(private_view_user1_org1.id),
        "show_view_info": 1,
    }

    # Private View with missing show_view_info
    assert widget.validate_config({"view_id": str(private_view_user1_org1.id)}) == {
        "view_id": str(private_view_user1_org1.id),
        "show_view_info": 0,
    }


@pytest.mark.django_db
def test_view_cves_widget_config(
    create_user,
    create_organization,
    create_view,
):
    """
    Test ViewCvesWidget.config to ensure correct views are passed to the config template.
    """
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")
    org1 = create_organization("org1", user=user1)
    org2 = create_organization("org2", user=user2)

    view_public_org1 = create_view(
        name="Public Org1", query="test", organization=org1, privacy="public"
    )
    view_private_user1_org1 = create_view(
        name="Private User1 Org1",
        query="test",
        organization=org1,
        privacy="private",
        user=user1,
    )
    view_public_org2 = create_view(
        name="Public Org2", query="test", organization=org2, privacy="public"
    )
    view_private_user1_org2 = create_view(
        name="Private User1 Org2",
        query="test",
        organization=org2,
        privacy="private",
        user=user1,
    )
    view_private_user2_org1 = create_view(
        name="Private User2 Org1",
        query="test",
        organization=org1,
        privacy="private",
        user=user2,
    )

    mock_request = MagicMock()
    mock_request.user = user1
    mock_request.current_organization = org1
    widget = ViewCvesWidget(
        mock_request,
        {
            "id": "f9a0b1c2-d3e4-f5a6-b7c8-d9e0f1a2b3c4",
            "type": "view_cves",
            "title": "Test View CVEs Config",
            "config": {"view_id": str(view_public_org1.id), "show_view_info": True},
        },
    )

    with patch("dashboards.widgets.render_to_string") as mock_render:
        widget.config()

    # Assertions
    actual_call_args, _ = mock_render.call_args
    actual_template_name = actual_call_args[0]
    assert actual_template_name == "dashboards/widgets/view_cves/config.html"

    actual_context = actual_call_args[1]
    actual_views = actual_context.pop("views")
    assert actual_context == {
        "widget_id": "f9a0b1c2-d3e4-f5a6-b7c8-d9e0f1a2b3c4",
        "widget_type": "view_cves",
        "title": "Test View CVEs Config",
        "config": widget.configuration,
        "request": mock_request,
    }
    assert list(actual_views) == [view_public_org1, view_private_user1_org1]

    # Explicitly check that excluded views are not present
    returned_view_ids = {v.id for v in actual_views}
    assert view_public_org2.id not in returned_view_ids
    assert view_private_user1_org2.id not in returned_view_ids
    assert view_private_user2_org1.id not in returned_view_ids


@pytest.mark.django_db
def test_view_cves_widget_index(
    create_user,
    create_organization,
    create_view,
    create_cve,
):
    """
    Test ViewCvesWidget.index to ensure correct view and associated CVEs are passed to the template.
    """
    user = create_user()
    org = create_organization("org1", user=user)
    cve = create_cve("CVE-2024-31331")

    view = create_view(
        name="Test View for CVE",
        query="cve:CVE-2024-31331",
        organization=org,
        privacy="public",
    )

    mock_request = MagicMock()
    mock_request.user = user
    mock_request.current_organization = org

    widget = ViewCvesWidget(
        mock_request,
        {
            "id": "b1c2d3e4-f5a6-b7c8-d9e0-f1a2b3c4d5e6",
            "type": "view_cves",
            "title": "CVEs for Test View",
            "config": {
                "view_id": str(view.id),
                "show_view_info": 1,
            },
        },
    )

    with patch("dashboards.widgets.render_to_string") as mock_render:
        widget.index()

    # Assertions
    mock_render.assert_called_once()

    actual_call_args, _ = mock_render.call_args
    actual_template_name = actual_call_args[0]
    assert actual_template_name == "dashboards/widgets/view_cves/index.html"

    actual_context = actual_call_args[1]
    actual_view = actual_context.pop("view")
    actual_cves = actual_context.pop("cves")
    assert actual_context == {
        "widget_id": "b1c2d3e4-f5a6-b7c8-d9e0-f1a2b3c4d5e6",
        "widget_type": "view_cves",
        "title": "CVEs for Test View",
        "config": widget.configuration,
        "request": mock_request,
    }
    assert actual_view == view
    assert list(actual_cves) == [cve]


# ProjectCvesWidget class


@pytest.mark.django_db
def test_project_cves_widget_validate_config(
    create_user,
    create_organization,
    create_project,
):
    """
    Test the ProjectCvesWidget.validate_config method.
    """
    user1 = create_user(username="user1")
    org1 = create_organization(name="org1", owner=user1)
    project1 = create_project(name="project1", organization=org1, active=True)
    project2 = create_project(name="project2", organization=org1, active=False)

    user2 = create_user(username="user2")
    org2 = create_organization(name="org2", owner=user2)
    project3 = create_project(name="project3", organization=org2)

    request = MagicMock()
    request.user = user1
    request.current_organization = org1
    widget = ProjectCvesWidget(
        request,
        {
            "id": "123e4567-e89b-12d3-a456-426614174000",
            "type": "project_cves",
            "title": "Test Project CVEs",
            "config": {"project_id": str(project1.id), "show_project_info": True},
        },
    )

    # Valid config with show_project_info=True
    valid_config_true = {"project_id": str(project1.id), "show_project_info": True}
    cleaned_config = widget.validate_config(valid_config_true)
    assert cleaned_config == {"project_id": str(project1.id), "show_project_info": 1}

    # Valid config with show_project_info=False
    valid_config_false = {"project_id": str(project1.id), "show_project_info": False}
    cleaned_config = widget.validate_config(valid_config_false)
    assert cleaned_config == {"project_id": str(project1.id), "show_project_info": 0}

    # Invalid config without show_project_info and default value
    assert widget.validate_config({"project_id": str(project1.id)}) == {
        "project_id": str(project1.id),
        "show_project_info": 0,
    }

    # Invalid project_id (not UUID)
    invalid_uuid_config = {"project_id": "not-a-uuid", "show_project_info": True}
    with pytest.raises(ValueError, match=re.escape("Invalid project ID (not-a-uuid)")):
        widget.validate_config(invalid_uuid_config)

    # Project does not exist
    non_existent_uuid = str(uuid.uuid4())
    non_existent_config = {"project_id": non_existent_uuid, "show_project_info": True}
    with pytest.raises(
        ValueError, match=re.escape(f"Project not found ({non_existent_uuid})")
    ):
        widget.validate_config(non_existent_config)

    # Project is inactive
    inactive_config = {"project_id": str(project2.id), "show_project_info": True}
    with pytest.raises(
        ValueError, match=re.escape(f"Inactive project ({project2.id})")
    ):
        widget.validate_config(inactive_config)

    # Project belongs to another organization
    other_org_config = {"project_id": str(project3.id), "show_project_info": True}
    with pytest.raises(
        ValueError, match=re.escape(f"Project not found ({project3.id})")
    ):
        widget.validate_config(other_org_config)

    # Config with extra keys (should be ignored)
    extra_keys_config = {
        "project_id": str(project1.id),
        "show_project_info": True,
        "extra_key": "some_value",
    }
    cleaned_config = widget.validate_config(extra_keys_config)
    assert cleaned_config == {"project_id": str(project1.id), "show_project_info": 1}


@pytest.mark.django_db
def test_project_cves_widget_config(
    create_user,
    create_organization,
    create_project,
):
    """
    Test ProjectCvesWidget.config to ensure correct projects are passed to the config template.
    """
    user1 = create_user(username="user1")
    org1 = create_organization(name="org1", owner=user1)
    project_active_org1 = create_project(
        name="Active Org1", organization=org1, active=True
    )
    project_inactive_org1 = create_project(
        name="Inactive Org1", organization=org1, active=False
    )

    user2 = create_user(username="user2")
    org2 = create_organization(name="org2", owner=user2)
    project_active_org2 = create_project(
        name="Active Org2", organization=org2, active=True
    )

    mock_request = MagicMock()
    mock_request.user = user1
    mock_request.current_organization = org1

    widget = ProjectCvesWidget(
        mock_request,
        {
            "id": "a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6",
            "type": "project_cves",
            "title": "Test Project CVEs Config",
            "config": {
                "project_id": str(project_active_org1.id),
                "show_project_info": True,
            },
        },
    )

    with patch("dashboards.widgets.render_to_string") as mock_render:
        widget.config()

    # Assertions
    mock_render.assert_called_once()

    actual_call_args, _ = mock_render.call_args
    actual_template_name = actual_call_args[0]
    assert actual_template_name == "dashboards/widgets/project_cves/config.html"

    actual_context = actual_call_args[1]
    actual_projects = actual_context.pop("projects")
    assert actual_context == {
        "widget_id": "a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6",
        "widget_type": "project_cves",
        "title": "Test Project CVEs Config",
        "config": widget.configuration,
        "request": mock_request,
    }

    # Verify only the active project from org1 is passed
    assert list(actual_projects) == [project_active_org1]

    # Explicitly check that excluded projects are not present
    returned_project_ids = {p.id for p in actual_projects}
    assert project_inactive_org1.id not in returned_project_ids
    assert project_active_org2.id not in returned_project_ids


@pytest.mark.django_db
def test_project_cves_widget_index(
    create_user,
    create_organization,
    create_project,
    create_cve,
):
    """
    Test ProjectCvesWidget.index to ensure correct project and associated CVEs are passed to the template.
    """
    user = create_user(username="testuser")
    org = create_organization(name="org1", owner=user)

    project_tomexam = create_project(
        name="Project TomExam",
        organization=org,
        active=True,
        vendors=["tomexam"],
        products=["tomexam$PRODUCT$tomexam"],
    )
    project_no_subs = create_project(
        name="Project No Subs", organization=org, active=True, vendors=[], products=[]
    )

    cve_tomexam = create_cve("CVE-2021-34181")  # Associated with tomexam
    cve_google = create_cve("CVE-2024-31331")  # Associated with google

    mock_request = MagicMock()
    mock_request.user = user
    mock_request.current_organization = org

    # Project with tomexam subscription
    widget = ProjectCvesWidget(
        mock_request,
        {
            "id": "b1c2d3e4-f5a6-b7c8-d9e0-f1a2b3c4d5e6",
            "type": "project_cves",
            "title": "CVEs for Project TomExam",
            "config": {
                "project_id": str(project_tomexam.id),
                "show_project_info": 1,
            },
        },
    )

    with patch("dashboards.widgets.render_to_string") as mock_render:
        widget.index()

    mock_render.assert_called_once()
    actual_call_args, _ = mock_render.call_args
    actual_template_name = actual_call_args[0]
    assert actual_template_name == "dashboards/widgets/project_cves/index.html"

    actual_context = actual_call_args[1]
    actual_project = actual_context.pop("project")
    actual_cves = actual_context.pop("cves")

    assert actual_context == {
        "widget_id": "b1c2d3e4-f5a6-b7c8-d9e0-f1a2b3c4d5e6",
        "widget_type": "project_cves",
        "title": "CVEs for Project TomExam",
        "config": widget.configuration,
        "request": mock_request,
    }
    assert actual_project == project_tomexam
    assert list(actual_cves) == [cve_tomexam]
    assert cve_google not in actual_cves

    # Project with no subscription
    widget_no_subs = ProjectCvesWidget(
        mock_request,
        {
            "id": "c2d3e4f5-a6b7-c8d9-e0f1-a2b3c4d5e6f7",
            "type": "project_cves",
            "title": "CVEs for Project No Subs",
            "config": {
                "project_id": str(project_no_subs.id),
                "show_project_info": 0,
            },
        },
    )

    with patch("dashboards.widgets.render_to_string") as mock_render_no_subs:
        widget_no_subs.index()

    mock_render_no_subs.assert_called_once()
    actual_call_args_ns, _ = mock_render_no_subs.call_args
    actual_template_name_ns = actual_call_args_ns[0]
    assert actual_template_name_ns == "dashboards/widgets/project_cves/index.html"

    actual_context_ns = actual_call_args_ns[1]
    actual_project_ns = actual_context_ns.pop("project")
    actual_cves_ns = actual_context_ns.pop("cves")

    assert actual_context_ns == {
        "widget_id": "c2d3e4f5-a6b7-c8d9-e0f1-a2b3c4d5e6f7",
        "widget_type": "project_cves",
        "title": "CVEs for Project No Subs",
        "config": widget_no_subs.configuration,
        "request": mock_request,
    }
    assert actual_project_ns == project_no_subs
    assert list(actual_cves_ns) == []


# TagsWidget class


@pytest.mark.django_db
def test_tags_widget_index(
    create_user,
    create_organization,
):
    """
    Test TagsWidget.index to ensure only the current user's tags are returned.
    """
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")
    org = create_organization(name="org1", owner=user1)

    tag1_user1 = UserTag.objects.create(name="tag1_u1", user=user1)
    tag2_user1 = UserTag.objects.create(name="tag2_u1", user=user1)
    tag1_user2 = UserTag.objects.create(name="tag1_u2", user=user2)

    mock_request = MagicMock()
    mock_request.user = user1
    mock_request.current_organization = org

    widget = TagsWidget(
        mock_request,
        {
            "id": "d1e2f3a4-b5c6-d7e8-f9a0-b1c2d3e4f5a6",
            "type": "tags",
            "title": "My Tags",
        },
    )

    with patch("dashboards.widgets.render_to_string") as mock_render:
        widget.index()

    # Assertions
    mock_render.assert_called_once()

    actual_call_args, _ = mock_render.call_args
    actual_template_name = actual_call_args[0]
    assert actual_template_name == "dashboards/widgets/tags/index.html"

    actual_context = actual_call_args[1]
    actual_tags = actual_context.pop("tags")
    assert actual_context == {
        "widget_id": "d1e2f3a4-b5c6-d7e8-f9a0-b1c2d3e4f5a6",
        "widget_type": "tags",
        "title": "My Tags",
        "config": widget.configuration,
        "request": mock_request,
    }

    assert list(actual_tags) == [tag1_user1, tag2_user1]
    assert tag1_user2 not in actual_tags


# ProjectsWidget class


@pytest.mark.django_db
def test_projects_widget_index(
    create_user,
    create_organization,
    create_project,
):
    """
    Test ProjectsWidget.index to ensure only projects from the current organization are returned.
    """
    user1 = create_user(username="user1")
    org1 = create_organization(name="Org Alpha", owner=user1)
    user2 = create_user(username="user2")
    org2 = create_organization(name="Org Beta", owner=user2)

    proj_b_org1 = create_project(name="Project B", organization=org1)
    proj_a_org1 = create_project(name="Project A", organization=org1)
    proj_c_org2 = create_project(name="Project C", organization=org2)

    mock_request = MagicMock()
    mock_request.user = user1
    mock_request.current_organization = org1

    widget = ProjectsWidget(
        mock_request,
        {
            "id": "e1f2a3b4-c5d6-e7f8-a9b0-c1d2e3f4a5b6",
            "type": "projects",
            "title": "Organization Projects",
        },
    )

    with patch("dashboards.widgets.render_to_string") as mock_render:
        widget.index()

    # Assertions
    mock_render.assert_called_once()

    actual_call_args, _ = mock_render.call_args
    actual_template_name = actual_call_args[0]
    assert actual_template_name == "dashboards/widgets/projects/index.html"

    actual_context = actual_call_args[1]
    actual_organization = actual_context.pop("organization")
    actual_projects = actual_context.pop("projects")
    assert actual_context == {
        "widget_id": "e1f2a3b4-c5d6-e7f8-a9b0-c1d2e3f4a5b6",
        "widget_type": "projects",
        "title": "Organization Projects",
        "config": widget.configuration,
        "request": mock_request,
    }

    assert actual_organization == org1
    assert list(actual_projects) == [proj_a_org1, proj_b_org1]
    assert proj_c_org2 not in actual_projects


# LastReportsWidget class


@pytest.mark.django_db
def test_last_reports_widget_index(
    create_user,
    create_organization,
    create_project,
):
    """
    Test LastReportsWidget.index to ensure only reports from the current
    organization's projects are returned
    """
    user1 = create_user(username="user1")
    org1 = create_organization(name="Org Alpha", owner=user1)
    proj_org1 = create_project(name="Project Alpha", organization=org1)

    user2 = create_user(username="user2")
    org2 = create_organization(name="Org Beta", owner=user2)
    proj_org2 = create_project(name="Project Beta", organization=org2)

    # Reports for org1
    report_old_org1 = Report.objects.create(project=proj_org1, day=date(2024, 1, 15))
    report_new_org1 = Report.objects.create(project=proj_org1, day=date(2024, 1, 20))

    # Report for org2
    report_org2 = Report.objects.create(project=proj_org2, day=date(2024, 1, 18))

    mock_request = MagicMock()
    mock_request.user = user1
    mock_request.current_organization = org1

    widget = LastReportsWidget(
        mock_request,
        {
            "id": "f1a2b3c4-d5e6-f7a8-b9c0-d1e2f3a4b5c6",
            "type": "last_reports",
            "title": "Latest Reports",
        },
    )

    with patch("dashboards.widgets.render_to_string") as mock_render:
        widget.index()

    # Assertions
    mock_render.assert_called_once()

    actual_call_args, _ = mock_render.call_args
    actual_template_name = actual_call_args[0]
    assert actual_template_name == "dashboards/widgets/last_reports/index.html"

    actual_context = actual_call_args[1]
    actual_organization = actual_context.pop("organization")
    actual_reports = actual_context.pop("reports")
    assert actual_context == {
        "widget_id": "f1a2b3c4-d5e6-f7a8-b9c0-d1e2f3a4b5c6",
        "widget_type": "last_reports",
        "title": "Latest Reports",
        "config": widget.configuration,
        "request": mock_request,
    }

    assert actual_organization == org1
    assert list(actual_reports) == [report_new_org1, report_old_org1]
    assert report_org2 not in actual_reports


# MyAssignedCvesWidget class


@pytest.mark.django_db
def test_my_assigned_cves_widget_index(
    create_user,
    create_organization,
    create_project,
    create_cve,
):
    """
    Test MyAssignedCvesWidget.index to ensure only CVEs assigned to the current user
    across organization projects are returned.
    """
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")
    org1 = create_organization(name="org1", owner=user1)
    org2 = create_organization(name="org2", owner=user2)

    project1_org1 = create_project(name="Project1 Org1", organization=org1, active=True)
    project2_org1 = create_project(name="Project2 Org1", organization=org1, active=True)
    project1_org2 = create_project(name="Project1 Org2", organization=org2, active=True)

    cve1 = create_cve("CVE-2021-34181")
    cve2 = create_cve("CVE-2022-20698")
    cve3 = create_cve("CVE-2023-22490")
    cve4 = create_cve("CVE-2024-31331")

    # Create trackers: user1 assigned to cve1 and cve2 in org1 projects
    CveTracker.update_tracker(
        project=project1_org1, cve=cve1, assignee=user1, status="to_evaluate"
    )
    CveTracker.update_tracker(
        project=project2_org1, cve=cve2, assignee=user1, status="pending_review"
    )
    # user2 assigned to cve3 in org1 (should not appear for user1)
    CveTracker.update_tracker(
        project=project1_org1, cve=cve3, assignee=user2, status="to_evaluate"
    )
    # user1 assigned to cve4 in org2 (should not appear, different org)
    CveTracker.update_tracker(
        project=project1_org2, cve=cve4, assignee=user1, status="to_evaluate"
    )

    mock_request = MagicMock()
    mock_request.user = user1
    mock_request.current_organization = org1

    widget = MyAssignedCvesWidget(
        mock_request,
        {
            "id": "a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6",
            "type": "my_assignment_cves",
            "title": "My Assigned CVEs",
            "config": {},
        },
    )

    with patch("dashboards.widgets.render_to_string") as mock_render:
        widget.index()

    # Assertions
    mock_render.assert_called_once()

    actual_call_args, _ = mock_render.call_args
    actual_template_name = actual_call_args[0]
    assert actual_template_name == "dashboards/widgets/my_assignment_cves/index.html"

    actual_context = actual_call_args[1]
    actual_trackers = actual_context.pop("trackers")
    assert actual_context == {
        "widget_id": "a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6",
        "widget_type": "my_assignment_cves",
        "title": "My Assigned CVEs",
        "config": {},
        "request": mock_request,
    }

    # Verify only trackers for CVEs assigned to user1 in org1 are returned
    returned_cve_ids = {t.cve.cve_id for t in actual_trackers}
    assert cve1.cve_id in returned_cve_ids
    assert cve2.cve_id in returned_cve_ids
    assert cve3.cve_id not in returned_cve_ids  # Assigned to user2
    assert cve4.cve_id not in returned_cve_ids  # Different organization


# AssignmentCvesWidget class


@pytest.mark.django_db
def test_assignment_cves_widget_validate_config(
    create_user,
    create_organization,
    create_project,
):
    """
    Test AssignmentCvesWidget.validate_config for various scenarios:
    - Invalid assignee_id format
    - Assignee not found or not in organization
    - Invalid status
    - Invalid project_id format
    - Project not found or inactive
    """
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")
    org1 = create_organization(name="org1", user=user1)
    org2 = create_organization(name="org2", user=user2)

    project1_org1 = create_project(name="project1", organization=org1, active=True)
    project2_org1 = create_project(name="project2", organization=org1, active=False)
    project1_org2 = create_project(name="project3", organization=org2, active=True)

    mock_request = MagicMock()
    mock_request.user = user1
    mock_request.current_organization = org1

    widget = AssignmentCvesWidget(
        mock_request,
        {
            "id": "b1c2d3e4-f5a6-b7c8-d9e0-f1a2b3c4d5e6",
            "type": "assignment_cves",
            "title": "CVEs by Assignment",
            "config": {"assignee_id": "", "status": "", "project_id": ""},
        },
    )

    # Valid empty config
    assert widget.validate_config({}) == {
        "assignee_id": "",
        "status": "",
        "project_id": "",
    }

    # Invalid assignee_id format (not UUID)
    with pytest.raises(ValueError, match=re.escape("Invalid assignee ID (not-a-uuid)")):
        widget.validate_config(
            {"assignee_id": "not-a-uuid", "status": "", "project_id": ""}
        )

    # Assignee not found
    non_existent_uuid = str(uuid.uuid4())
    with pytest.raises(
        ValueError, match=re.escape(f"Assignee not found ({non_existent_uuid})")
    ):
        widget.validate_config(
            {"assignee_id": non_existent_uuid, "status": "", "project_id": ""}
        )

    # Assignee in different organization (user2 is not member of org1 yet)
    with pytest.raises(ValueError, match=re.escape(f"Assignee not found ({user2.id})")):
        widget.validate_config(
            {"assignee_id": str(user2.id), "status": "", "project_id": ""}
        )

    # Valid assignee_id (user1 is owner of org1)
    valid_config_assignee = widget.validate_config(
        {"assignee_id": str(user1.id), "status": "", "project_id": ""}
    )
    assert valid_config_assignee == {
        "assignee_id": str(user1.id),
        "status": "",
        "project_id": "",
    }

    # Now add user2 as member of org1 and test again
    Membership.objects.create(
        user=user2,
        organization=org1,
        role=Membership.MEMBER,
        date_invited=timezone.now(),
        date_joined=timezone.now(),
    )

    # Valid assignee_id for user2 (now member of org1)
    valid_config_assignee_user2 = widget.validate_config(
        {"assignee_id": str(user2.id), "status": "", "project_id": ""}
    )
    assert valid_config_assignee_user2 == {
        "assignee_id": str(user2.id),
        "status": "",
        "project_id": "",
    }

    # Invalid status
    with pytest.raises(ValueError, match=re.escape("Invalid status (invalid_status)")):
        widget.validate_config(
            {"assignee_id": "", "status": "invalid_status", "project_id": ""}
        )

    # Valid status
    valid_config_status = widget.validate_config(
        {"assignee_id": "", "status": "to_evaluate", "project_id": ""}
    )
    assert valid_config_status == {
        "assignee_id": "",
        "status": "to_evaluate",
        "project_id": "",
    }

    # Invalid project_id format
    with pytest.raises(ValueError, match=re.escape("Invalid project ID (not-a-uuid)")):
        widget.validate_config(
            {"assignee_id": "", "status": "", "project_id": "not-a-uuid"}
        )

    # Project not found
    non_existent_project_uuid = str(uuid.uuid4())
    with pytest.raises(
        ValueError,
        match=re.escape(f"Project not found ({non_existent_project_uuid})"),
    ):
        widget.validate_config(
            {
                "assignee_id": "",
                "status": "",
                "project_id": non_existent_project_uuid,
            }
        )

    # Project in different organization
    with pytest.raises(
        ValueError, match=re.escape(f"Project not found ({project1_org2.id})")
    ):
        widget.validate_config(
            {"assignee_id": "", "status": "", "project_id": str(project1_org2.id)}
        )

    # Inactive project
    with pytest.raises(
        ValueError, match=re.escape(f"Inactive project ({project2_org1.id})")
    ):
        widget.validate_config(
            {"assignee_id": "", "status": "", "project_id": str(project2_org1.id)}
        )

    # Valid project_id
    valid_config_project = widget.validate_config(
        {"assignee_id": "", "status": "", "project_id": str(project1_org1.id)}
    )
    assert valid_config_project == {
        "assignee_id": "",
        "status": "",
        "project_id": str(project1_org1.id),
    }

    # Valid config with all fields
    valid_config_all = widget.validate_config(
        {
            "assignee_id": str(user1.id),
            "status": "resolved",
            "project_id": str(project1_org1.id),
        }
    )
    assert valid_config_all == {
        "assignee_id": str(user1.id),
        "status": "resolved",
        "project_id": str(project1_org1.id),
    }


@pytest.mark.django_db
def test_assignment_cves_widget_config(
    create_user,
    create_organization,
    create_project,
):
    """
    Test AssignmentCvesWidget.config to ensure correct members, projects,
    and status choices are passed to the config template.
    """
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")
    org1 = create_organization(name="org1", user=user1)
    org2 = create_organization(name="org2", user=user2)

    project_active_org1 = create_project(
        name="Active Org1", organization=org1, active=True
    )
    project_inactive_org1 = create_project(
        name="Inactive Org1", organization=org1, active=False
    )
    project_active_org2 = create_project(
        name="Active Org2", organization=org2, active=True
    )

    # Add user2 as member of org1 for testing
    Membership.objects.create(
        user=user2,
        organization=org1,
        role=Membership.MEMBER,
        date_invited=timezone.now(),
        date_joined=timezone.now(),
    )

    mock_request = MagicMock()
    mock_request.user = user1
    mock_request.current_organization = org1

    widget = AssignmentCvesWidget(
        mock_request,
        {
            "id": "c1d2e3f4-a5b6-c7d8-e9f0-a1b2c3d4e5f6",
            "type": "assignment_cves",
            "title": "CVEs by Assignment Config",
            "config": {"assignee_id": "", "status": "", "project_id": ""},
        },
    )

    with patch("dashboards.widgets.render_to_string") as mock_render:
        widget.config()

    # Assertions
    mock_render.assert_called_once()

    actual_call_args, _ = mock_render.call_args
    actual_template_name = actual_call_args[0]
    assert actual_template_name == "dashboards/widgets/assignment_cves/config.html"

    actual_context = actual_call_args[1]
    actual_members = actual_context.pop("members")
    actual_projects = actual_context.pop("projects")
    actual_status_choices = actual_context.pop("status_choices")
    assert actual_context == {
        "widget_id": "c1d2e3f4-a5b6-c7d8-e9f0-a1b2c3d4e5f6",
        "widget_type": "assignment_cves",
        "title": "CVEs by Assignment Config",
        "config": widget.configuration,
        "request": mock_request,
    }

    # Verify only active project from org1 is passed
    assert list(actual_projects) == [project_active_org1]
    returned_project_ids = {p.id for p in actual_projects}
    assert project_inactive_org1.id not in returned_project_ids
    assert project_active_org2.id not in returned_project_ids

    # Verify members from org1 are included
    returned_member_ids = {m.id for m in actual_members}
    assert user1.id in returned_member_ids
    assert user2.id in returned_member_ids  # user2 is member of org1

    # Verify status choices are passed
    assert actual_status_choices == CveTracker.STATUS_CHOICES


@pytest.mark.django_db
def test_assignment_cves_widget_index(
    create_user,
    create_organization,
    create_project,
    create_cve,
):
    """
    Test AssignmentCvesWidget.index to ensure CVEs are filtered correctly
    by assignee, status, and project.
    """
    user1 = create_user(username="user1")
    user2 = create_user(username="user2")
    org1 = create_organization(name="org1", user=user1)

    project1 = create_project(name="Project1", organization=org1, active=True)
    project2 = create_project(name="Project2", organization=org1, active=True)

    # Add user2 as member of org1 for testing
    Membership.objects.create(
        user=user2,
        organization=org1,
        role=Membership.MEMBER,
        date_invited=timezone.now(),
        date_joined=timezone.now(),
    )

    cve1 = create_cve("CVE-2021-34181")
    cve2 = create_cve("CVE-2022-20698")
    cve3 = create_cve("CVE-2023-22490")
    cve4 = create_cve("CVE-2024-31331")

    # Create trackers with different combinations
    CveTracker.update_tracker(
        project=project1, cve=cve1, assignee=user1, status="to_evaluate"
    )
    CveTracker.update_tracker(
        project=project1, cve=cve2, assignee=user1, status="resolved"
    )
    CveTracker.update_tracker(
        project=project1, cve=cve3, assignee=user2, status="to_evaluate"
    )
    CveTracker.update_tracker(
        project=project2, cve=cve4, assignee=user1, status="to_evaluate"
    )

    mock_request = MagicMock()
    mock_request.user = user1
    mock_request.current_organization = org1

    # Test with no filters (all CVEs in organization)
    widget = AssignmentCvesWidget(
        mock_request,
        {
            "id": "d1e2f3a4-b5c6-d7e8-f9a0-b1c2d3e4f5a6",
            "type": "assignment_cves",
            "title": "CVEs by Assignment",
            "config": {"assignee_id": "", "status": "", "project_id": ""},
        },
    )

    with patch("dashboards.widgets.render_to_string") as mock_render:
        widget.index()

    mock_render.assert_called_once()
    actual_call_args, _ = mock_render.call_args
    actual_context = actual_call_args[1]
    actual_trackers = actual_context.pop("trackers")
    returned_cve_ids = {t.cve.cve_id for t in actual_trackers}

    assert cve1.cve_id in returned_cve_ids
    assert cve2.cve_id in returned_cve_ids
    assert cve3.cve_id in returned_cve_ids
    assert cve4.cve_id in returned_cve_ids

    # Test with assignee filter
    widget_assignee = AssignmentCvesWidget(
        mock_request,
        {
            "id": "e1f2a3b4-c5d6-e7f8-a9b0-c1d2e3f4a5b6",
            "type": "assignment_cves",
            "title": "CVEs by Assignment",
            "config": {
                "assignee_id": str(user1.id),
                "status": "",
                "project_id": "",
            },
        },
    )

    with patch("dashboards.widgets.render_to_string") as mock_render_assignee:
        widget_assignee.index()

    actual_call_args_assignee, _ = mock_render_assignee.call_args
    actual_context_assignee = actual_call_args_assignee[1]
    actual_trackers_assignee = actual_context_assignee.pop("trackers")
    returned_cve_ids_assignee = {t.cve.cve_id for t in actual_trackers_assignee}

    assert cve1.cve_id in returned_cve_ids_assignee
    assert cve2.cve_id in returned_cve_ids_assignee
    assert cve4.cve_id in returned_cve_ids_assignee
    assert cve3.cve_id not in returned_cve_ids_assignee  # Assigned to user2

    # Test with status filter
    widget_status = AssignmentCvesWidget(
        mock_request,
        {
            "id": "f1a2b3c4-d5e6-f7a8-b9c0-d1e2f3a4b5c6",
            "type": "assignment_cves",
            "title": "CVEs by Assignment",
            "config": {
                "assignee_id": "",
                "status": "to_evaluate",
                "project_id": "",
            },
        },
    )

    with patch("dashboards.widgets.render_to_string") as mock_render_status:
        widget_status.index()

    actual_call_args_status, _ = mock_render_status.call_args
    actual_context_status = actual_call_args_status[1]
    actual_trackers_status = actual_context_status.pop("trackers")
    returned_cve_ids_status = {t.cve.cve_id for t in actual_trackers_status}

    assert cve1.cve_id in returned_cve_ids_status
    assert cve3.cve_id in returned_cve_ids_status
    assert cve4.cve_id in returned_cve_ids_status
    assert cve2.cve_id not in returned_cve_ids_status  # Status is "resolved"

    # Test with project filter
    widget_project = AssignmentCvesWidget(
        mock_request,
        {
            "id": "a1b2c3d4-e5f6-a7b8-c9d0-e1f2a3b4c5d6",
            "type": "assignment_cves",
            "title": "CVEs by Assignment",
            "config": {
                "assignee_id": "",
                "status": "",
                "project_id": str(project1.id),
            },
        },
    )

    with patch("dashboards.widgets.render_to_string") as mock_render_project:
        widget_project.index()

    actual_call_args_project, _ = mock_render_project.call_args
    actual_context_project = actual_call_args_project[1]
    actual_trackers_project = actual_context_project.pop("trackers")
    returned_cve_ids_project = {t.cve.cve_id for t in actual_trackers_project}

    assert cve1.cve_id in returned_cve_ids_project
    assert cve2.cve_id in returned_cve_ids_project
    assert cve3.cve_id in returned_cve_ids_project
    assert cve4.cve_id not in returned_cve_ids_project  # In project2

    # Test with all filters combined
    widget_all = AssignmentCvesWidget(
        mock_request,
        {
            "id": "b1c2d3e4-f5a6-b7c8-d9e0-f1a2b3c4d5e6",
            "type": "assignment_cves",
            "title": "CVEs by Assignment",
            "config": {
                "assignee_id": str(user1.id),
                "status": "to_evaluate",
                "project_id": str(project1.id),
            },
        },
    )

    with patch("dashboards.widgets.render_to_string") as mock_render_all:
        widget_all.index()

    actual_call_args_all, _ = mock_render_all.call_args
    actual_context_all = actual_call_args_all[1]
    actual_trackers_all = actual_context_all.pop("trackers")
    returned_cve_ids_all = {t.cve.cve_id for t in actual_trackers_all}

    assert cve1.cve_id in returned_cve_ids_all
    assert cve2.cve_id not in returned_cve_ids_all  # Status is "resolved"
    assert cve3.cve_id not in returned_cve_ids_all  # Assigned to user2
    assert cve4.cve_id not in returned_cve_ids_all  # In project2
