import pytest
from bs4 import BeautifulSoup
from django.test import override_settings
from django.urls import reverse
from django.utils.timezone import now
from unittest.mock import patch, MagicMock
import uuid
import json
from django.http import JsonResponse
from django.http import HttpRequest

from dashboards.widgets import list_widgets
from dashboards.models import Dashboard
from dashboards.views import (
    BaseWidgetDataView,
    DashboardView,
    SaveDashboardView,
)
from organizations.models import Membership


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
def test_dashboard_view_context(client, auth_client, create_user, create_organization):
    """
    Test that DashboardView correctly passes the sorted list of widgets to the template context.
    """
    # Test unauthenticated access
    response = client.get(reverse("home"))
    assert response.status_code == 302
    assert reverse("cves") in response.url

    user = create_user()
    create_organization(name="Test Org", user=user)
    client = auth_client(user)
    response = client.get(reverse("home"))

    # Assertions
    assert response.status_code == 200
    assert response.template_name == ["dashboards/index.html"]
    assert "widgets" in response.context

    expected_widgets = sorted(list_widgets().values(), key=lambda x: x["name"])
    assert response.context["widgets"] == expected_widgets

    soup = BeautifulSoup(response.content, features="html.parser")
    assert [
        n.text.split("\n")[0]
        for n in soup.find("div", {"id": "modal-add-widget"}).find_all(
            "strong", {"class": "product-title"}
        )
    ] == [w["name"] for w in expected_widgets]


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
def test_dashboard_view_get_context_data(
    auth_client, create_user, create_organization, create_dashboard
):
    """
    Test DashboardView.get_context_data: widgets, dashboards list, default dashboard
    creation/selection, and dashboards_data structure.
    """
    user = create_user()
    organization = create_organization(name="Test Org", user=user)
    client = auth_client(user)
    request = client.get(reverse("home")).wsgi_request
    request.user = user
    request.current_organization = organization

    view = DashboardView()
    view.request = request
    view.kwargs = {}
    context = view.get_context_data()

    # Widgets: sorted by name
    expected_widgets = sorted(list_widgets().values(), key=lambda x: x["name"])
    assert context["widgets"] == expected_widgets

    # No dashboards initially -> default is created
    assert "dashboards" in context
    assert "default_dashboard_id" in context
    assert "dashboards_data" in context
    assert len(context["dashboards"]) == 1
    assert context["dashboards"][0]["name"] == "Default"
    assert context["dashboards"][0]["is_default"] is True
    assert context["dashboards"][0]["id"] == context["default_dashboard_id"]
    assert context["dashboards_data"] == {
        "dashboards": context["dashboards"],
        "default_dashboard_id": context["default_dashboard_id"],
    }

    default_id = context["default_dashboard_id"]
    default_db = Dashboard.objects.get(id=default_id)
    assert default_db.organization_id == organization.id
    assert default_db.user_id == user.id
    assert default_db.is_default is True
    assert "widgets" in default_db.config

    # Existing dashboards, none marked default -> first becomes default
    create_dashboard(
        organization=organization,
        user=user,
        name="Second",
        config={"widgets": []},
        is_default=False,
    )
    Dashboard.objects.filter(organization=organization, user=user).update(
        is_default=False
    )
    context2 = view.get_context_data()
    assert len(context2["dashboards"]) == 2
    default_in_list = next(d for d in context2["dashboards"] if d["is_default"])
    assert context2["dashboards_data"]["default_dashboard_id"] == default_in_list["id"]
    assert (
        Dashboard.objects.filter(
            organization=organization, user=user, is_default=True
        ).count()
        == 1
    )

    # Each dashboard entry has id, name, is_default
    for d in context2["dashboards"]:
        assert set(d.keys()) == {"id", "name", "is_default"}
        assert d["id"] and d["name"]


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
@patch("dashboards.models.uuid.uuid4")
def test_load_dashboard_view(
    mock_uuid4, client, auth_client, create_user, create_organization
):
    """
    Test that LoadDashboardView returns the correct dashboard config.
    """
    mock_uuid4.return_value = uuid.UUID("12345678-1234-5678-1234-567812345678")

    # Check unauthenticated access
    response = client.get(reverse("load_dashboard"))
    assert response.status_code == 302
    assert reverse("account_login") in response.url

    user = create_user()
    organization = create_organization(name="Test Org", user=user)
    client = auth_client(user)

    # Check default dashboard
    response = client.get(reverse("load_dashboard"))
    dashboard = Dashboard.objects.get(
        organization=organization, user=user, is_default=True
    )
    expected_config = Dashboard.get_default_config(client.request().wsgi_request)

    assert response.status_code == 200
    assert response.json() == expected_config
    assert dashboard.config == expected_config

    # Check existing dashboard
    custom_config = {"widgets": [{"id": "custom-widget", "type": "test"}]}
    dashboard.config = custom_config
    dashboard.save()

    response = client.get(reverse("load_dashboard"))
    assert response.status_code == 200
    assert response.json() == custom_config
    assert (
        Dashboard.objects.filter(
            organization=organization, user=user, is_default=True
        ).count()
        == 1
    )


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
def test_load_dashboard_view_no_organization(client, auth_client, create_user):
    """
    LoadDashboardView returns 400 when user is authenticated but has no organization.
    """
    user = create_user()
    client = auth_client(user)
    # User has no organization; middleware leaves current_organization as None
    response = client.get(reverse("load_dashboard"))
    assert response.status_code == 400
    assert response.json() == {"error": "No organization selected"}


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
@patch("dashboards.models.uuid.uuid4")
def test_load_dashboard_view_by_id(
    mock_uuid4, client, auth_client, create_user, create_organization, create_dashboard
):
    """
    LoadDashboardView with dashboard_id: returns config for that dashboard or 404.
    """
    mock_uuid4.return_value = uuid.UUID("12345678-1234-5678-1234-567812345678")

    user = create_user()
    organization = create_organization(name="Test Org", user=user)
    client = auth_client(user)

    default_dash = create_dashboard(
        organization=organization,
        user=user,
        name="Default",
        config={
            "widgets": [{"id": "w1", "type": "tags", "title": "Tags", "config": {}}]
        },
        is_default=True,
    )
    other_dash = create_dashboard(
        organization=organization,
        user=user,
        name="Other",
        config={
            "widgets": [
                {
                    "id": "w2",
                    "type": "activity",
                    "title": "Activity",
                    "config": {"activities_view": "all"},
                }
            ]
        },
        is_default=False,
    )

    # Load by id: returns that dashboard's config
    response = client.get(
        reverse("load_dashboard"), {"dashboard_id": str(other_dash.id)}
    )
    assert response.status_code == 200
    assert response.json() == other_dash.config
    assert response.json()["widgets"][0]["id"] == "w2"

    response_default = client.get(
        reverse("load_dashboard"), {"dashboard_id": str(default_dash.id)}
    )
    assert response_default.status_code == 200
    assert response_default.json() == default_dash.config

    # Invalid id: 404
    response_404 = client.get(
        reverse("load_dashboard"),
        {"dashboard_id": "00000000-0000-0000-0000-000000000000"},
    )
    assert response_404.status_code == 404
    assert response_404.json() == {"error": "Dashboard not found"}

    # Dashboard of another user returns 404
    other_user = create_user(username="other_user")
    Membership.objects.create(
        user=other_user,
        organization=organization,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    other_user_dash = create_dashboard(
        organization=organization,
        user=other_user,
        name="Other User Dashboard",
        config={"widgets": []},
        is_default=True,
    )
    response_other = client.get(
        reverse("load_dashboard"), {"dashboard_id": str(other_user_dash.id)}
    )
    assert response_other.status_code == 404
    assert response_other.json() == {"error": "Dashboard not found"}


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
def test_save_dashboard_validate_widgets_config(
    auth_client, create_user, create_organization
):
    """
    Test the static method validate_widgets_config in SaveDashboardView.
    """
    user = create_user()
    client = auth_client(user)
    organization = create_organization(name="Test Org", user=user)

    request = client.request().wsgi_request
    request.current_organization = organization
    request.user = user

    valid_uuid = str(uuid.uuid4())

    # Valid configuration
    valid_widgets = [
        {"id": valid_uuid, "type": "tags", "title": "My Tags", "config": {}},
        {
            "id": str(uuid.uuid4()),
            "type": "activity",
            "title": "Activity",
            "config": {"activities_view": "all"},
        },
    ]
    is_clean, result = SaveDashboardView.validate_widgets_config(request, valid_widgets)
    assert is_clean is True
    assert len(result) == 2
    assert result[0]["id"] == valid_uuid
    assert result[0]["type"] == "tags"
    assert result[0]["config"] == {}  # TagsWidget cleans config
    assert result[1]["type"] == "activity"
    assert result[1]["config"] == {"activities_view": "all"}

    # Invalid Widget ID
    invalid_id_widgets = [
        {"id": "not-a-uuid", "type": "tags", "title": "Invalid Tags", "config": {}},
    ]
    is_clean, result = SaveDashboardView.validate_widgets_config(
        request, invalid_id_widgets
    )
    assert is_clean is False
    assert result == "Error creating widget instance"

    # Invalid Widget Type
    invalid_type_widgets = [
        {
            "id": str(uuid.uuid4()),
            "type": "invalid_type",
            "title": "Invalid Type",
            "config": {},
        },
    ]
    is_clean, result = SaveDashboardView.validate_widgets_config(
        request, invalid_type_widgets
    )
    assert is_clean is False
    assert result == "Invalid widget type"

    # Invalid Widget Config (ActivityWidget)
    invalid_config_widgets = [
        {
            "id": str(uuid.uuid4()),
            "type": "activity",
            "title": "Invalid Activity Config",
            "config": {"activities_view": "invalid_value"},
        },
    ]
    is_clean, result = SaveDashboardView.validate_widgets_config(
        request, invalid_config_widgets
    )
    assert is_clean is False
    assert result == "Error creating widget instance"


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
@patch("dashboards.models.uuid.uuid4")
def test_save_dashboard_view_post(
    mock_uuid4, client, auth_client, create_user, create_organization
):
    """
    Test the post method of SaveDashboardView.
    """
    fixed_uuid_str = "12345678-1234-5678-1234-567812345678"
    mock_uuid4.return_value = uuid.UUID(fixed_uuid_str)

    # Check unauthenticated access
    response = client.get(reverse("load_dashboard"))
    assert response.status_code == 302
    assert reverse("account_login") in response.url

    user = create_user()
    client = auth_client(user)
    organization = create_organization(name="Test Org", user=user)

    # Invalid payload, no dashboard created
    invalid_payload = [
        {"id": "not-a-uuid", "type": "tags", "title": "Invalid ID", "config": {}}
    ]
    response = client.post(
        reverse("save_dashboard"),
        data=json.dumps({"widgets": invalid_payload}),
        content_type="application/json",
    )
    assert response.status_code == 400
    assert response.json() == {"error": "Error creating widget instance"}
    assert not Dashboard.objects.filter(
        organization=organization, user=user, is_default=True
    ).exists()

    # Valid payload, dashboard created
    initial_payload = [
        {"id": fixed_uuid_str, "type": "tags", "title": "My Tags", "config": {}}
    ]
    response = client.post(
        reverse("save_dashboard"),
        data=json.dumps({"widgets": initial_payload}),
        content_type="application/json",
    )
    assert response.status_code == 200
    assert response.json() == {"message": "dashboard saved"}
    assert (
        Dashboard.objects.filter(
            organization=organization, user=user, is_default=True
        ).count()
        == 1
    )

    dashboard = Dashboard.objects.get(
        organization=organization, user=user, is_default=True
    )
    assert dashboard.config == {
        "widgets": [
            {"id": fixed_uuid_str, "type": "tags", "title": "My Tags", "config": {}}
        ]
    }

    # Valid payload, dashboard updated
    updated_payload = [
        {"id": fixed_uuid_str, "type": "tags", "title": "Updated Tags", "config": {}},
        {
            "id": str(uuid.uuid4()),
            "type": "activity",
            "title": "Activity Feed",
            "config": {"activities_view": "subscriptions"},
        },
    ]
    response = client.post(
        reverse("save_dashboard"),
        data=json.dumps({"widgets": updated_payload}),
        content_type="application/json",
    )
    assert response.status_code == 200
    assert response.json() == {"message": "dashboard saved"}

    # Check dashboard update and config
    assert (
        Dashboard.objects.filter(
            organization=organization, user=user, is_default=True
        ).count()
        == 1
    )

    dashboard.refresh_from_db()
    assert dashboard.config == {
        "widgets": [
            {
                "id": fixed_uuid_str,
                "type": "tags",
                "title": "Updated Tags",
                "config": {},
            },
            {
                "id": fixed_uuid_str,
                "type": "activity",
                "title": "Activity Feed",
                "config": {"activities_view": "subscriptions"},
            },
        ]
    }


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
@patch("dashboards.models.uuid.uuid4")
def test_save_dashboard_view_post_with_dashboard_id(
    mock_uuid4, client, auth_client, create_user, create_organization, create_dashboard
):
    """
    SaveDashboardView POST with dashboard_id in payload saves config to that dashboard,
    not the default one.
    """
    fixed_uuid_str = "12345678-1234-5678-1234-567812345678"
    mock_uuid4.return_value = uuid.UUID(fixed_uuid_str)

    user = create_user()
    client = auth_client(user)
    organization = create_organization(name="Test Org", user=user)

    default_dash = create_dashboard(
        organization=organization,
        user=user,
        name="Default",
        config={"widgets": []},
        is_default=True,
    )
    custom_dash = create_dashboard(
        organization=organization,
        user=user,
        name="My Dashboard",
        config={
            "widgets": [{"id": "old", "type": "tags", "title": "Old", "config": {}}]
        },
        is_default=False,
    )

    payload = {
        "widgets": [
            {
                "id": fixed_uuid_str,
                "type": "tags",
                "title": "Tags on custom",
                "config": {},
            },
            {
                "id": str(uuid.uuid4()),
                "type": "activity",
                "title": "Activity on custom",
                "config": {"activities_view": "all"},
            },
        ],
        "dashboard_id": str(custom_dash.id),
    }
    response = client.post(
        reverse("save_dashboard"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert response.status_code == 200
    assert response.json() == {"message": "dashboard saved"}

    custom_dash.refresh_from_db()
    assert custom_dash.config["widgets"][0]["title"] == "Tags on custom"
    assert custom_dash.config["widgets"][1]["title"] == "Activity on custom"
    assert len(custom_dash.config["widgets"]) == 2

    default_dash.refresh_from_db()
    assert default_dash.config == {"widgets": []}

    # Invalid dashboard_id returns 404
    response_404 = client.post(
        reverse("save_dashboard"),
        data=json.dumps(
            {"widgets": [], "dashboard_id": "00000000-0000-0000-0000-000000000000"}
        ),
        content_type="application/json",
    )
    assert response_404.status_code == 404
    assert response_404.json() == {"error": "Dashboard not found"}


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
def test_create_dashboard_view_post_no_organization(client, auth_client, create_user):
    """
    CreateDashboardView returns 400 when user is authenticated but has no organization.
    """
    user = create_user()
    client = auth_client(user)
    response = client.post(reverse("create_dashboard"), data={})
    assert response.status_code == 400
    assert response.json() == {"error": "No organization selected"}


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
def test_create_dashboard_view_post(
    client, auth_client, create_user, create_organization, create_dashboard
):
    """
    CreateDashboardView POST creates a new dashboard and iterate the name.
    """
    user = create_user()
    organization = create_organization(name="Test Org", user=user)
    client = auth_client(user)

    # First create: "New Dashboard"
    response = client.post(reverse("create_dashboard"), data={})
    assert response.status_code == 201
    data = response.json()
    assert "id" in data
    assert data["name"] == "New Dashboard"
    dash1 = Dashboard.objects.get(id=data["id"])
    assert dash1.organization == organization
    assert dash1.user == user
    assert dash1.name == "New Dashboard"
    assert dash1.is_default is False
    assert dash1.config == {"widgets": []}

    # Second create: "New Dashboard (1)"
    response = client.post(reverse("create_dashboard"), data={})
    assert response.status_code == 201
    assert response.json()["name"] == "New Dashboard (1)"
    assert Dashboard.objects.filter(organization=organization, user=user).count() == 2

    # Third create: "New Dashboard (2)"
    response = client.post(reverse("create_dashboard"), data={})
    assert response.status_code == 201
    assert response.json()["name"] == "New Dashboard (2)"

    # One more existing name: next create gets "New Dashboard (4)"
    create_dashboard(
        organization=organization,
        user=user,
        name="New Dashboard (3)",
        config={"widgets": []},
        is_default=False,
    )
    response = client.post(reverse("create_dashboard"), data={})
    assert response.status_code == 201
    assert response.json()["name"] == "New Dashboard (4)"


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
def test_update_dashboard_view_validation_and_not_found(
    client, auth_client, create_user, create_organization, create_dashboard
):
    """
    Error handling for UpdateDashboardView.
    """
    # Unauthenticated access
    response_unauth = client.post(
        reverse("update_dashboard"),
        data=json.dumps({"dashboard_id": "00000000-0000-0000-0000-000000000000"}),
        content_type="application/json",
    )
    assert response_unauth.status_code == 302
    assert reverse("account_login") in response_unauth.url

    user = create_user()
    organization = create_organization(name="Test Org", user=user)
    client = auth_client(user)

    dashboard = create_dashboard(
        organization=organization,
        user=user,
        name="My dashboard",
        config={"widgets": []},
        is_default=True,
    )

    # Invalid JSON payload
    response_invalid_json = client.post(
        reverse("update_dashboard"),
        data="not json",
        content_type="text/plain",
    )
    assert response_invalid_json.status_code == 400
    assert response_invalid_json.json() == {"error": "Invalid JSON payload"}

    # Missing dashboard_id
    response_missing_id = client.post(
        reverse("update_dashboard"),
        data=json.dumps({}),
        content_type="application/json",
    )
    assert response_missing_id.status_code == 400
    assert response_missing_id.json() == {"error": "dashboard_id required"}

    # Dashboard not found
    response_not_found = client.post(
        reverse("update_dashboard"),
        data=json.dumps({"dashboard_id": "00000000-0000-0000-0000-000000000000"}),
        content_type="application/json",
    )
    assert response_not_found.status_code == 404
    assert response_not_found.json() == {"error": "Dashboard not found"}

    # Nothing to update (only dashboard_id provided)
    response_nothing = client.post(
        reverse("update_dashboard"),
        data=json.dumps({"dashboard_id": str(dashboard.id)}),
        content_type="application/json",
    )
    assert response_nothing.status_code == 400
    assert response_nothing.json() == {"error": "Nothing to update"}


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
def test_update_dashboard_view_set_default(
    auth_client, create_user, create_organization, create_dashboard
):
    """
    Set the selected dashboard as default.
    """
    user = create_user()
    organization = create_organization(name="Test Org", user=user)
    client = auth_client(user)

    dash_default = create_dashboard(
        organization=organization,
        user=user,
        name="Default",
        config={"widgets": []},
        is_default=True,
    )
    dash_other = create_dashboard(
        organization=organization,
        user=user,
        name="Other",
        config={"widgets": []},
        is_default=False,
    )

    payload = {
        "dashboard_id": str(dash_other.id),
        "set_default": True,
    }
    response = client.post(
        reverse("update_dashboard"),
        data=json.dumps(payload),
        content_type="application/json",
    )
    assert response.status_code == 200
    assert response.json() == {"message": "Dashboard set as default"}

    dash_default.refresh_from_db()
    dash_other.refresh_from_db()
    assert dash_default.is_default is False
    assert dash_other.is_default is True


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
def test_update_dashboard_view_update_name(
    auth_client, create_user, create_organization, create_dashboard
):
    """
    Update the dashboard name.
    """
    user = create_user()
    organization = create_organization(name="Test Org", user=user)
    client = auth_client(user)

    dash1 = create_dashboard(
        organization=organization,
        user=user,
        name="Dashboard 1",
        config={"widgets": []},
        is_default=True,
    )
    dash2 = create_dashboard(
        organization=organization,
        user=user,
        name="Dashboard 2",
        config={"widgets": []},
        is_default=False,
    )

    # Empty name (after strip)
    response_empty = client.post(
        reverse("update_dashboard"),
        data=json.dumps({"dashboard_id": str(dash1.id), "name": "   "}),
        content_type="application/json",
    )
    assert response_empty.status_code == 400
    assert response_empty.json() == {"error": "Name cannot be empty"}

    # Duplicate name
    response_duplicate = client.post(
        reverse("update_dashboard"),
        data=json.dumps({"dashboard_id": str(dash1.id), "name": "Dashboard 2"}),
        content_type="application/json",
    )
    assert response_duplicate.status_code == 400
    assert response_duplicate.json() == {
        "error": "A dashboard with this name already exists"
    }

    # Valid rename
    new_name = "Renamed Dashboard"
    response_ok = client.post(
        reverse("update_dashboard"),
        data=json.dumps({"dashboard_id": str(dash1.id), "name": new_name}),
        content_type="application/json",
    )
    assert response_ok.status_code == 200
    assert response_ok.json() == {"message": "Dashboard updated", "name": new_name}

    dash1.refresh_from_db()
    assert dash1.name == new_name


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
def test_delete_dashboard_view_validation(
    client, auth_client, create_user, create_organization, create_dashboard
):
    """
    Error handling for DeleteDashboardView.
    """
    # Unauthenticated
    response_unauth = client.post(
        reverse("delete_dashboard"),
        data=json.dumps({"dashboard_id": "00000000-0000-0000-0000-000000000000"}),
        content_type="application/json",
    )
    assert response_unauth.status_code == 302
    assert reverse("account_login") in response_unauth.url

    user = create_user()
    organization = create_organization(name="Test Org", user=user)
    client = auth_client(user)

    dashboard = create_dashboard(
        organization=organization,
        user=user,
        name="Only one",
        config={"widgets": []},
        is_default=True,
    )

    # Invalid JSON
    response_invalid = client.post(
        reverse("delete_dashboard"),
        data="not json",
        content_type="text/plain",
    )
    assert response_invalid.status_code == 400
    assert response_invalid.json() == {"error": "Invalid JSON payload"}

    # Missing dashboard_id
    response_missing = client.post(
        reverse("delete_dashboard"),
        data=json.dumps({}),
        content_type="application/json",
    )
    assert response_missing.status_code == 400
    assert response_missing.json() == {"error": "dashboard_id required"}

    # Dashboard not found
    response_404 = client.post(
        reverse("delete_dashboard"),
        data=json.dumps({"dashboard_id": "00000000-0000-0000-0000-000000000000"}),
        content_type="application/json",
    )
    assert response_404.status_code == 404
    assert response_404.json() == {"error": "Dashboard not found"}

    # Cannot delete the last dashboard
    response_last = client.post(
        reverse("delete_dashboard"),
        data=json.dumps({"dashboard_id": str(dashboard.id)}),
        content_type="application/json",
    )
    assert response_last.status_code == 400
    assert response_last.json() == {"error": "Cannot delete the last dashboard"}
    assert Dashboard.objects.filter(organization=organization, user=user).count() == 1


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
def test_delete_dashboard_view_success(
    auth_client, create_user, create_organization, create_dashboard
):
    """
    Successfully delete a non-default dashboard.
    """
    user = create_user()
    organization = create_organization(name="Test Org", user=user)
    client = auth_client(user)

    dash_default = create_dashboard(
        organization=organization,
        user=user,
        name="Default",
        config={"widgets": []},
        is_default=True,
    )
    dash_other = create_dashboard(
        organization=organization,
        user=user,
        name="Other",
        config={"widgets": []},
        is_default=False,
    )

    response = client.post(
        reverse("delete_dashboard"),
        data=json.dumps({"dashboard_id": str(dash_other.id)}),
        content_type="application/json",
    )
    assert response.status_code == 200
    assert response.json() == {"message": "Dashboard deleted"}
    assert "new_default_id" not in response.json()

    # Dashboard is deleted and the other is set as default
    assert not Dashboard.objects.filter(id=dash_other.id).exists()
    assert Dashboard.objects.filter(organization=organization, user=user).count() == 1
    dash_default.refresh_from_db()
    assert dash_default.is_default is True


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
def test_delete_dashboard_view_other_user_returns_404(
    auth_client, create_user, create_organization, create_dashboard
):
    """
    Cannot delete another user's dashboard.
    """
    user = create_user()
    other_user = create_user(username="other_user")
    organization = create_organization(name="Test Org", user=user)
    Membership.objects.create(
        user=other_user,
        organization=organization,
        role=Membership.MEMBER,
        date_invited=now(),
        date_joined=now(),
    )
    client = auth_client(user)

    other_dash = create_dashboard(
        organization=organization,
        user=other_user,
        name="Other user dashboard",
        config={"widgets": []},
        is_default=True,
    )
    create_dashboard(
        organization=organization,
        user=other_user,
        name="Other user second",
        config={"widgets": []},
        is_default=False,
    )

    response = client.post(
        reverse("delete_dashboard"),
        data=json.dumps({"dashboard_id": str(other_dash.id)}),
        content_type="application/json",
    )
    assert response.status_code == 404
    assert response.json() == {"error": "Dashboard not found"}
    assert Dashboard.objects.filter(id=other_dash.id).exists()


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
def test_base_widget_data_view_render_widget(
    auth_client, create_user, create_organization, create_view
):
    """
    Test the _render_widget method of BaseWidgetDataView.
    """
    user = create_user()
    client = auth_client(user)
    organization = create_organization(name="Test Org", user=user)

    request = client.request().wsgi_request
    request.current_organization = organization
    request.user = user

    base_view = BaseWidgetDataView()
    base_view.request = request

    # Valid widget without config
    tags_config = {
        "id": str(uuid.uuid4()),
        "type": "tags",
        "title": "Tags Test",
        "config": {},
    }
    response = base_view._render_widget(request, tags_config)
    assert response.status_code == 200
    json_data = json.loads(response.content)
    assert "html" in json_data
    assert "You don’t have any tags" in json_data["html"]
    assert "config" not in json_data

    # Valid widget with config
    response_with_config = base_view._render_widget(
        request, tags_config, include_config=True
    )
    assert response_with_config.status_code == 200
    json_data_with_config = json.loads(response_with_config.content)
    assert "html" in json_data_with_config
    assert "config" in json_data_with_config
    assert json_data_with_config["config"] == {}

    # Invalid widget type
    invalid_type_config = {
        "id": str(uuid.uuid4()),
        "type": "invalid_type",
        "title": "Invalid",
    }
    response_invalid_type = base_view._render_widget(request, invalid_type_config)
    assert response_invalid_type.status_code == 400
    assert json.loads(response_invalid_type.content) == {"error": "Invalid widget type"}

    # Invalid widget (view_id format)
    invalid_view_config = {
        "id": str(uuid.uuid4()),
        "type": "view_cves",
        "title": "View CVEs Invalid",
        "config": {"view_id": "not-a-uuid"},
    }
    response_invalid_view = base_view._render_widget(request, invalid_view_config)
    assert response_invalid_view.status_code == 400
    assert json.loads(response_invalid_view.content) == {
        "error": "Error rendering widget"
    }

    # Valid widget with data in config
    valid_view = create_view(
        name="My Valid View",
        query="test",
        organization=organization,
        privacy="public",
    )
    valid_view_cves_config = {
        "id": str(uuid.uuid4()),
        "type": "view_cves",
        "title": "Valid View CVEs",
        "config": {"view_id": str(valid_view.id), "show_view_info": 1},
    }
    response_valid_view_cves = base_view._render_widget(
        request, valid_view_cves_config, include_config=True
    )
    assert response_valid_view_cves.status_code == 200
    json_data_valid_view = json.loads(response_valid_view_cves.content)
    assert "html" in json_data_valid_view
    assert "config" in json_data_valid_view
    assert json_data_valid_view["config"] == {
        "view_id": str(valid_view.id),
        "show_view_info": 1,
    }


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
@patch("dashboards.views.BaseWidgetDataView._render_widget")
def test_load_widget_data_view_get(
    mock_render_widget,
    client,
    auth_client,
    create_user,
    create_organization,
    create_dashboard,
):
    """
    Test the get method of LoadWidgetDataView.
    """
    widget_id_1 = str(uuid.uuid4())
    widget_config_1 = {
        "id": widget_id_1,
        "type": "tags",
        "title": "Test Widget 1",
        "config": {},
    }
    dashboard_config = {"widgets": [widget_config_1]}

    user = create_user()
    organization = create_organization(name="Test Org", user=user)
    create_dashboard(
        organization=organization,
        user=user,
        name="Default",
        config=dashboard_config,
        is_default=True,
    )

    # Unauthenticated access
    response_unauth = client.get(
        reverse("load_widget_data", kwargs={"widget_id": widget_id_1})
    )
    assert response_unauth.status_code == 302
    assert reverse("account_login") in response_unauth.url
    mock_render_widget.assert_not_called()

    # Widget Found
    auth_client = auth_client(user)
    mock_render_widget.return_value = JsonResponse({"html": "mocked_render"})

    response_found = auth_client.get(
        reverse("load_widget_data", kwargs={"widget_id": widget_id_1})
    )
    assert response_found.status_code == 200
    assert response_found.json() == {"html": "mocked_render"}
    mock_render_widget.assert_called_once()
    call_args, call_kwargs = mock_render_widget.call_args

    # args[0] should be the request object, args[1] the config
    assert len(call_args) == 2
    assert call_args[1] == widget_config_1

    # Widget Not Found
    mock_render_widget.reset_mock()
    response_not_found = auth_client.get(
        reverse("load_widget_data", kwargs={"widget_id": str(uuid.uuid4())})
    )
    assert response_not_found.status_code == 404
    assert response_not_found.json() == {"error": "Widget not found"}
    mock_render_widget.assert_not_called()


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
def test_load_widget_data_view_multiple_members_owner_dashboard(
    auth_client,
    create_user,
    create_organization,
    create_dashboard,
):
    owner = create_user(username="owner")
    organization = create_organization(name="Shared Org For Widget Test", user=owner)
    owner_widget_id = str(uuid.uuid4())
    create_dashboard(
        organization=organization,
        user=owner,
        name="Owner dashboard",
        config={
            "widgets": [
                {
                    "id": owner_widget_id,
                    "type": "tags",
                    "title": "Tags Owner widget",
                    "config": {},
                }
            ]
        },
        is_default=True,
    )

    member = create_user(username="member")
    Membership.objects.create(
        user=member,
        organization=organization,
        role=Membership.MEMBER,
    )
    member_widget_id = str(uuid.uuid4())
    create_dashboard(
        organization=organization,
        user=member,
        name="Member dashboard",
        config={
            "widgets": [
                {
                    "id": member_widget_id,
                    "type": "projects",
                    "title": "Projects Member widget",
                    "config": {},
                }
            ]
        },
        is_default=True,
    )

    # Owner can access its own dashboard
    client_owner = auth_client(owner)
    response_owner = client_owner.get(
        reverse("load_widget_data", kwargs={"widget_id": owner_widget_id})
    )
    assert response_owner.status_code == 200
    assert "You don’t have any tags" in response_owner.json()["html"]


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
def test_load_widget_data_view_dashboard_not_found(
    auth_client, create_user, create_organization
):
    """
    Test LoadWidgetDataView returns 404 if no default dashboard exists.
    """
    user = create_user()
    create_organization(name="Org Without Dashboard", user=user)

    client = auth_client(user)
    url = reverse("load_widget_data", kwargs={"widget_id": str(uuid.uuid4())})

    response = client.get(url)

    assert response.status_code == 404
    assert response.json() == {"error": "Dashboard not found"}


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
@patch("dashboards.views.BaseWidgetDataView._render_widget")
def test_render_widget_data_view_post(
    mock_render_widget, client, auth_client, create_user
):
    """
    Test the post method of RenderWidgetDataView.
    """
    user = create_user()
    widget_id = str(uuid.uuid4())

    # Unauthenticated access
    response_unauth = client.post(
        reverse("render_widget_data", kwargs={"widget_type": "tags"}),
        data={"id": widget_id, "config": json.dumps({"some_key": "some_value"})},
    )
    assert response_unauth.status_code == 302
    assert reverse("account_login") in response_unauth.url
    mock_render_widget.assert_not_called()

    auth_client = auth_client(user)
    mock_render_widget.return_value = JsonResponse(
        {"html": "mocked_html", "config": "mocked_config"}
    )

    # Invalid widget type
    response_invalid_type = auth_client.post(
        reverse("render_widget_data", kwargs={"widget_type": "invalid_type"}),
        data={"id": widget_id, "config": json.dumps({"key": "value"})},
    )
    assert response_invalid_type.status_code == 400
    assert response_invalid_type.json() == {"error": "Invalid widget type"}
    mock_render_widget.assert_not_called()

    # Valid request
    response_valid = auth_client.post(
        reverse("render_widget_data", kwargs={"widget_type": "tags"}),
        data={"id": widget_id, "config": json.dumps({"key": "value"})},
    )
    assert response_valid.status_code == 200
    assert response_valid.json() == {"html": "mocked_html", "config": "mocked_config"}

    mock_render_widget.assert_called_once()
    call_args, call_kwargs = mock_render_widget.call_args

    # request, widget_config
    assert len(call_args) == 2
    assert isinstance(call_args[0], HttpRequest)
    assert call_args[1] == {
        "id": widget_id,
        "type": "tags",
        "title": None,
        "config": {"key": "value"},
    }
    assert call_kwargs == {"include_config": True}


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
def test_load_widget_config_view_post(client, auth_client, create_user):
    """
    Test the post method of LoadWidgetConfigView.
    """
    user = create_user()

    # Unauthenticated access
    response_unauth = client.post(
        reverse("load_widget_config", kwargs={"widget_type": "tags"}),
        data=json.dumps({"title": "Test Title", "config": {}}),
        content_type="application/json",
    )
    assert response_unauth.status_code == 302
    assert reverse("account_login") in response_unauth.url

    auth_client = auth_client(user)

    # Invalid JSON payload
    response_invalid_json = auth_client.post(
        reverse("load_widget_config", kwargs={"widget_type": "tags"}),
        data="not json",
        content_type="text/plain",
    )
    assert response_invalid_json.status_code == 400
    assert response_invalid_json.json() == {"error": "Invalid JSON payload"}

    # Invalid widget type
    response_invalid_type = auth_client.post(
        reverse("load_widget_config", kwargs={"widget_type": "invalid_type"}),
        data=json.dumps({"title": "Test Title", "config": {}}),
        content_type="application/json",
    )
    assert response_invalid_type.status_code == 400
    assert response_invalid_type.json() == {"error": "Invalid widget type"}

    # Valid widget
    with patch(
        "dashboards.widgets.TagsWidget.config", return_value="<p>Mocked Config HTML</p>"
    ) as mock_widget_config:
        response_valid = auth_client.post(
            reverse("load_widget_config", kwargs={"widget_type": "tags"}),
            data=json.dumps({"title": "Test Title", "config": {}}),
            content_type="application/json",
        )

    assert response_valid.status_code == 200
    assert response_valid.json() == {"html": "<p>Mocked Config HTML</p>"}
    mock_widget_config.assert_called_once()


@override_settings(ENABLE_ONBOARDING=False)
@pytest.mark.django_db
def test_invalid_widget_validate_config_handling(
    auth_client, create_user, create_organization, create_dashboard
):
    user = create_user()
    auth_client = auth_client(user)

    # LoadWidgetConfigView does not validate the config
    response = auth_client.post(
        reverse("load_widget_config", kwargs={"widget_type": "view_cves"}),
        data=json.dumps({"title": "Invalid View", "config": {"view_id": "not-a-uuid"}}),
        content_type="application/json",
    )
    assert response.status_code == 200

    # RenderWidgetDataView validates the config
    response = auth_client.post(
        reverse("render_widget_data", kwargs={"widget_type": "view_cves"}),
        data=json.dumps({"id": str(uuid.uuid4()), "config": {"view_id": "not-a-uuid"}}),
        content_type="application/json",
    )
    assert response.status_code == 400

    # LoadWidgetDataView validate the config
    widget_id = str(uuid.uuid4())
    organization = create_organization(name="Test Org", user=user)
    create_dashboard(
        organization=organization,
        user=user,
        name="Default",
        config={
            "widgets": [
                {
                    "id": widget_id,
                    "title": "Test Widget",
                    "type": "view_cves",
                    "config": {"view_id": "not-a-uuid"},
                }
            ]
        },
        is_default=True,
    )

    # Unauthenticated access
    response = auth_client.get(
        reverse("load_widget_data", kwargs={"widget_id": widget_id}),
    )
    assert response.status_code == 400
