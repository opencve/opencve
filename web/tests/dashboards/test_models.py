import pytest
from unittest.mock import MagicMock

from dashboards.models import Dashboard


@pytest.mark.django_db
def test_dashboard_model(create_user, create_organization, create_dashboard):
    user = create_user(username="dash_user")
    org = create_organization(name="dash_org", user=user)
    dashboard = create_dashboard(organization=org, user=user, name="Default Dashboard")

    # Assert attributes and relationships
    assert dashboard.organization == org
    assert dashboard.user == user
    assert dashboard.name == "Default Dashboard"
    assert dashboard.config == {}
    assert dashboard.is_default is False

    # Verify relationship access
    assert user.dashboards.count() == 1
    assert user.dashboards.first() == dashboard
    assert org.dashboards.count() == 1
    assert org.dashboards.first() == dashboard

    # Custom config
    config_data = {"key": "value"}
    dashboard = create_dashboard(
        organization=org,
        user=user,
        name="Config Dash",
        is_default=True,
        config=config_data,
    )
    assert dashboard.is_default is True
    assert dashboard.name == "Config Dash"
    assert dashboard.config == config_data


@pytest.mark.django_db
def test_dashboard_get_default_config_with_project(
    create_user, create_organization, create_project
):
    """
    Test get_default_config when an active project exists.
    """
    user = create_user()
    org = create_organization("org_with_proj", user=user)
    project = create_project(name="Active Project", organization=org, active=True)

    # Get the default config
    mock_request = MagicMock()
    mock_request.current_organization = org
    default_config = Dashboard.get_default_config(mock_request)

    # Assertions
    assert "widgets" in default_config
    assert isinstance(default_config["widgets"], list)

    widgets = [
        {"type": w.get("type"), "config": w.get("config")}
        for w in default_config["widgets"]
    ]

    assert widgets == [
        {"type": "activity", "config": {"activities_view": "all"}},
        {
            "type": "project_cves",
            "config": {
                "project_id": str(project.id),
                "show_project_info": 1,
            },
        },
        {"type": "projects", "config": {}},
        {"type": "tags", "config": {}},
        {"type": "views", "config": {}},
        {"type": "last_reports", "config": {}},
    ]


@pytest.mark.django_db
def test_dashboard_get_default_config_without_project(
    create_user, create_organization, create_project
):
    """
    Test get_default_config when no active project exists.
    """
    user = create_user()
    org = create_organization("org_no_proj", user=user)
    create_project(name="Inactive Project", organization=org, active=False)

    # Get the default config
    mock_request = MagicMock()
    mock_request.current_organization = org
    default_config = Dashboard.get_default_config(mock_request)

    # Assertions
    assert "widgets" in default_config
    assert isinstance(default_config["widgets"], list)

    widgets = [
        {"type": w.get("type"), "config": w.get("config")}
        for w in default_config["widgets"]
    ]

    assert widgets == [
        {"type": "activity", "config": {"activities_view": "all"}},
        {"type": "projects", "config": {}},
        {"type": "tags", "config": {}},
        {"type": "views", "config": {}},
        {"type": "last_reports", "config": {}},
    ]
