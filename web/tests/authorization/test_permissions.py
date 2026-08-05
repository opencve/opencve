import pytest

from authorization.permissions import (
    PROJECT_AUTOMATIONS_MANAGE,
    PROJECT_AUTOMATIONS_VIEW,
    PROJECT_NOTIFICATIONS_MANAGE,
    PROJECT_NOTIFICATIONS_VIEW,
    PROJECT_SUBSCRIPTIONS_MANAGE,
    PROJECT_SUBSCRIPTIONS_VIEW,
    PROJECT_TRACKER_ASSIGN,
    PROJECT_TRACKER_COMMENT,
)
from authorization.registry import RoleRegistry
from authorization.roles import PROJECT_ADMIN, PROJECT_CONTRIBUTOR, PROJECT_VIEWER


def test_viewer_has_all_read_permissions():
    """Viewer role includes read permissions but no manage or tracker actions."""
    perms = RoleRegistry.get_project_permissions(PROJECT_VIEWER)
    assert PROJECT_AUTOMATIONS_VIEW in perms
    assert PROJECT_NOTIFICATIONS_VIEW in perms
    assert PROJECT_SUBSCRIPTIONS_VIEW in perms
    assert PROJECT_AUTOMATIONS_MANAGE not in perms
    assert PROJECT_SUBSCRIPTIONS_MANAGE not in perms
    assert PROJECT_TRACKER_ASSIGN not in perms


def test_contributor_inherits_viewer_and_adds_operational_actions():
    """Contributor inherits viewer permissions and adds tracker operations."""
    perms = RoleRegistry.get_project_permissions(PROJECT_CONTRIBUTOR)
    viewer = RoleRegistry.get_project_permissions(PROJECT_VIEWER)
    assert viewer.issubset(perms)
    assert PROJECT_TRACKER_ASSIGN in perms
    assert PROJECT_TRACKER_COMMENT in perms
    assert PROJECT_AUTOMATIONS_MANAGE not in perms
    assert PROJECT_SUBSCRIPTIONS_MANAGE not in perms


def test_project_admin_inherits_contributor_and_adds_management():
    """Project admin inherits contributor permissions and adds management actions."""
    perms = RoleRegistry.get_project_permissions(PROJECT_ADMIN)
    contributor = RoleRegistry.get_project_permissions(PROJECT_CONTRIBUTOR)
    assert contributor.issubset(perms)
    assert PROJECT_SUBSCRIPTIONS_MANAGE in perms
    assert PROJECT_AUTOMATIONS_MANAGE in perms
    assert PROJECT_NOTIFICATIONS_MANAGE in perms
