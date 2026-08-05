"""
Project ACL permission matrices.

Convention for new project-scoped resources:
- Add ``resource.view`` to PROJECT_READ_PERMISSIONS (all roles can read metadata).
- Add ``resource.manage`` to PROJECT_ADMIN_MANAGE_PERMISSIONS (Project Admin only).
- Sensitive fields (secrets, tokens, webhook URLs) are masked in the UI/API for
  non-managers even when the resource itself is visible.

Role model:
- Viewer: read-only on all project resources (PROJECT_READ_PERMISSIONS).
- Contributor: Viewer + operational tracker actions (assign, status, comment).
- Project Admin: Contributor + project management (edit, members, subscriptions, …).
"""

# Organization permissions
ORG_VIEW = "org.view"
ORG_EDIT = "org.edit"
ORG_DELETE = "org.delete"
ORG_MEMBERS_VIEW = "org.members.view"
ORG_TOKENS_MANAGE = "org.tokens.manage"
ORG_AUDIT_LOGS_VIEW = "org.audit_logs.view"
ORG_PROJECTS_CREATE = "org.projects.create"
ORG_PROJECTS_DELETE = "org.projects.delete"

# Project permissions
PROJECT_VIEW = "project.view"
PROJECT_EDIT = "project.edit"
PROJECT_MEMBERS_VIEW = "project.members.view"
PROJECT_MEMBERS_MANAGE = "project.members.manage"
PROJECT_SUBSCRIPTIONS_VIEW = "project.subscriptions.view"
PROJECT_SUBSCRIPTIONS_MANAGE = "project.subscriptions.manage"
PROJECT_TRACKER_ASSIGN = "project.tracker.assign"
PROJECT_TRACKER_UPDATE_STATUS = "project.tracker.update_status"
PROJECT_TRACKER_COMMENT = "project.tracker.comment"
PROJECT_CVES_EXPORT = "project.cves.export"
PROJECT_REPORTS_VIEW = "project.reports.view"
PROJECT_AUTOMATIONS_VIEW = "project.automations.view"
PROJECT_AUTOMATIONS_MANAGE = "project.automations.manage"
PROJECT_NOTIFICATIONS_VIEW = "project.notifications.view"
PROJECT_NOTIFICATIONS_MANAGE = "project.notifications.manage"

# All project-scoped read permissions. Extend when adding a new *.view permission.
PROJECT_READ_PERMISSIONS = frozenset(
    {
        PROJECT_VIEW,
        PROJECT_SUBSCRIPTIONS_VIEW,
        PROJECT_CVES_EXPORT,
        PROJECT_REPORTS_VIEW,
        PROJECT_AUTOMATIONS_VIEW,
        PROJECT_NOTIFICATIONS_VIEW,
        PROJECT_MEMBERS_VIEW,
    }
)

# Viewer: read-only on every project resource.
VIEWER_PERMISSIONS = PROJECT_READ_PERMISSIONS

# Contributor: operational actions on top of read access.
CONTRIBUTOR_OPERATIONAL_PERMISSIONS = frozenset(
    {
        PROJECT_TRACKER_ASSIGN,
        PROJECT_TRACKER_UPDATE_STATUS,
        PROJECT_TRACKER_COMMENT,
    }
)

# Project Admin: management actions (includes subscription changes).
PROJECT_ADMIN_MANAGE_PERMISSIONS = frozenset(
    {
        PROJECT_EDIT,
        PROJECT_MEMBERS_MANAGE,
        PROJECT_SUBSCRIPTIONS_MANAGE,
        PROJECT_AUTOMATIONS_MANAGE,
        PROJECT_NOTIFICATIONS_MANAGE,
    }
)

OWNER_ORG_PERMISSIONS = frozenset(
    {
        ORG_VIEW,
        ORG_EDIT,
        ORG_DELETE,
        ORG_MEMBERS_VIEW,
        ORG_TOKENS_MANAGE,
        ORG_AUDIT_LOGS_VIEW,
        ORG_PROJECTS_CREATE,
        ORG_PROJECTS_DELETE,
    }
)

ADMIN_ORG_PERMISSIONS = frozenset(
    {
        ORG_VIEW,
        ORG_MEMBERS_VIEW,
        ORG_TOKENS_MANAGE,
        ORG_PROJECTS_CREATE,
        ORG_PROJECTS_DELETE,
    }
)

MEMBER_ORG_PERMISSIONS = frozenset({ORG_VIEW})
