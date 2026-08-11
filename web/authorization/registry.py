from dataclasses import dataclass, field
from typing import Callable, Optional

from authorization.exceptions import (
    CircularRoleDependencyError,
    RoleAlreadyRegisteredError,
    UnknownBaseRoleError,
)
from authorization.permissions import (
    ADMIN_ORG_PERMISSIONS,
    CONTRIBUTOR_OPERATIONAL_PERMISSIONS,
    MEMBER_ORG_PERMISSIONS,
    OWNER_ORG_PERMISSIONS,
    PROJECT_ADMIN_MANAGE_PERMISSIONS,
    VIEWER_PERMISSIONS,
)
from authorization.roles import (
    ORG_ADMIN,
    ORG_MEMBER,
    ORG_OWNER,
    PROJECT_ADMIN,
    PROJECT_CONTRIBUTOR,
    PROJECT_VIEWER,
)

_org_roles: dict[str, "OrgRoleDefinition"] = {}
_project_roles: dict[str, "ProjectRoleDefinition"] = {}
_resolved_org_cache: dict[str, frozenset[str]] = {}
_resolved_project_cache: dict[str, frozenset[str]] = {}


@dataclass(frozen=True)
class OrgRoleDefinition:
    """Organization role with a fixed permission set and optional assignability rule."""

    key: str
    label: str
    permissions: frozenset[str]
    summary: str = ""
    order: int = 0
    assignable_by: Optional[Callable] = None

    @property
    def choice_label(self) -> str:
        if self.summary:
            return f"{self.label} ({self.summary})"
        return self.label


@dataclass(frozen=True)
class ProjectRoleDefinition:
    """Project role defined directly or via base_role inheritance."""

    key: str
    label: str
    permissions: frozenset[str] = field(default_factory=frozenset)
    base_role: Optional[str] = None
    extra_permissions: frozenset[str] = field(default_factory=frozenset)
    summary: str = ""
    order: int = 0

    @property
    def choice_label(self) -> str:
        if self.summary:
            return f"{self.label} ({self.summary})"
        return self.label


class RoleRegistry:
    """Central registry for org/project roles and resolved permission sets."""

    @classmethod
    def register_org_role(cls, definition: OrgRoleDefinition) -> None:
        if definition.key in _org_roles:
            raise RoleAlreadyRegisteredError(
                f"Organization role '{definition.key}' is already registered."
            )
        _org_roles[definition.key] = definition
        _resolved_org_cache.pop(definition.key, None)

    @classmethod
    def register_project_role(cls, definition: ProjectRoleDefinition) -> None:
        if definition.key in _project_roles:
            raise RoleAlreadyRegisteredError(
                f"Project role '{definition.key}' is already registered."
            )
        _project_roles[definition.key] = definition
        _resolved_project_cache.pop(definition.key, None)

    @classmethod
    def is_valid_org_role(cls, key: str) -> bool:
        return key in _org_roles

    @classmethod
    def is_valid_project_role(cls, key: str) -> bool:
        return key in _project_roles

    @classmethod
    def get_org_role(cls, key: str) -> OrgRoleDefinition:
        return _org_roles[key]

    @classmethod
    def get_project_role(cls, key: str) -> ProjectRoleDefinition:
        return _project_roles[key]

    @classmethod
    def get_org_permissions(cls, role_key: str) -> frozenset[str]:
        if role_key not in _resolved_org_cache:
            if role_key not in _org_roles:
                return frozenset()
            _resolved_org_cache[role_key] = _org_roles[role_key].permissions
        return _resolved_org_cache[role_key]

    @classmethod
    def get_project_permissions(cls, role_key: str) -> frozenset[str]:
        if role_key not in _resolved_project_cache:
            _resolved_project_cache[role_key] = cls._resolve_project_permissions(
                role_key, visiting=set()
            )
        return _resolved_project_cache[role_key]

    @classmethod
    def _resolve_project_permissions(cls, role_key: str, visiting: set) -> frozenset:
        if role_key in visiting:
            raise CircularRoleDependencyError(
                f"Circular dependency detected for project role '{role_key}'."
            )
        if role_key not in _project_roles:
            return frozenset()
        visiting = visiting | {role_key}
        defn = _project_roles[role_key]
        if defn.base_role:
            if defn.base_role not in _project_roles:
                raise UnknownBaseRoleError(
                    f"Unknown base role '{defn.base_role}' for '{role_key}'."
                )
            base = cls._resolve_project_permissions(defn.base_role, visiting)
            return base | defn.extra_permissions | defn.permissions
        return defn.permissions | defn.extra_permissions

    @classmethod
    def get_org_role_choices(
        cls, *, actor_membership=None, include_summary: bool = False
    ) -> list[tuple[str, str]]:
        choices = []
        for key, defn in sorted(
            _org_roles.items(), key=lambda x: (x[1].order, x[1].label)
        ):
            label = defn.choice_label if include_summary else defn.label
            if actor_membership is None:
                choices.append((key, label))
            elif defn.assignable_by is None or defn.assignable_by(actor_membership):
                choices.append((key, label))
        return choices

    @classmethod
    def get_project_role_choices(
        cls, *, actor=None, include_summary: bool = False
    ) -> list[tuple[str, str]]:
        return [
            (key, defn.choice_label if include_summary else defn.label)
            for key, defn in sorted(
                _project_roles.items(), key=lambda x: (x[1].order, x[1].label)
            )
        ]

    @classmethod
    def register_roles(cls) -> None:
        """Register default org and project roles."""

        def owner_can_assign(actor_membership):
            return actor_membership.role == ORG_OWNER

        def owner_or_admin_can_assign_member(actor_membership):
            return actor_membership.role in (ORG_OWNER, ORG_ADMIN)

        cls.register_org_role(
            OrgRoleDefinition(
                key=ORG_OWNER,
                label="Owner",
                summary="full control",
                order=0,
                permissions=OWNER_ORG_PERMISSIONS,
                assignable_by=owner_can_assign,
            )
        )
        cls.register_org_role(
            OrgRoleDefinition(
                key=ORG_ADMIN,
                label="Admin",
                summary="manage projects and members",
                order=1,
                permissions=ADMIN_ORG_PERMISSIONS,
                assignable_by=owner_can_assign,
            )
        )
        cls.register_org_role(
            OrgRoleDefinition(
                key=ORG_MEMBER,
                label="Member",
                summary="project access only",
                order=2,
                permissions=MEMBER_ORG_PERMISSIONS,
                assignable_by=owner_or_admin_can_assign_member,
            )
        )
        cls.register_project_role(
            ProjectRoleDefinition(
                key=PROJECT_VIEWER,
                label="Viewer",
                summary="read only access",
                order=2,
                permissions=VIEWER_PERMISSIONS,
            )
        )
        cls.register_project_role(
            ProjectRoleDefinition(
                key=PROJECT_CONTRIBUTOR,
                label="Contributor",
                summary="Viewer with operational CVE workflow",
                order=1,
                base_role=PROJECT_VIEWER,
                extra_permissions=CONTRIBUTOR_OPERATIONAL_PERMISSIONS,
            )
        )
        cls.register_project_role(
            ProjectRoleDefinition(
                key=PROJECT_ADMIN,
                label="Project Admin",
                summary="project management",
                order=0,
                base_role=PROJECT_CONTRIBUTOR,
                extra_permissions=PROJECT_ADMIN_MANAGE_PERMISSIONS,
            )
        )
