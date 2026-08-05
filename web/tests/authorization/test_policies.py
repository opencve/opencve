import pytest

from authorization.policies import (
    can_assign_org_role,
    can_manage_membership,
    can_remove_membership,
    is_org_admin_or_owner,
)
from authorization.roles import ORG_ADMIN, ORG_MEMBER, ORG_OWNER
from organizations.models import Membership, Organization
from django.utils.timezone import now


@pytest.fixture
def org_with_members(db, django_user_model):
    organization = Organization.objects.create(name="org1")
    owner = django_user_model.objects.create_user(username="owner", password="x")
    admin = django_user_model.objects.create_user(username="admin", password="x")
    member = django_user_model.objects.create_user(username="member", password="x")
    owner_m = Membership.objects.create(
        user=owner, organization=organization, role=ORG_OWNER, date_joined=now()
    )
    admin_m = Membership.objects.create(
        user=admin, organization=organization, role=ORG_ADMIN, date_joined=now()
    )
    member_m = Membership.objects.create(
        user=member, organization=organization, role=ORG_MEMBER, date_joined=now()
    )
    return organization, owner_m, admin_m, member_m


def test_owner_can_manage_admin_and_member(org_with_members):
    """Owner can change roles or remove admins and members."""
    _, owner_m, admin_m, member_m = org_with_members
    assert can_manage_membership(owner_m, admin_m) is True
    assert can_manage_membership(owner_m, member_m) is True


def test_admin_can_manage_member_only(org_with_members):
    """Admin can manage members but not other admins or the owner."""
    _, owner_m, admin_m, member_m = org_with_members
    assert can_manage_membership(admin_m, member_m) is True
    assert can_manage_membership(admin_m, admin_m) is False
    assert can_manage_membership(admin_m, owner_m) is False


def test_actor_cannot_manage_self(org_with_members):
    """Users cannot manage their own membership row via can_manage_membership."""
    _, owner_m, admin_m, member_m = org_with_members
    assert can_manage_membership(owner_m, owner_m) is False
    assert can_manage_membership(admin_m, admin_m) is False
    assert can_manage_membership(member_m, member_m) is False


def test_can_remove_membership_allows_self_leave(org_with_members):
    """Any member may remove themselves from the organization."""
    _, owner_m, admin_m, member_m = org_with_members
    assert can_remove_membership(member_m, member_m) is True
    assert can_remove_membership(admin_m, admin_m) is True


def test_owner_can_assign_all_org_roles(org_with_members):
    """Owner may assign Owner, Admin, and Member roles."""
    _, owner_m, _, _ = org_with_members
    assert can_assign_org_role(owner_m, ORG_OWNER) is True
    assert can_assign_org_role(owner_m, ORG_ADMIN) is True
    assert can_assign_org_role(owner_m, ORG_MEMBER) is True


def test_admin_can_assign_member_role_only(org_with_members):
    """Admin may assign Member but not Owner or Admin."""
    _, _, admin_m, _ = org_with_members
    assert can_assign_org_role(admin_m, ORG_MEMBER) is True
    assert can_assign_org_role(admin_m, ORG_ADMIN) is False
    assert can_assign_org_role(admin_m, ORG_OWNER) is False


def test_is_org_admin_or_owner(org_with_members):
    """is_org_admin_or_owner is true for Owner and Admin memberships."""
    _, owner_m, admin_m, member_m = org_with_members
    assert is_org_admin_or_owner(owner_m) is True
    assert is_org_admin_or_owner(admin_m) is True
    assert is_org_admin_or_owner(member_m) is False
    assert is_org_admin_or_owner(None) is False
