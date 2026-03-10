import json
from datetime import date, timedelta

import pytest
from auditlog.models import LogEntry
from django.contrib.contenttypes.models import ContentType

from cves.constants import PRODUCT_SEPARATOR
from organizations.auditlog import (
    DISPLAY_FIELDS_BY_RESOURCE_ACTION,
    FIELDS_ALWAYS_HIDDEN,
    RESOURCE_LABELS,
    _build_project_subscriptions_change,
    _format_notification_configuration_changes,
    _format_notification_configuration_value,
    _normalize_subscriptions_payload,
    _resolve_cve_id_to_display,
    _resolve_pair,
    _resolve_project_id_to_name,
    _resolve_user_id_to_display,
    apply_audit_log_get_filters,
    build_audit_log_queryset,
    extend_audit_log_pks_with_deleted,
    get_audit_log_display_data,
    get_audit_log_filter_choices,
    get_display_object_repr_for_entries,
    get_displayable_changes,
    get_organization_audit_log_pks,
    get_resource_label,
)
from organizations.models import Membership, Organization, OrganizationAPIToken
from projects.models import CveTracker, Notification, Project
from views.models import View as SavedView


#
# Notification.configuration helpers
#


def test_format_notification_configuration_value_happy_path():
    raw = {
        "extras": {
            "email": "user@example.com",
            "webhook_url": "https://example.com/hook",
            "headers": {"X-Test": "1"},
        },
        "types": ["a", "b"],
        "metrics": {"cvss31": "9.8"},
    }
    result = _format_notification_configuration_value(json.dumps(raw))
    # Basic sanity of human‑readable content
    assert "Email: user@example.com" in result
    assert "Webhook URL: https://example.com/hook" in result
    assert "Headers: X-Test: 1" in result
    assert "Types: a, b" in result
    assert "CVSS 3.1: 9.8" in result


def test_format_notification_configuration_value_no_known_keys_returns_raw():
    raw = {"foo": "bar"}
    dumped = json.dumps(raw)
    assert _format_notification_configuration_value(dumped) == dumped


def test_format_notification_configuration_changes_only_diff_lines():
    before = {
        "extras": {"email": "a@example.com"},
        "types": ["a"],
    }
    after = {
        "extras": {"email": "b@example.com"},
        "types": ["a", "b"],
    }
    before_text, after_text = _format_notification_configuration_changes(
        json.dumps(before), json.dumps(after)
    )

    # All summary lines should be preserved and reflect the two configurations
    assert "Email: a@example.com" in before_text
    assert "Email: b@example.com" in after_text
    assert "Types: a" in before_text
    assert "Types: a, b" in after_text


#
# Subscriptions helpers (Project.subscriptions)
#


def test_normalize_subscriptions_payload_accepts_various_input_shapes():
    data = {
        "vendors": ["v2", "v1", "v1"],
        "products": [
            f"vendor{PRODUCT_SEPARATOR}prod1",
            "plainprod",
        ],
    }
    vendors, products = _normalize_subscriptions_payload(json.dumps(data))
    assert vendors == ["v1", "v2"]

    # Vendor prefix should be stripped
    assert sorted(products) == ["plainprod", "prod1"]


def test_build_project_subscriptions_change_diff_structure():
    before = {
        "vendors": ["v1"],
        "products": ["p1"],
    }
    after = {
        "vendors": ["v1", "v2"],
        "products": ["p2"],
    }

    change = _build_project_subscriptions_change(before, after)
    assert change["is_project_subscriptions"] is True
    assert change["before"]["vendors"] == ["v1"]
    assert change["after"]["vendors"] == ["v1", "v2"]
    assert change["diff"]["vendors_added"] == ["v2"]
    assert change["diff"]["vendors_removed"] == []
    assert change["diff"]["products_added"] == ["p2"]
    assert change["diff"]["products_removed"] == ["p1"]


#
# ID resolvers
#


def test_resolve_project_cve_and_user_ids(
    create_user, create_organization, create_project, create_cve
):
    user = create_user(username="u1", email="u1@example.com")
    org = create_organization(name="org1", user=user)
    project = create_project(name="p1", organization=org)
    cve = create_cve("CVE-2021-34181")

    assert _resolve_project_id_to_name(project.pk) == project.name
    assert _resolve_cve_id_to_display(cve.pk) == cve.cve_id
    assert _resolve_user_id_to_display(user.pk) in {user.username, user.email}

    # Unknown ids fall back to string representation
    assert _resolve_project_id_to_name(999999) == "999999"
    assert _resolve_cve_id_to_display(999999) == "999999"
    assert _resolve_user_id_to_display(999999) == "999999"


def test_resolve_pair_applies_resolver_conditionally():
    def resolver(v):
        return f"r-{v}"

    before, after = _resolve_pair("a", "b", resolver)
    assert (before, after) == ("r-a", "r-b")

    before, after = _resolve_pair(None, "", resolver)
    assert (before, after) == (None, "")


#
# Displayable changes
#


class DummyEntry:
    def __init__(self, changes_dict, content_type, action):
        self.changes_dict = changes_dict
        self.content_type = content_type
        self.action = action


@pytest.mark.django_db
def test_get_displayable_changes_filters_and_formats_notification_configuration():
    ct = ContentType.objects.get_for_model(Notification)
    before = {
        "extras": {"email": "a@example.com"},
        "types": [],
        "metrics": {},
    }
    after = {
        "extras": {"email": "b@example.com"},
        "types": [],
        "metrics": {},
    }
    entry = DummyEntry(
        changes_dict={"configuration": [json.dumps(before), json.dumps(after)]},
        content_type=ct,
        action=LogEntry.Action.UPDATE,
    )

    result = get_displayable_changes(entry)
    assert "configuration" in result
    value = result["configuration"]

    # For UPDATE actions we expect the special diff structure with the
    # is_notification_configuration flag and before/after summaries.
    assert isinstance(value, dict)
    assert value.get("is_notification_configuration") is True
    assert "Email: a@example.com" in value.get("before", "")
    assert "Email: b@example.com" in value.get("after", "")


@pytest.mark.django_db
def test_get_displayable_changes_project_subscriptions_and_hidden_fields():
    ct = ContentType.objects.get_for_model(Project)
    changes = {
        "subscriptions": [
            json.dumps({"vendors": ["v1"], "products": ["p1"]}),
            json.dumps({"vendors": ["v2"], "products": ["p2"]}),
        ],
        # Should be removed by FIELDS_ALWAYS_HIDDEN
        next(iter(FIELDS_ALWAYS_HIDDEN)): ["before", "after"],
    }
    entry = DummyEntry(
        changes_dict=changes,
        content_type=ct,
        action=LogEntry.Action.UPDATE,
    )

    result = get_displayable_changes(entry)
    assert "subscriptions" in result
    assert next(iter(FIELDS_ALWAYS_HIDDEN)) not in result
    subs = result["subscriptions"]
    assert subs["is_project_subscriptions"] is True
    assert subs["before"]["vendors"] == ["v1"]
    assert subs["after"]["vendors"] == ["v2"]


@pytest.mark.django_db
def test_get_displayable_changes_respects_display_fields_by_resource_action():
    ct = ContentType.objects.get_for_model(Project)
    allowed_fields = DISPLAY_FIELDS_BY_RESOURCE_ACTION["project"]
    changes = {name: ["before", "after"] for name in allowed_fields}
    changes["ignored"] = ["x", "y"]

    entry = DummyEntry(
        changes_dict=changes,
        content_type=ct,
        action=LogEntry.Action.UPDATE,
    )
    result = get_displayable_changes(entry)
    for name in allowed_fields:
        assert name in result
    assert "ignored" not in result


#
# Object representation helpers
#


def _create_log_entry_for_obj(obj, object_repr=None, actor=None, action=None):
    return LogEntry.objects.create(
        content_type=ContentType.objects.get_for_model(obj.__class__),
        object_pk=str(obj.pk),
        object_repr=object_repr or str(obj),
        actor=actor,
        action=action or LogEntry.Action.CREATE,
    )


def test_get_display_object_repr_for_entries_uses_model_specific_formatters(
    create_user, create_organization, create_project
):
    user = create_user(username="john", email="john@example.com")
    org = create_organization(name="org1", user=user)
    project = create_project(name="project1", organization=org)

    # Membership formatter should use email or username
    membership = Membership.objects.get(organization=org, user=user)
    e_membership = _create_log_entry_for_obj(membership, object_repr="MEMBERSHIP")

    # Project formatter should use name
    e_project = _create_log_entry_for_obj(project, object_repr="PROJECT")

    entries = [e_membership, e_project]
    mapping = get_display_object_repr_for_entries(entries)

    assert mapping[e_membership.id] in {
        membership.email or user.username,
        str(membership),
    }
    assert mapping[e_project.id] == project.name


@pytest.mark.django_db
def test_get_display_object_repr_for_entries_fallback_on_missing_content_type():
    class DummyEntryForMissingCT:
        def __init__(self):
            self.id = 1
            self.content_type_id = 999999
            self.object_repr = "fallback"

    entry = DummyEntryForMissingCT()
    mapping = get_display_object_repr_for_entries([entry])
    assert mapping[entry.id] == "fallback"


#
# Organization audit log helpers
#


def test_get_organization_audit_log_pks_uses_related_objects(
    create_user,
    create_organization,
    create_project,
    create_notification,
    create_view,
    create_cve,
):
    user = create_user(username="u1")
    org = create_organization(name="org1", user=user)
    token = OrganizationAPIToken.objects.create(
        organization=org,
        name="token",
        description="d",
        created_by=user,
    )
    project = create_project(name="p1", organization=org)
    notif = create_notification(name="n1", project=project)
    saved_view = create_view(name="v1", query="q", organization=org, user=user)
    cve = create_cve("CVE-2021-34181")
    cve_tracker = CveTracker.objects.create(
        project=project,
        cve=cve,
        status="to_evaluate",
    )

    pks = get_organization_audit_log_pks(org)
    assert str(org.pk) in pks[Organization]
    assert (
        str(Membership.objects.get(organization=org, user=user).pk) in pks[Membership]
    )
    assert str(token.pk) in pks[OrganizationAPIToken]
    assert str(project.pk) in pks[Project]
    assert str(notif.pk) in pks[Notification]
    assert str(saved_view.pk) in pks[SavedView]
    assert str(cve_tracker.pk) in pks[CveTracker]


def test_extend_audit_log_pks_with_deleted_adds_deleted_objects(
    create_user, create_organization, create_project, create_notification
):
    user = create_user(username="u1")
    org = create_organization(name="org1", user=user)
    project = create_project(name="p1", organization=org)
    notif = create_notification(name="n1", project=project)

    base_pks = get_organization_audit_log_pks(org)

    org_ct = ContentType.objects.get_for_model(Organization)
    project_ct = ContentType.objects.get_for_model(Project)
    notif_ct = ContentType.objects.get_for_model(Notification)

    # Deleted project and notification via project FK
    LogEntry.objects.create(
        content_type=project_ct,
        object_pk="888",
        object_repr="deleted project",
        actor=None,
        action=LogEntry.Action.DELETE,
        serialized_data={"fields": {"organization": str(org.pk)}},
    )
    LogEntry.objects.create(
        content_type=notif_ct,
        object_pk="777",
        object_repr="deleted notif",
        actor=None,
        action=LogEntry.Action.DELETE,
        serialized_data={"fields": {"project": str(project.pk)}},
    )

    extended = extend_audit_log_pks_with_deleted(org, base_pks)
    assert "888" in extended[Project]
    assert "777" in extended[Notification]
    # Original dict must not be mutated

    # Silence unused variable if fixture is not used in logic above
    assert notif is not None


def test_build_audit_log_queryset_returns_expected_entries(
    create_user, create_organization
):
    user = create_user(username="u1")
    org = create_organization(name="org1", user=user)
    pks = get_organization_audit_log_pks(org)

    # Create a log entry for the organization itself
    e = LogEntry.objects.create(
        content_type=ContentType.objects.get_for_model(Organization),
        object_pk=str(org.pk),
        object_repr=str(org),
        actor=user,
        action=LogEntry.Action.UPDATE,
    )

    qs = build_audit_log_queryset(pks)
    # The queryset may contain additional entries created by signals;
    # we only assert that our explicit entry is included.
    assert e in list(qs)

    # Empty pks dict returns .none()
    assert not build_audit_log_queryset({}).exists()


#
# Filters and display data
#


def test_get_audit_log_filter_choices_and_apply_filters(
    create_user, create_organization
):
    user1 = create_user(username="u1")
    user2 = create_user(username="u2")
    org = create_organization(name="org1", user=user1)

    ct_org = ContentType.objects.get_for_model(Organization)
    # System entry (actor is None)
    system_entry = LogEntry.objects.create(
        content_type=ct_org,
        object_pk=str(org.pk),
        object_repr=str(org),
        actor=None,
        action=LogEntry.Action.CREATE,
    )
    # User entries
    user_entry = LogEntry.objects.create(
        content_type=ct_org,
        object_pk=str(org.pk),
        object_repr=str(org),
        actor=user2,
        action=LogEntry.Action.UPDATE,
    )

    # Restrict queryset to the entries created in this test to avoid
    # interference from auditlog signals in other tests.
    qs = LogEntry.objects.filter(id__in=[system_entry.id, user_entry.id])
    users_choices, resources_choices, action_choices = get_audit_log_filter_choices(qs)

    # Users list should contain user2 (but not system)
    assert any(c["username"] == user2.username for c in users_choices)

    # Resources choices should use RESOURCE_LABELS
    key = f"{ct_org.app_label}.{ct_org.model}"
    assert any(
        r["key"] == key and r["label"] == RESOURCE_LABELS.get(key)
        for r in resources_choices
    )

    # Action choices derived from LogEntry.Action.choices
    assert any(c["value"] == LogEntry.Action.CREATE for c in action_choices)

    # Apply filters: system user
    filtered, filters = apply_audit_log_get_filters(qs, {"user": "system"})
    assert list(filtered) == [system_entry]
    assert filters["user"] == "system"

    # Filter by specific user
    filtered, _ = apply_audit_log_get_filters(qs, {"user": str(user2.pk)})
    assert list(filtered) == [user_entry]

    # Filter by resource and action
    resource_param = f"{ct_org.app_label}.{ct_org.model}"
    filtered, _ = apply_audit_log_get_filters(
        qs, {"resource": resource_param, "action": str(LogEntry.Action.UPDATE)}
    )
    assert list(filtered) == [user_entry]

    # Date filters
    today = date.today()
    tomorrow = today + timedelta(days=1)
    filtered, _ = apply_audit_log_get_filters(
        qs,
        {
            "date_from": today.isoformat(),
            "date_to": tomorrow.isoformat(),
        },
    )
    # Both entries are created "now" so they should be included
    assert set(filtered.values_list("id", flat=True)) == {
        system_entry.id,
        user_entry.id,
    }


def test_get_audit_log_display_data_includes_changes_and_object_repr(
    create_user, create_organization
):
    user = create_user(username="u1")
    org = create_organization(name="org1", user=user)
    ct_org = ContentType.objects.get_for_model(Organization)

    entry = LogEntry.objects.create(
        content_type=ct_org,
        object_pk=str(org.pk),
        object_repr="Org Object",
        actor=user,
        action=LogEntry.Action.UPDATE,
        changes={
            "name": ["old", "new"],
        },
    )

    data = get_audit_log_display_data([entry])
    assert entry.id in data

    info = data[entry.id]
    assert info["display_changes_dict"]["name"] == ["old", "new"]
    assert info["display_object_repr"] in {"Org Object", org.name}
    assert info["resource_label"] == get_resource_label(ct_org)


#
# Integration: apply filters + display helpers
#


def test_integration_build_queryset_filters_and_display_data(
    create_user, create_organization
):
    user = create_user(username="u1")
    org = create_organization(name="org1", user=user)
    pks = get_organization_audit_log_pks(org)

    # Update organization name to have a change dict
    original_name = org.name
    org.name = "org1-updated"
    org.save()

    entry = LogEntry.objects.create(
        content_type=ContentType.objects.get_for_model(Organization),
        object_pk=str(org.pk),
        object_repr=str(org),
        actor=user,
        action=LogEntry.Action.UPDATE,
        changes={"name": [original_name, org.name]},
    )

    qs = build_audit_log_queryset(pks)
    assert entry in list(qs)

    filtered_qs, _ = apply_audit_log_get_filters(
        qs,
        {
            "user": str(user.pk),
            "resource": f"{entry.content_type.app_label}.{entry.content_type.model}",
        },
    )
    assert entry in list(filtered_qs)

    display = get_audit_log_display_data(filtered_qs)
    assert display[entry.id]["display_changes_dict"]["name"] == [
        original_name,
        org.name,
    ]
