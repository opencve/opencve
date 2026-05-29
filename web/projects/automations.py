"""
Human-readable labels and flow graph data for automation configuration.

Long labels mirror web/static/js/custom.js; short labels are used on the Overview graph.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from projects.models import Automation, CveTracker, count_conditions_tree

TRIGGER_LABELS = {
    "cve_enters_project": "A CVE enters this project",
    "cvss_increased": "The CVSS score increases",
    "cvss_decreased": "The CVSS score decreases",
    "epss_increased": "The EPSS score increases",
    "epss_decreased": "The EPSS score decreases",
    "kev_added": "The CVE is added to the CISA KEV catalog",
    "new_vendor": "A new affected vendor is added",
    "new_product": "A new affected product is added",
    "description_changed": "The description changes",
    "title_changed": "The title changes",
    "new_reference": "A new reference is added",
    "new_weakness": "A new weakness is added",
}

CONDITION_LABEL_TEMPLATES = {
    "cvss_gte": "The CVSS {version} score is greater than or equal to {value}",
    "epss_gte": "The EPSS score is greater than or equal to {value}",
    "kev_present": "The CVE is listed in the CISA KEV catalog",
    "vendor_equals": "The vendor matches {value}",
    "product_equals": "The product matches {value}",
    "cve_newer_than": "The CVE was published less than {value} days ago",
    "cve_unassigned": "The CVE is unassigned",
    "cve_status": "The CVE status is {status}",
}

CONDITION_ICONS = {
    "cvss_gte": "fa-shield",
    "epss_gte": "fa-line-chart",
    "kev_present": "fa-star",
    "vendor_equals": "fa-building",
    "product_equals": "fa-cube",
    "cve_newer_than": "fa-clock-o",
    "cve_unassigned": "fa-user-times",
    "cve_status": "fa-flag",
}

ACTION_LABEL_TEMPLATES = {
    "send_notification": "Send a notification using {notification}",
    "assign_user": "Assign the CVE to the user {user}",
    "change_status": "Change the CVE status to {status}",
}

ACTION_ICONS = {
    "send_notification": "fa-bell",
    "assign_user": "fa-user",
    "change_status": "fa-check-circle",
}


@dataclass
class AutomationLookups:
    users_by_id: dict[str, str] = field(default_factory=dict)
    notifications_by_id: dict[str, str] = field(default_factory=dict)
    status_labels: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_context(
        cls,
        organization_members,
        notifications,
        status_choices=None,
    ) -> AutomationLookups:
        status_labels = dict(status_choices or CveTracker.STATUS_CHOICES)
        return cls(
            users_by_id={str(u.id): u.username for u in organization_members},
            notifications_by_id={str(n.id): n.name for n in notifications},
            status_labels=status_labels,
        )


class _GraphBuilder:
    def __init__(self, trigger_type: str):
        self.trigger_type = trigger_type
        self.nodes: list[dict] = []
        self.edges: list[dict] = []
        self.groups: list[dict] = []
        self._counter = 0

    def next_id(self, prefix: str) -> str:
        self._counter += 1
        return f"{prefix}_{self._counter}"

    def add_node(self, node_id: str, **kwargs) -> str:
        self.nodes.append({"id": node_id, **kwargs})
        return node_id

    def add_edge(self, source: str, target: str) -> None:
        self.edges.append({"from": source, "to": target})

    def to_dict(self) -> dict:
        return {
            "trigger_type": self.trigger_type,
            "nodes": self.nodes,
            "edges": self.edges,
            "groups": self.groups,
        }


def format_trigger(trigger_type: str) -> str:
    return TRIGGER_LABELS.get(trigger_type, trigger_type.replace("_", " ").title())


def _format_cvss_value(value: Any) -> tuple[str, str]:
    if isinstance(value, dict):
        version = value.get("version", "v3.1")
        score = value.get("value", 0)
    else:
        version = "v3.1"
        score = value
    try:
        score_str = f"{float(score):g}"
    except (TypeError, ValueError):
        score_str = str(score)
    return version, score_str


def format_condition_short(node: dict, lookups: AutomationLookups) -> str:
    condition_type = node.get("type", "")
    value = node.get("value")

    if condition_type == "cvss_gte":
        version, score_str = _format_cvss_value(value)
        return f"CVSS {version} ≥ {score_str}"

    if condition_type == "epss_gte":
        raw = value.get("value", value) if isinstance(value, dict) else value
        try:
            score_str = f"{float(raw):g}"
        except (TypeError, ValueError):
            score_str = str(raw)
        return f"EPSS ≥ {score_str}"

    if condition_type == "kev_present":
        return "KEV present"

    if condition_type == "cve_unassigned":
        return "Unassigned"

    if condition_type in ("vendor_equals", "product_equals"):
        raw = value.get("value", value) if isinstance(value, dict) else value
        label = "Vendor" if condition_type == "vendor_equals" else "Product"
        return f"{label}: {raw}"

    if condition_type == "cve_newer_than":
        raw = value.get("value", value) if isinstance(value, dict) else value
        return f"Published < {raw} days"

    if condition_type == "cve_status":
        status_key = value
        if isinstance(value, dict):
            status_key = value.get("status", "")
        label = lookups.status_labels.get(status_key, status_key)
        return f"Status: {label}"

    return condition_type.replace("_", " ").title()


def format_action_short(action: dict, lookups: AutomationLookups) -> str:
    action_type = action.get("type", "")

    if action_type == "send_notification":
        notification_id = str(action.get("value", ""))
        name = lookups.notifications_by_id.get(
            notification_id, action.get("name", notification_id)
        )
        return f"Notify: {name}"

    if action_type == "assign_user":
        username = action.get("username")
        if not username:
            user_id = str(action.get("value", ""))
            username = lookups.users_by_id.get(user_id, user_id)
        return f"Assign user: {username}"

    if action_type == "change_status":
        label = action.get("label")
        if not label:
            status_key = action.get("value", "")
            label = lookups.status_labels.get(status_key, status_key)
        return f"Change status: {label}"

    return action_type.replace("_", " ").title()


def format_action(action: dict, lookups: AutomationLookups) -> str:
    action_type = action.get("type", "")
    template = ACTION_LABEL_TEMPLATES.get(action_type)
    if not template:
        return action_type.replace("_", " ").title()

    if action_type == "send_notification":
        notification_id = str(action.get("value", ""))
        name = lookups.notifications_by_id.get(
            notification_id, action.get("name", notification_id)
        )
        return template.format(notification=name)

    if action_type == "assign_user":
        username = action.get("username")
        if not username:
            user_id = str(action.get("value", ""))
            username = lookups.users_by_id.get(user_id, user_id)
        return template.format(user=username)

    if action_type == "change_status":
        label = action.get("label")
        if not label:
            status_key = action.get("value", "")
            label = lookups.status_labels.get(status_key, status_key)
        return template.format(status=label)

    return template


def _weekday_label(weekday_key: str) -> str:
    return dict(Automation.WEEKDAY_CHOICES).get(weekday_key, weekday_key.title())


def _frequency_label(frequency: str) -> str:
    return dict(Automation.FREQUENCY_CHOICES).get(frequency, frequency.title())


def format_schedule_line(automation: Automation) -> str:
    frequency = automation.frequency or Automation.FREQUENCY_DAILY
    timezone = automation.schedule_timezone or "UTC"
    freq_label = _frequency_label(frequency)
    return (
        f"Collect matching CVEs over a {freq_label} period "
        f"in the {timezone} timezone"
    )


def format_report_actions_schedule_line(automation: Automation) -> str:
    time_str = ""
    if automation.schedule_time:
        time_str = automation.schedule_time.strftime("%H:%M")
    if automation.frequency == Automation.FREQUENCY_WEEKLY:
        day = _weekday_label(automation.schedule_weekday or Automation.WEEKDAY_MONDAY)
        return f"Run every {day} at {time_str or '09:00'}"
    return f"Run at {time_str or '09:00'}"


def _add_placeholder(builder: _GraphBuilder, title: str = "(none)") -> str:
    node_id = builder.next_id("none")
    builder.add_node(
        node_id,
        kind="placeholder",
        title=title,
        icon="fa-minus-circle",
        muted=True,
    )
    return node_id


def _add_condition_leaf(
    builder: _GraphBuilder, node: dict, lookups: AutomationLookups
) -> str:
    condition_type = node.get("type", "")
    node_id = builder.next_id("cond")
    builder.add_node(
        node_id,
        kind="condition",
        title=format_condition_short(node, lookups),
        icon=CONDITION_ICONS.get(condition_type, "fa-filter"),
    )
    return node_id


def _connect_triggers_to_conditions(
    builder: _GraphBuilder,
    trigger_ids: list[str],
    cond_entries: list[str],
) -> None:
    for trigger_id in trigger_ids:
        for cond_entry in cond_entries:
            builder.add_edge(trigger_id, cond_entry)


def _append_conditions_group(builder: _GraphBuilder, child_ids: list[str]) -> str:
    """Return exit node id (last child) for edges to actions."""
    if not child_ids:
        child_ids = [_add_placeholder(builder)]

    group_id = builder.next_id("conditions_group")
    builder.groups.append(
        {
            "id": group_id,
            "title": "Conditions",
            "icon": "fa-filter",
            "children": child_ids,
        }
    )
    return child_ids[-1]


def _append_conditions_subgraph(
    builder: _GraphBuilder,
    node: dict,
    lookups: AutomationLookups,
) -> tuple[list[str], list[str]]:
    """Return (branch_entry_ids, exit_node_ids). OR/AND are implicit (no operator nodes)."""
    if "type" in node:
        leaf_id = _add_condition_leaf(builder, node, lookups)
        _append_conditions_group(builder, [leaf_id])
        return [leaf_id], [leaf_id]

    children = node.get("children") or []
    if not children:
        placeholder_id = _add_placeholder(builder)
        _append_conditions_group(builder, [placeholder_id])
        return [placeholder_id], [placeholder_id]

    branch_entries: list[str] = []
    branch_exits: list[str] = []
    for child in children:
        if "children" in child:
            and_children = child.get("children") or []
            if not and_children:
                placeholder_id = _add_placeholder(builder)
                _append_conditions_group(builder, [placeholder_id])
                branch_entries.append(placeholder_id)
                branch_exits.append(placeholder_id)
                continue

            branch_leaf_ids: list[str] = []
            for leaf in and_children:
                if "type" in leaf:
                    branch_leaf_ids.append(_add_condition_leaf(builder, leaf, lookups))
                else:
                    sub_entries, sub_exits = _append_conditions_subgraph(
                        builder, leaf, lookups
                    )
                    branch_entries.extend(sub_entries)
                    branch_exits.extend(sub_exits)

            if branch_leaf_ids:
                exit_id = _append_conditions_group(builder, branch_leaf_ids)
                branch_entries.append(branch_leaf_ids[0])
                branch_exits.append(exit_id)
        elif "type" in child:
            leaf_id = _add_condition_leaf(builder, child, lookups)
            _append_conditions_group(builder, [leaf_id])
            branch_entries.append(leaf_id)
            branch_exits.append(leaf_id)
        else:
            sub_entries, sub_exits = _append_conditions_subgraph(
                builder, child, lookups
            )
            branch_entries.extend(sub_entries)
            branch_exits.extend(sub_exits)

    return branch_entries, branch_exits


def _append_triggers_group(
    builder: _GraphBuilder,
    *,
    trigger_types: list[str] | None = None,
    schedule_automation: Automation | None = None,
) -> list[str]:
    """Return trigger node ids (layout positions are set client-side in the group)."""
    group_id = builder.next_id("triggers_group")
    child_ids: list[str] = []

    if schedule_automation is not None:
        schedule_id = builder.next_id("schedule")
        builder.add_node(
            schedule_id,
            kind="schedule",
            title="Schedule",
            subtitle=format_schedule_line(schedule_automation),
            icon="fa-calendar",
        )
        child_ids.append(schedule_id)
    elif not trigger_types:
        none_id = builder.next_id("none")
        builder.add_node(
            none_id,
            kind="placeholder",
            title="(none)",
            icon="fa-minus-circle",
            muted=True,
        )
        child_ids.append(none_id)
    else:
        for trigger_type in trigger_types:
            trigger_id = builder.next_id("trigger")
            builder.add_node(
                trigger_id,
                kind="trigger",
                title=format_trigger(trigger_type),
                icon="fa-bolt",
            )
            child_ids.append(trigger_id)

    builder.groups.insert(
        0,
        {
            "id": group_id,
            "title": "Triggers",
            "icon": "fa-bolt",
            "children": child_ids,
        },
    )
    return child_ids


def _append_actions_group(
    builder: _GraphBuilder,
    actions: list,
    lookups: AutomationLookups,
    schedule_meta: str | None = None,
) -> str:
    """Return the entry node id (actions group container)."""
    group_id = builder.next_id("actions_group")
    child_ids: list[str] = []

    if schedule_meta:
        meta_id = builder.next_id("action_meta")
        builder.add_node(
            meta_id,
            kind="action",
            title=schedule_meta,
            icon="fa-clock-o",
        )
        child_ids.append(meta_id)

    if not actions and not schedule_meta:
        none_id = builder.next_id("none")
        builder.add_node(
            none_id,
            kind="placeholder",
            title="(none)",
            icon="fa-minus-circle",
            muted=True,
        )
        child_ids.append(none_id)
    else:
        for action in actions:
            action_type = action.get("type", "")
            action_id = builder.next_id("action")
            builder.add_node(
                action_id,
                kind="action",
                title=format_action_short(action, lookups),
                icon=ACTION_ICONS.get(action_type, "fa-cog"),
            )
            child_ids.append(action_id)

    builder.groups.append(
        {
            "id": group_id,
            "title": "Actions",
            "icon": "fa-cog",
            "children": child_ids,
        }
    )
    return child_ids[0]


def build_automation_flow_graph(
    automation: Automation,
    lookups: AutomationLookups,
) -> dict:
    config = automation.configuration or {}
    conditions = config.get("conditions") or {"operator": "OR", "children": []}
    actions = config.get("actions") or []

    builder = _GraphBuilder(automation.trigger_type)

    if automation.trigger_type == Automation.TRIGGER_REPORT:
        trigger_ids = _append_triggers_group(builder, schedule_automation=automation)
    else:
        trigger_ids = _append_triggers_group(
            builder, trigger_types=config.get("triggers") or []
        )

    if count_conditions_tree(conditions) == 0 and not (conditions.get("children")):
        cond_entry = _add_placeholder(builder)
        _append_conditions_group(builder, [cond_entry])
        cond_entries = [cond_entry]
        cond_exits = [cond_entry]
    else:
        cond_entries, cond_exits = _append_conditions_subgraph(
            builder, conditions, lookups
        )

    _connect_triggers_to_conditions(builder, trigger_ids, cond_entries)

    schedule_meta = None
    if automation.trigger_type == Automation.TRIGGER_REPORT:
        schedule_meta = format_report_actions_schedule_line(automation)

    actions_entry = _append_actions_group(
        builder, actions, lookups, schedule_meta=schedule_meta
    )
    for cond_exit in cond_exits:
        builder.add_edge(cond_exit, actions_entry)

    return builder.to_dict()
