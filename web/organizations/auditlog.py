from collections import defaultdict

from django.apps import apps
from django.contrib.contenttypes.models import ContentType
from django.db.models import Q
from django.utils.dateparse import parse_date

from auditlog.models import LogEntry
from cves.constants import PRODUCT_SEPARATOR
from opencve.constants import RESOURCE_LABELS
from opencve.utils import normalize_pk_for_model, safe_load_json, get_resource_label
from organizations.models import Membership, Organization, OrganizationAPIToken
from projects.models import CveTracker, Notification, Project
from views.models import View as SavedView

# Fields to hide for all resources
FIELDS_ALWAYS_HIDDEN = frozenset({"updated_at"})


# Configuration of which fields are visible per resource.
# You can configure visibility per model (string key); applies to CREATE and DELETE.
# If no entry is found, all fields (except FIELDS_ALWAYS_HIDDEN) are shown.
DISPLAY_FIELDS_BY_RESOURCE_ACTION = {
    "cvetracker": ("cve", "project", "assignee", "status"),
    "membership": ("role", "email", "date_joined"),
    "organizationapitoken": ("name", "is_active", "description"),
    "view": ("name", "query", "privacy"),
    "notification": ("name", "type", "project", "is_enabled", "configuration"),
    "project": ("name", "active", "description", "subscriptions"),
    "organization": ("name",),
}


def _membership_repr(obj):
    if obj.email:
        return obj.email
    if obj.user_id:
        return getattr(obj.user, "username", None) or str(obj.user_id)
    return "—"


def _name_repr(obj):
    return getattr(obj, "name", str(obj))


def _user_repr(obj):
    return getattr(obj, "username", str(obj))


# (content_type.model) -> callable(obj) -> str for the "Target" column
OBJECT_REPR_FUNCTIONS = {
    "membership": _membership_repr,
    "organizationapitoken": _name_repr,
    "view": _name_repr,
    "notification": _name_repr,
    "project": _name_repr,
    "organization": _name_repr,
    "usertag": _name_repr,
    "cvetag": _name_repr,
    "user": _user_repr,
}


def _display_repr_for_same_content_type(ct_entries, content_type):
    """
    Return dict entry.id -> display string for entries sharing the same content type.
    Resolves objects from DB and uses OBJECT_REPR_FUNCTIONS; fallback to entry.object_repr.
    """
    model_class = content_type.model_class()
    if model_class is None:
        return {e.id: e.object_repr for e in ct_entries}

    model_name = content_type.model.lower()
    formatter = OBJECT_REPR_FUNCTIONS.get(model_name)

    # Normalize string PKs to the model's pk type (UUID, int, etc.)
    try:
        pk_list = [normalize_pk_for_model(model_class, e.object_pk) for e in ct_entries]
    except Exception:
        return {e.id: e.object_repr for e in ct_entries}

    # Bulk fetch objects; membership needs user for display
    try:
        qs = model_class.objects.filter(pk__in=pk_list)
        if model_name == "membership":
            qs = qs.select_related("user")
        objects = {obj.pk: obj for obj in qs}
    except Exception:
        return {e.id: e.object_repr for e in ct_entries}

    # Map each entry to its display string
    result = {}
    for entry in ct_entries:
        try:
            pk = normalize_pk_for_model(model_class, entry.object_pk)
            obj = objects.get(pk)
        except Exception:
            obj = None

        if obj is not None and formatter is not None:
            try:
                result[entry.id] = formatter(obj)
            except Exception:
                result[entry.id] = entry.object_repr
        else:
            result[entry.id] = entry.object_repr if obj is None else str(obj)
    return result


def get_display_object_repr_for_entries(entries):
    """
    For each entry, resolve the logged object (if still in DB) and return a display string
    using OBJECT_REPR_FUNCTIONS. Fallback to entry.object_repr when the object is deleted
    or no formatter is defined.
    Returns a dict entry.id -> display string.
    """
    result = {}

    # Group entries by content type to minimize DB hits
    by_ct = defaultdict(list)
    for entry in entries:
        by_ct[entry.content_type_id].append(entry)

    for ct_id, ct_entries in by_ct.items():
        try:
            content_type = ContentType.objects.get_for_id(ct_id)
        except ContentType.DoesNotExist:
            for entry in ct_entries:
                result[entry.id] = entry.object_repr
            continue
        result.update(_display_repr_for_same_content_type(ct_entries, content_type))

    return result


def _format_notification_configuration_value(raw_value):
    """
    Human‑friendly rendering for Notification.configuration JSON.

    Expected structure (keys are optional):
    {
      "extras": {"email": "...", "webhook_url": "...", "headers": {...}, "url": "..."},
      "types": [...],
      "metrics": {"cvss31": "..."}
    }
    """
    data = safe_load_json(raw_value)
    if not data:
        return raw_value

    # Build human-readable lines from known keys
    lines = []
    extras = data.get("extras") or {}

    email = extras.get("email") or extras.get("created_by_email")
    if email:
        lines.append(f"Email: {email}")

    webhook_url = extras.get("webhook_url")
    if webhook_url:
        lines.append(f"Webhook URL: {webhook_url}")

    url = extras.get("url")
    if url and url != webhook_url:
        lines.append(f"URL: {url}")

    headers = extras.get("headers") or {}
    if isinstance(headers, dict) and headers:
        lines.append(f"Headers: {', '.join(f'{k}: {v}' for k, v in headers.items())}")

    types = data.get("types") or []
    if isinstance(types, (list, tuple)) and types:
        lines.append(f"Types: {', '.join(str(t) for t in types)}")

    metrics = data.get("metrics") or {}
    if metrics.get("cvss31"):
        lines.append(f"CVSS 3.1: {metrics['cvss31']}")

    if not lines:
        return raw_value

    return "\n".join(lines)


def _format_notification_configuration_changes(before_raw, after_raw):
    """
    Produce two multi-line strings (before, after) containing ONLY the lines
    that differ between the human‑readable summaries of the two configurations.
    """
    before_summary = _format_notification_configuration_value(before_raw) or ""
    after_summary = _format_notification_configuration_value(after_raw) or ""
    before_lines = [line for line in str(before_summary).splitlines() if line.strip()]
    after_lines = [line for line in str(after_summary).splitlines() if line.strip()]
    common = set(before_lines) & set(after_lines)
    only_before = [line for line in before_lines if line not in common]
    only_after = [line for line in after_lines if line not in common]
    return "\n".join(only_before), "\n".join(only_after)


def _resolve_project_id_to_name(project_id):
    """Return project name for the given project ID, or the ID as string if not found."""
    if project_id is None or project_id == "":
        return None
    try:
        Project = apps.get_model("projects", "Project")
        proj = (
            Project.objects.filter(pk=project_id).values_list("name", flat=True).first()
        )
        return proj if proj is not None else str(project_id)
    except Exception:
        return str(project_id)


def _resolve_cve_id_to_display(cve_id):
    """Return a human readable identifier for a CVE primary key (CVE.cve_id or raw ID)."""
    if cve_id is None or cve_id == "":
        return None
    try:
        Cve = apps.get_model("cves", "Cve")
        row = Cve.objects.filter(pk=cve_id).values_list("cve_id", flat=True).first()
        return row if row is not None else str(cve_id)
    except Exception:
        return str(cve_id)


def _resolve_user_id_to_display(user_id):
    """Return a human readable identifier for a User (username, email, or raw ID)."""
    if user_id is None or user_id == "":
        return None
    try:
        User = apps.get_model("users", "User")
        user = User.objects.filter(pk=user_id).only("username", "email").first()
        if user is None:
            return str(user_id)
        return (
            getattr(user, "username", None)
            or getattr(user, "email", None)
            or str(user_id)
        )
    except Exception:
        return str(user_id)


def _resolve_pair(before, after, resolver):
    """Apply resolver to before/after when not empty; return (resolved_before, resolved_after)."""
    return (
        resolver(before) if before not in (None, "") else before,
        resolver(after) if after not in (None, "") else after,
    )


def _normalize_subscriptions_payload(raw_value):
    """Normalize a Project.subscriptions JSON-like value to sorted vendors/products lists."""
    data = safe_load_json(raw_value) or {}
    raw_vendors = data.get("vendors") or []
    raw_products = data.get("products") or []

    # Coerce to list (string -> single-item list)
    vendors = (
        [raw_vendors]
        if isinstance(raw_vendors, str)
        else list(raw_vendors) if isinstance(raw_vendors, (list, tuple)) else []
    )
    products = (
        [raw_products]
        if isinstance(raw_products, str)
        else list(raw_products) if isinstance(raw_products, (list, tuple)) else []
    )

    vendors = sorted({str(v) for v in vendors})

    # Strip vendor prefix from products (e.g. "vendor$PRODUCT$name" -> "name")
    products_clean = []
    for p in products:
        p_str = str(p)
        products_clean.append(
            p_str.split(PRODUCT_SEPARATOR, 1)[-1]
            if PRODUCT_SEPARATOR in p_str
            else p_str
        )
    products = sorted(set(products_clean))
    return vendors, products


def _build_project_subscriptions_change(before_raw, after_raw):
    """
    Build a rich structure describing subscriptions changes for display:
    before/after vendors & products, plus diff (added/removed).
    """
    before_vendors, before_products = _normalize_subscriptions_payload(before_raw)
    after_vendors, after_products = _normalize_subscriptions_payload(after_raw)
    return {
        "is_project_subscriptions": True,
        "before": {"vendors": before_vendors, "products": before_products},
        "after": {"vendors": after_vendors, "products": after_products},
        "diff": {
            "vendors_added": sorted(set(after_vendors) - set(before_vendors)),
            "vendors_removed": sorted(set(before_vendors) - set(after_vendors)),
            "products_added": sorted(set(after_products) - set(before_products)),
            "products_removed": sorted(set(before_products) - set(after_products)),
        },
    }


def get_displayable_changes(entry):
    """
    Return a filtered and optionally formatted copy of entry.changes_dict for display.
    """
    changes = getattr(entry, "changes_dict", None) or {}
    model = (getattr(entry.content_type, "model", None) or "").lower()
    action = getattr(entry, "action", None)
    allowed = (
        frozenset(DISPLAY_FIELDS_BY_RESOURCE_ACTION.get(model))
        if action is not None
        else None
    )
    if action is not None:
        action = int(action)

    filtered = {}
    for field_name, value in changes.items():
        if field_name in FIELDS_ALWAYS_HIDDEN:
            continue
        if allowed is not None and field_name not in allowed:
            continue

        # auditlog stores updates as [old_value, new_value]
        before, after = (
            (value[0], value[1])
            if isinstance(value, (list, tuple)) and len(value) == 2
            else (value, None)
        )

        # Special formatting for JSON / FK fields
        if model == "notification" and field_name == "configuration":
            if action == 1 and after is not None:
                before_lines, after_lines = _format_notification_configuration_changes(
                    before, after
                )
                filtered[field_name] = {
                    "is_notification_configuration": True,
                    "before": before_lines,
                    "after": after_lines,
                }
                continue

            before = _format_notification_configuration_value(before)
            after = (
                _format_notification_configuration_value(after)
                if after is not None
                else after
            )

        elif model == "project" and field_name == "subscriptions":
            filtered[field_name] = _build_project_subscriptions_change(
                before, after or {}
            )
            continue

        # Resolve FK IDs to human-readable names for display
        elif (
            model == "notification" or model == "cvetracker"
        ) and field_name == "project":
            before, after = _resolve_pair(before, after, _resolve_project_id_to_name)

        elif model == "cvetracker" and field_name == "cve":
            before, after = _resolve_pair(before, after, _resolve_cve_id_to_display)

        elif model == "cvetracker" and field_name == "assignee":
            before, after = _resolve_pair(before, after, _resolve_user_id_to_display)

        filtered[field_name] = [before, after] if after is not None else [before]
    return filtered


# --- Organization audit log view helpers ---


def get_organization_audit_log_pks(organization):
    """Return dict mapping model class -> list of str PKs for all objects related to this org."""
    return {
        Organization: [str(organization.pk)],
        Membership: [
            str(pk)
            for pk in Membership.objects.filter(organization=organization).values_list(
                "pk", flat=True
            )
        ],
        OrganizationAPIToken: [
            str(pk)
            for pk in OrganizationAPIToken.objects.filter(
                organization=organization
            ).values_list("pk", flat=True)
        ],
        Project: [
            str(pk)
            for pk in Project.objects.filter(organization=organization).values_list(
                "pk", flat=True
            )
        ],
        Notification: [
            str(pk)
            for pk in Notification.objects.filter(
                project__organization=organization
            ).values_list("pk", flat=True)
        ],
        SavedView: [str(pk) for pk in organization.views.values_list("pk", flat=True)],
        CveTracker: [
            str(pk)
            for pk in CveTracker.objects.filter(
                project__organization=organization
            ).values_list("pk", flat=True)
        ],
    }


def extend_audit_log_pks_with_deleted(organization, pks_dict):
    """
    Return a new dict like pks_dict but with PKs of deleted objects added
    (from LogEntry) so they appear in the audit log. Does not mutate pks_dict.
    """
    result = {model: list(ids) for model, ids in pks_dict.items()}
    org_pk_str = str(organization.pk)
    delete_q = Q(action=LogEntry.Action.DELETE, serialized_data__isnull=False)

    # Models with organization in serialized_data (direct link to org)
    for model in (Membership, OrganizationAPIToken, Project):
        ct = ContentType.objects.get_for_model(model)
        for pk in LogEntry.objects.filter(
            delete_q,
            content_type=ct,
            serialized_data__fields__organization=org_pk_str,
        ).values_list("object_pk", flat=True):
            if pk not in result[model]:
                result[model].append(pk)
    ct_view = ContentType.objects.get_for_model(SavedView)
    for pk in LogEntry.objects.filter(
        delete_q,
        content_type=ct_view,
        serialized_data__fields__organization=org_pk_str,
    ).values_list("object_pk", flat=True):
        if pk not in result[SavedView]:
            result[SavedView].append(pk)

    # Notification and CveTracker are linked via project
    project_ids = result[Project]
    if project_ids:
        for model in (Notification, CveTracker):
            ct = ContentType.objects.get_for_model(model)
            for pk in LogEntry.objects.filter(
                delete_q,
                content_type=ct,
                serialized_data__fields__project__in=project_ids,
            ).values_list("object_pk", flat=True):
                if pk not in result[model]:
                    result[model].append(pk)
    return result


def build_audit_log_queryset(pks_dict):
    """Build LogEntry queryset for the given PKs per model."""
    model_filters = [
        Q(
            content_type=ContentType.objects.get_for_model(model),
            object_pk__in=ids,
        )
        for model, ids in pks_dict.items()
        if ids
    ]

    if not model_filters:
        return LogEntry.objects.none()

    base_q = model_filters[0]
    for q in model_filters[1:]:
        base_q |= q

    return (
        LogEntry.objects.filter(base_q)
        .select_related("actor", "content_type")
        .order_by("-timestamp")
    )


def get_audit_log_filter_choices(entries_qs):
    """Return (users_choices, resources_choices, action_choices) from entries queryset."""
    actors = (
        entries_qs.filter(actor__isnull=False)
        .values("actor_id", "actor__username")
        .distinct()
        .order_by("actor__username")
    )
    users_choices = [
        {"id": str(a["actor_id"]), "username": a["actor__username"]} for a in actors
    ]

    # Distinct content types for the resource filter dropdown
    resources = (
        entries_qs.values(
            "content_type_id",
            "content_type__app_label",
            "content_type__model",
        )
        .distinct()
        .order_by("content_type__app_label", "content_type__model")
    )

    resources_choices = [
        {
            "key": f'{r["content_type__app_label"]}.{r["content_type__model"]}',
            "label": RESOURCE_LABELS.get(
                f'{r["content_type__app_label"]}.{r["content_type__model"]}',
                r["content_type__model"].replace("_", " ").title(),
            ),
        }
        for r in resources
    ]

    action_choices = [
        {"value": choice[0], "label": choice[1]} for choice in LogEntry.Action.choices
    ]

    return users_choices, resources_choices, action_choices


def apply_audit_log_get_filters(entries_qs, get_params):
    """Apply GET parameters to the entries queryset. Returns (filtered_qs, filters_dict)."""
    filters = {
        "user": get_params.get("user") or "",
        "resource": get_params.get("resource") or "",
        "action": get_params.get("action") or "",
        "date_from": get_params.get("date_from") or "",
        "date_to": get_params.get("date_to") or "",
    }

    # User: "system" = actor is null, else filter by actor_id
    user_filter = filters["user"]
    if user_filter == "system":
        entries_qs = entries_qs.filter(actor__isnull=True)
    elif user_filter:
        entries_qs = entries_qs.filter(actor_id=user_filter)

    if filters["resource"]:
        try:
            app_label, model = filters["resource"].split(".", 1)
            ct = ContentType.objects.get(app_label=app_label, model=model)
            entries_qs = entries_qs.filter(content_type=ct)
        except (ValueError, ContentType.DoesNotExist):
            pass

    if filters["action"]:
        try:
            entries_qs = entries_qs.filter(action=int(filters["action"]))
        except ValueError:
            pass

    # Date range (inclusive)
    if filters["date_from"]:
        parsed = parse_date(filters["date_from"])
        if parsed:
            entries_qs = entries_qs.filter(timestamp__date__gte=parsed)

    if filters["date_to"]:
        parsed = parse_date(filters["date_to"])
        if parsed:
            entries_qs = entries_qs.filter(timestamp__date__lte=parsed)

    return entries_qs, filters


def get_audit_log_display_data(entries):
    """
    Return display data for each entry: dict entry.id -> {
        "display_changes_dict", "display_object_repr", "resource_label"
    }.
    Does not mutate the entry objects.
    """
    display_repr_by_id = get_display_object_repr_for_entries(entries)
    return {
        entry.id: {
            "display_changes_dict": get_displayable_changes(entry),
            "display_object_repr": display_repr_by_id.get(entry.id, entry.object_repr),
            "resource_label": get_resource_label(entry.content_type),
        }
        for entry in entries
    }
