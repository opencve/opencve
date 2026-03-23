from django.db import migrations


TYPE_TO_TRIGGERS = {
    "created": ["cve_enters_project"],
    "description": ["description_changed"],
    "title": ["title_changed"],
    "first_time": ["cve_enters_project"],
    "weaknesses": ["new_weakness"],
    "cpes": ["new_vendor", "new_product"],
    "vendors": ["new_vendor", "new_product"],
    "references": ["new_reference"],
    "metrics": ["cvss_increased", "cvss_decreased"],
}


def _to_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _build_conditions(cvss31):
    and_children = []
    parsed_cvss31 = _to_float(cvss31)
    if parsed_cvss31 is not None:
        and_children.append(
            {
                "type": "cvss_gte",
                "value": {"value": parsed_cvss31, "version": "v3.1"},
            }
        )

    return {
        "operator": "OR",
        "children": [{"operator": "AND", "children": and_children}],
    }


def _build_triggers(types):
    triggers = []
    for item in types:
        for trigger in TYPE_TO_TRIGGERS.get(item, []):
            if trigger not in triggers:
                triggers.append(trigger)
    return triggers


def migrate_notification_rules_to_automations(apps, schema_editor):
    Notification = apps.get_model("projects", "Notification")
    Automation = apps.get_model("projects", "Automation")

    for notification in Notification.objects.select_related("project").all():
        configuration = notification.configuration or {}
        notification_types = configuration.get("types") or []
        if not isinstance(notification_types, list):
            notification_types = []

        metrics = configuration.get("metrics") or {}
        if not isinstance(metrics, dict):
            metrics = {}

        automation_configuration = {
            "triggers": _build_triggers(notification_types),
            "conditions": _build_conditions(metrics.get("cvss31")),
            "actions": [{"type": "send_notification", "value": str(notification.id)}],
        }

        Automation.objects.create(
            project_id=notification.project_id,
            name=notification.name,
            is_enabled=notification.is_enabled,
            trigger_type="realtime",
            configuration=automation_configuration,
        )

        extras = configuration.get("extras")
        # notification.configuration = {"extras": extras if isinstance(extras, dict) else {}}
        # notification.save(update_fields=["configuration", "updated_at"])


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("projects", "0008_automation_automationexecution_automationrunresult"),
    ]

    operations = [
        migrations.RunPython(migrate_notification_rules_to_automations, noop),
    ]
