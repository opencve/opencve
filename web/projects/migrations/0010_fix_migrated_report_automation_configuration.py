from django.db import migrations


CORRECT_REPORT_CONFIGURATION = {
    "conditions": {
        "operator": "OR",
        "children": [{"operator": "AND", "children": []}],
    },
    "actions": [{"type": "generate_report", "value": True}],
}


def _is_broken_migrated_report_configuration(configuration):
    if not isinstance(configuration, dict):
        return False

    actions = configuration.get("actions")
    conditions = configuration.get("conditions")
    if actions != []:
        return False
    if not isinstance(conditions, dict):
        return False

    return conditions.get("operator") == "OR" and conditions.get("children") == []


def fix_migrated_report_automation_configuration(apps, schema_editor):
    """
    This migration fixes the broken configuration of report automations
    that were migrated from the legacy notification system.
    """
    Automation = apps.get_model("projects", "Automation")

    for automation in Automation.objects.filter(trigger_type="report").iterator():
        if not _is_broken_migrated_report_configuration(automation.configuration):
            continue

        automation.configuration = CORRECT_REPORT_CONFIGURATION
        automation.save(update_fields=["configuration", "updated_at"])


def noop(apps, schema_editor):
    pass


class Migration(migrations.Migration):
    dependencies = [
        ("projects", "0009_migrate_notification_rules_to_automations"),
    ]

    operations = [
        migrations.RunPython(
            fix_migrated_report_automation_configuration,
            noop,
        ),
    ]
