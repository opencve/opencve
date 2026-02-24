# Data migration: rename trigger_type value from "periodic" to "scheduled"

from django.db import migrations


def periodic_to_scheduled(apps, schema_editor):
    Automation = apps.get_model("projects", "Automation")
    Automation.objects.filter(trigger_type="periodic").update(trigger_type="scheduled")


def scheduled_to_periodic(apps, schema_editor):
    Automation = apps.get_model("projects", "Automation")
    Automation.objects.filter(trigger_type="scheduled").update(trigger_type="periodic")


class Migration(migrations.Migration):

    dependencies = [
        ("projects", "0012_automationrunoutput_details_only"),
    ]

    operations = [
        migrations.RunPython(periodic_to_scheduled, scheduled_to_periodic),
    ]
