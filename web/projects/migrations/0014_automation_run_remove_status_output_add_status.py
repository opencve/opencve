# Migration: remove status from AutomationRun, add status to AutomationRunOutput

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("projects", "0013_automation_trigger_periodic_to_scheduled"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="automationrun",
            name="status",
        ),
        migrations.AddField(
            model_name="automationrunoutput",
            name="status",
            field=models.CharField(
                choices=[
                    ("success", "Success"),
                    ("skipped", "Skipped"),
                    ("failed", "Failed"),
                ],
                default="success",
                max_length=20,
            ),
        ),
    ]
