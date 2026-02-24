# Rename AutomationRunOutput → AutomationRunResult (outputs → results)

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("projects", "0014_automation_run_remove_status_output_add_status"),
    ]

    operations = [
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.RenameModel(
                    old_name="AutomationRunOutput",
                    new_name="AutomationRunResult",
                ),
                migrations.AlterModelTable(
                    name="automationrunresult",
                    table="opencve_automation_run_results",
                ),
            ],
            database_operations=[
                migrations.RunSQL(
                    sql="ALTER TABLE opencve_automation_run_outputs RENAME TO opencve_automation_run_results",
                    reverse_sql="ALTER TABLE opencve_automation_run_results RENAME TO opencve_automation_run_outputs",
                ),
            ],
        ),
    ]
