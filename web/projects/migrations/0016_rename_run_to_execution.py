# Rename AutomationRun → AutomationExecution (runs → executions)

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("projects", "0015_rename_automationrunoutput_to_automationrunresult"),
    ]

    operations = [
        # 1. Rename AutomationRun model and table to AutomationExecution
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.RenameModel(
                    old_name="AutomationRun",
                    new_name="AutomationExecution",
                ),
                migrations.AlterModelTable(
                    name="automationexecution",
                    table="opencve_automation_executions",
                ),
            ],
            database_operations=[
                migrations.RunSQL(
                    sql="ALTER TABLE opencve_automation_runs RENAME TO opencve_automation_executions",
                    reverse_sql="ALTER TABLE opencve_automation_executions RENAME TO opencve_automation_runs",
                ),
            ],
        ),
        # 2. Rename run_at → executed_at on AutomationExecution
        migrations.RenameField(
            model_name="automationexecution",
            old_name="run_at",
            new_name="executed_at",
        ),
        # 3. Rename FK automation_run → automation_execution on AutomationRunResult
        migrations.RenameField(
            model_name="automationrunresult",
            old_name="automation_run",
            new_name="automation_execution",
        ),
        # 4. Rename AutomationRunResult table
        migrations.SeparateDatabaseAndState(
            state_operations=[
                migrations.AlterModelTable(
                    name="automationrunresult",
                    table="opencve_automation_execution_results",
                ),
            ],
            database_operations=[
                migrations.RunSQL(
                    sql="ALTER TABLE opencve_automation_run_results RENAME TO opencve_automation_execution_results",
                    reverse_sql="ALTER TABLE opencve_automation_execution_results RENAME TO opencve_automation_run_results",
                ),
            ],
        ),
    ]
