from django.db import migrations, models
import django.db.models.deletion


REPORT_SQL = """
DROP PROCEDURE IF EXISTS report_upsert(uuid, uuid, timestamptz, jsonb);

CREATE PROCEDURE report_upsert(
    p_report uuid,
    p_project uuid,
    p_automation uuid,
    p_period_day date,
    p_period_type text,
    p_period_timezone text,
    p_changes jsonb
)
LANGUAGE plpgsql
AS $$
DECLARE
   _change      uuid;
   _report_id   uuid;
BEGIN
    INSERT INTO opencve_reports (
        id,
        created_at,
        updated_at,
        day,
        period_type,
        period_timezone,
        seen,
        project_id,
        automation_id
    )
    VALUES(
        p_report,
        NOW(),
        NOW(),
        p_period_day,
        p_period_type,
        p_period_timezone,
        'f',
        p_project,
        p_automation
    )
    ON CONFLICT (day, period_type, project_id, automation_id) DO NOTHING;

    SELECT id INTO _report_id
    FROM opencve_reports
    WHERE project_id = p_project
      AND automation_id = p_automation
      AND day = p_period_day
      AND period_type = p_period_type;

    FOR _change IN SELECT * FROM json_array_elements_text(p_changes::json)
    LOOP
      INSERT INTO opencve_reports_changes (report_id, change_id)
      VALUES(_report_id, _change)
      ON CONFLICT (report_id, change_id) DO NOTHING;
    END LOOP;
END;
$$;
"""

REPORT_REVERSE_SQL = """
DROP PROCEDURE IF EXISTS report_upsert(
    uuid, uuid, uuid, date, text, text, jsonb
);

CREATE PROCEDURE report_upsert(
    report uuid,
    project uuid,
    created timestamptz,
    changes jsonb
)
LANGUAGE plpgsql
AS $$
DECLARE
   _change      uuid;
   _report_id   uuid;
BEGIN
    INSERT INTO opencve_reports (id, created_at, updated_at, day, seen, project_id)
    VALUES(report, created, created, DATE(created), 'f', project)
    ON CONFLICT (day, project_id) DO NOTHING;

    SELECT id INTO _report_id FROM opencve_reports
    WHERE project_id = project AND day = DATE(created);

    FOR _change IN SELECT * FROM json_array_elements_text(changes::json)
    LOOP
      INSERT INTO opencve_reports_changes (report_id, change_id)
      VALUES(_report_id, _change)
      ON CONFLICT (report_id, change_id) DO NOTHING;
    END LOOP;
END;
$$;
"""


class Migration(migrations.Migration):
    dependencies = [
        ("projects", "0008_automation_automationexecution_automationrunresult"),
        ("changes", "0004_report_ai_summary"),
    ]

    operations = [
        migrations.AddField(
            model_name="report",
            name="automation",
            field=models.ForeignKey(
                blank=True,
                null=True,
                on_delete=django.db.models.deletion.CASCADE,
                related_name="reports",
                to="projects.automation",
            ),
        ),
        migrations.AddField(
            model_name="report",
            name="period_type",
            field=models.CharField(
                choices=[("daily", "Daily"), ("weekly", "Weekly")],
                default="daily",
                max_length=20,
            ),
        ),
        migrations.AddField(
            model_name="report",
            name="period_timezone",
            field=models.CharField(default="UTC", max_length=64),
        ),
        migrations.RemoveConstraint(
            model_name="report",
            name="ix_unique_project_day",
        ),
        migrations.AddConstraint(
            model_name="report",
            constraint=models.UniqueConstraint(
                fields=("day", "period_type", "project_id", "automation_id"),
                name="ix_unique_project_period_automation",
            ),
        ),
        migrations.RunSQL(sql=REPORT_SQL, reverse_sql=REPORT_REVERSE_SQL),
    ]
