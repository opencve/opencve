from django.db import migrations


CHANGE_SQL = """
CREATE PROCEDURE change_upsert(
    cve             text,
    change          uuid,
    created         timestamptz,
    updated         timestamptz,
    commit_hash     text,
    file_path       text,
    events_types    jsonb
)
LANGUAGE plpgsql
AS $$
DECLARE
    _cve_id     uuid;
BEGIN
    -- retrieve the cve ID
    SELECT id INTO _cve_id FROM opencve_cves WHERE cve_id = cve;

    -- create a new change
    INSERT INTO opencve_changes (id, created_at, updated_at, cve_id, path, commit, types)
    VALUES(change, created, updated, _cve_id, file_path, commit_hash, events_types)
    ON CONFLICT (created_at, cve_id, commit) DO NOTHING;
END;
$$;
"""
CHANGE_REVERSE_SQL = """
DROP PROCEDURE change_upsert(
    cve             text,
    change          uuid,
    created         timestamptz,
    updated         timestamptz,
    commit_hash     text,
    file_path       text,
    events_types    jsonb
);
"""

REPORT_SQL = """
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
    -- create the daily report for the project
    INSERT INTO opencve_reports (id, created_at, updated_at, day, seen, project_id)
    VALUES(report, created, created, DATE(created), 'f', project)
    ON CONFLICT (day, project_id) DO NOTHING;

    -- retrieve the report ID
    SELECT id INTO _report_id FROM opencve_reports
    WHERE project_id = project AND day = DATE(created);

    -- associate the changes to the report
    FOR _change IN SELECT * FROM json_array_elements_text(changes::json)
    LOOP
      INSERT INTO opencve_reports_changes (report_id, change_id)
      VALUES(_report_id, _change)
      ON CONFLICT (report_id, change_id) DO NOTHING;
    END LOOP;
END;
$$;
"""
REPORT_REVERSE_SQL = """
DROP PROCEDURE report_upsert(
    report uuid,
    project uuid,
    created timestamptz,
    changes jsonb
);
"""


class Migration(migrations.Migration):
    dependencies = [
        ('changes', '0002_initial'),
    ]

    operations = [
        migrations.RunSQL(sql=CHANGE_SQL, reverse_sql=CHANGE_REVERSE_SQL),
        migrations.RunSQL(sql=REPORT_SQL, reverse_sql=REPORT_REVERSE_SQL)
    ]