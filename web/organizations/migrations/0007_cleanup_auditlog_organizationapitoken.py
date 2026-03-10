from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("organizations", "0006_organizationapitoken"),
    ]

    operations = [
        # Remove audit log entries with only the "last_used_at"
        # and "updated_at" fields for organization API tokens
        migrations.RunSQL(
            sql="""
            DELETE FROM auditlog_logentry l
            USING django_content_type ct
            WHERE l.content_type_id = ct.id
              AND ct.app_label = 'organizations'
              AND ct.model = 'organizationapitoken'
              AND NOT EXISTS (
                  SELECT 1
                  FROM jsonb_object_keys(l.changes) AS key
                  WHERE key NOT IN ('last_used_at','updated_at')
              );
            """,
            reverse_sql=migrations.RunSQL.noop,
        ),
        # Remove log entries with only the "updated_at" field
        migrations.RunSQL(
            sql="""
            DELETE FROM auditlog_logentry l
            WHERE (
                SELECT array_agg(key ORDER BY key)
                FROM jsonb_object_keys(l.changes) AS key
            ) = ARRAY['updated_at'];
            """,
            reverse_sql=migrations.RunSQL.noop,
        ),
    ]
