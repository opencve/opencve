from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("organizations", "0010_unique_organization_name"),
    ]

    operations = [
        migrations.AddField(
            model_name="organizationapitoken",
            name="access_mode",
            field=models.CharField(
                choices=[("read", "Read-only"), ("write", "Read-write")],
                default="read",
                max_length=10,
            ),
        ),
        migrations.AddField(
            model_name="organizationapitoken",
            name="scopes",
            field=models.JSONField(blank=True, default=list),
        ),
    ]
