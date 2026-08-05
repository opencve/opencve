from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("organizations", "0011_organizationapitoken_access_mode_scopes"),
    ]

    operations = [
        migrations.AlterField(
            model_name="membership",
            name="role",
            field=models.CharField(default="member", max_length=32),
        ),
    ]
