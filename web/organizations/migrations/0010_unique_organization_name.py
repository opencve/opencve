# Generated manually

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("organizations", "0009_alter_membership_organization"),
    ]

    operations = [
        migrations.AddConstraint(
            model_name="organization",
            constraint=models.UniqueConstraint(
                fields=("name",),
                name="ix_unique_organization_name",
            ),
        ),
    ]
