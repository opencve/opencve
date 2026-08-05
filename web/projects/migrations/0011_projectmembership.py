import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("organizations", "0012_alter_membership_role_acl"),
        ("projects", "0010_fix_migrated_report_automation_configuration"),
    ]

    operations = [
        migrations.CreateModel(
            name="ProjectMembership",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("role", models.CharField(max_length=32)),
                (
                    "membership",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="project_memberships",
                        to="organizations.membership",
                    ),
                ),
                (
                    "project",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="memberships",
                        to="projects.project",
                    ),
                ),
            ],
            options={
                "db_table": "opencve_project_memberships",
                "indexes": [
                    models.Index(fields=["membership"], name="ix_pm_membership"),
                    models.Index(fields=["project"], name="ix_pm_project"),
                ],
            },
        ),
        migrations.AddConstraint(
            model_name="projectmembership",
            constraint=models.UniqueConstraint(
                fields=("project", "membership"),
                name="ix_unique_project_membership",
            ),
        ),
    ]
