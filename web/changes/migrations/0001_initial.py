# Generated by Django 4.2.3 on 2023-12-24 14:06

from django.db import migrations, models
import django.utils.timezone
import uuid


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Change",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4, primary_key=True, serialize=False
                    ),
                ),
                (
                    "created_at",
                    models.DateTimeField(
                        db_index=True, default=django.utils.timezone.now
                    ),
                ),
                (
                    "updated_at",
                    models.DateTimeField(
                        db_index=True, default=django.utils.timezone.now
                    ),
                ),
                ("path", models.TextField(default=None)),
                ("commit", models.CharField(max_length=40)),
                ("types", models.JSONField(default=list)),
            ],
            options={
                "db_table": "opencve_changes",
            },
        ),
        migrations.CreateModel(
            name="Report",
            fields=[
                (
                    "id",
                    models.UUIDField(
                        default=uuid.uuid4, primary_key=True, serialize=False
                    ),
                ),
                (
                    "created_at",
                    models.DateTimeField(
                        db_index=True, default=django.utils.timezone.now
                    ),
                ),
                (
                    "updated_at",
                    models.DateTimeField(
                        db_index=True, default=django.utils.timezone.now
                    ),
                ),
                ("seen", models.BooleanField(default=False)),
                ("day", models.DateField(default=django.utils.timezone.now)),
                ("changes", models.ManyToManyField(to="changes.change")),
            ],
            options={
                "db_table": "opencve_reports",
            },
        ),
    ]
