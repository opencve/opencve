# Generated by Django 4.2.3 on 2023-12-24 14:06

import uuid

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Membership",
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
                (
                    "role",
                    models.CharField(
                        choices=[("owner", "owner"), ("member", "member")],
                        default="member",
                        max_length=20,
                    ),
                ),
                (
                    "date_invited",
                    models.DateTimeField(
                        db_index=True, default=django.utils.timezone.now
                    ),
                ),
                (
                    "date_joined",
                    models.DateTimeField(blank=True, db_index=True, null=True),
                ),
                ("key", models.CharField(blank=True, max_length=64, null=True)),
            ],
            options={
                "db_table": "opencve_memberships",
            },
        ),
        migrations.CreateModel(
            name="Organization",
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
                ("name", models.CharField(max_length=100)),
            ],
            options={
                "db_table": "opencve_organizations",
                "permissions": (("add_member", "Add member"),),
            },
        ),
    ]
