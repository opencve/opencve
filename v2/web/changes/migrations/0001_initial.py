# Generated by Django 4.2.3 on 2023-08-02 19:42

from django.db import migrations, models
import django.utils.timezone
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Change',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('path', models.TextField(default=None)),
                ('commit', models.CharField(max_length=40)),
            ],
            options={
                'db_table': 'opencve_changes',
            },
        ),
        migrations.CreateModel(
            name='Event',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('type', models.CharField(max_length=50)),
                ('details', models.JSONField()),
            ],
            options={
                'db_table': 'opencve_events',
            },
        ),
        migrations.CreateModel(
            name='Report',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('day', models.DateField(default=django.utils.timezone.now)),
                ('seen', models.BooleanField(default=False)),
                ('changes', models.ManyToManyField(to='changes.change')),
            ],
            options={
                'db_table': 'opencve_reports',
            },
        ),
    ]