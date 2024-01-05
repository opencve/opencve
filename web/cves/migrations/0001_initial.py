# Generated by Django 4.2.3 on 2023-12-24 14:06

import django.contrib.postgres.indexes
from django.db import migrations, models
import django.db.models.deletion
import django.db.models.functions.text
import django.utils.timezone
import uuid


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='Cwe',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('cwe_id', models.CharField(max_length=16, unique=True)),
                ('name', models.CharField(blank=True, max_length=256, null=True)),
                ('description', models.TextField(blank=True, null=True)),
            ],
            options={
                'db_table': 'opencve_cwes',
            },
        ),
        migrations.CreateModel(
            name='Vendor',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('name', models.CharField(max_length=256, unique=True)),
            ],
            options={
                'db_table': 'opencve_vendors',
            },
        ),
        migrations.CreateModel(
            name='Product',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('name', models.CharField(max_length=256)),
                ('vendor', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='products', to='cves.vendor')),
            ],
            options={
                'db_table': 'opencve_products',
            },
        ),
        migrations.CreateModel(
            name='Cve',
            fields=[
                ('id', models.UUIDField(default=uuid.uuid4, primary_key=True, serialize=False)),
                ('created_at', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('updated_at', models.DateTimeField(db_index=True, default=django.utils.timezone.now)),
                ('cve_id', models.CharField(max_length=20, unique=True)),
                ('vendors', models.JSONField(default=list)),
                ('cwes', models.JSONField(default=list)),
                ('sources', models.JSONField(default=dict)),
                ('summary', models.TextField(default=None, null=True)),
                ('cvss', models.JSONField(default=dict)),
            ],
            options={
                'db_table': 'opencve_cves',
                'indexes': [django.contrib.postgres.indexes.GinIndex(fields=['vendors'], name='ix_cves_vendors'), django.contrib.postgres.indexes.GinIndex(fields=['cwes'], name='ix_cves_cwes'), django.contrib.postgres.indexes.GinIndex(django.contrib.postgres.indexes.OpClass(django.db.models.functions.text.Upper('summary'), name='gin_trgm_ops'), name='ix_cves_summary'), django.contrib.postgres.indexes.GinIndex(django.contrib.postgres.indexes.OpClass(django.db.models.functions.text.Upper('cve_id'), name='gin_trgm_ops'), name='ix_cves_cve_id')],
            },
        ),
        migrations.AddConstraint(
            model_name='product',
            constraint=models.UniqueConstraint(fields=('name', 'vendor_id'), name='ix_unique_products'),
        ),
    ]
