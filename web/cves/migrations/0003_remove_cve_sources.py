# Generated by Django 4.2.3 on 2023-12-31 14:31

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('cves', '0002_add_cve_upsert_procedures'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='cve',
            name='sources',
        ),
    ]
