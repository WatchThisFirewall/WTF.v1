# Generated by Django 4.2.15 on 2025-04-17 13:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0013_alter_acl_gross_hostname'),
    ]

    operations = [
        migrations.AddField(
            model_name='my_devices',
            name='Hardware',
            field=models.CharField(blank=True, max_length=120, null=True),
        ),
        migrations.AddField(
            model_name='my_devices',
            name='SW_Version',
            field=models.CharField(blank=True, max_length=120, null=True),
        ),
    ]
