# Generated by Django 4.2.15 on 2025-01-26 00:07

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0002_alter_default_credentials_password_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='global_settings',
            name='Max_Capture_Age',
            field=models.IntegerField(default=20),
        ),
        migrations.AlterField(
            model_name='global_settings',
            name='Max_NAT_Inactive_Age',
            field=models.IntegerField(default=180),
        ),
        migrations.AlterField(
            model_name='global_settings',
            name='Max_NAT_ZeroHit_Age',
            field=models.IntegerField(default=180),
        ),
        migrations.AlterField(
            model_name='global_settings',
            name='N_NAT_Most_Triggered',
            field=models.IntegerField(default=10),
        ),
        migrations.AlterField(
            model_name='global_settings',
            name='WTFLog_Duration_Days',
            field=models.IntegerField(default=100),
        ),
    ]
