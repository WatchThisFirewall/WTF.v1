# Generated by Django 4.2.15 on 2025-03-21 11:44

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0004_acl_most_expanded'),
    ]

    operations = [
        migrations.CreateModel(
            name='ACL_Most_HitPermit',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('HostName', models.CharField(blank=True, default='', max_length=120, null=True)),
                ('ACL_Line', models.TextField()),
                ('ACL_HitCnt', models.PositiveBigIntegerField(blank=True, default=0, null=True)),
            ],
            options={
                'verbose_name': 'ACL_Most_HitPermit',
                'verbose_name_plural': 'ACL_Most_HitPermit',
                'db_table': 'ACL_Most_HitPermit',
                'managed': True,
            },
        ),
    ]
