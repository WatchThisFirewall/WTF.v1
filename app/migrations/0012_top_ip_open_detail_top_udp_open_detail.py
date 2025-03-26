# Generated by Django 4.2.15 on 2025-03-25 00:10

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('app', '0011_alter_top_tcp_open_detail_tcp_open_val'),
    ]

    operations = [
        migrations.CreateModel(
            name='Top_IP_Open_Detail',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('HostName', models.CharField(blank=True, default='', max_length=120, null=True)),
                ('ACL_Line', models.TextField(blank=True, default='', null=True)),
                ('IP_Open_Val', models.DecimalField(blank=True, decimal_places=0, default=0, max_digits=50, null=True)),
            ],
            options={
                'verbose_name': 'Top_IP_Open_Detail',
                'verbose_name_plural': 'Top_IP_Open_Detail',
                'db_table': 'Top_IP_Open_Detail',
                'managed': True,
            },
        ),
        migrations.CreateModel(
            name='Top_UDP_Open_Detail',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('HostName', models.CharField(blank=True, default='', max_length=120, null=True)),
                ('ACL_Line', models.TextField(blank=True, default='', null=True)),
                ('UDP_Open_Val', models.DecimalField(blank=True, decimal_places=0, default=0, max_digits=50, null=True)),
            ],
            options={
                'verbose_name': 'Top_UDP_Open_Detail',
                'verbose_name_plural': 'Top_UDP_Open_Detail',
                'db_table': 'Top_UDP_Open_Detail',
                'managed': True,
            },
        ),
    ]
