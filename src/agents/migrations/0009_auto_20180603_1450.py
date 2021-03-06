# -*- coding: utf-8 -*-
# Generated by Django 1.11.6 on 2018-06-03 07:50
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0008_auto_20180602_0834'),
    ]

    operations = [
        migrations.AddField(
            model_name='hoststatisticsmodel',
            name='is_site_down',
            field=models.BooleanField(default=False),
        ),
        migrations.AlterField(
            model_name='websitesecurityalertmodel',
            name='type',
            field=models.CharField(choices=[('VULNERABILITY', 'vulnerability'), ('ABNORMAL', 'Abnormal'), ('PENETRATION', 'Penetration testing'), ('MALWARE', 'Malware'), ('BLACKLIST', 'Blacklist'), ('WEB_DEFACE', 'Web deface'), ('SITE_DOWN', 'Site down')], default='ABNORMAL', max_length=200),
        ),
    ]
