# -*- coding: utf-8 -*-
# Generated by Django 1.11.6 on 2018-06-03 08:07
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('agents', '0009_auto_20180603_1450'),
    ]

    operations = [
        migrations.AddField(
            model_name='hoststatisticsmodel',
            name='abnormal_alert_count',
            field=models.IntegerField(default=1),
        ),
    ]
