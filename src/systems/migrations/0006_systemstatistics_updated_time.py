# -*- coding: utf-8 -*-
# Generated by Django 1.11.6 on 2018-06-18 10:35
from __future__ import unicode_literals

from django.db import migrations, models
import time


class Migration(migrations.Migration):

    dependencies = [
        ('systems', '0005_systemstatistics_date_statistic'),
    ]

    operations = [
        migrations.AddField(
            model_name='systemstatistics',
            name='updated_time',
            field=models.IntegerField(auto_created=time.time, default=1),
            preserve_default=False,
        ),
    ]
