# -*- coding: utf-8 -*-
# Generated by Django 1.11.6 on 2017-11-07 01:11
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('plugins', '0005_auto_20171107_0616'),
    ]

    operations = [
        migrations.AlterField(
            model_name='pluginsmodel',
            name='created_at',
            field=models.IntegerField(auto_created=1510017093),
        ),
    ]
