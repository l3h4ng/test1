# -*- coding: utf-8 -*-
# Generated by Django 1.11.6 on 2017-11-09 03:45
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('plugins', '0012_auto_20171109_0459'),
    ]

    operations = [
        migrations.AlterField(
            model_name='pluginsmodel',
            name='created_at',
            field=models.IntegerField(auto_created=True, default=1510199113),
        ),
    ]
