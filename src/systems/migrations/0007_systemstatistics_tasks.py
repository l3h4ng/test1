# -*- coding: utf-8 -*-
# Generated by Django 1.11.6 on 2018-06-19 08:55
from __future__ import unicode_literals

import django.contrib.postgres.fields
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('systems', '0006_systemstatistics_updated_time'),
    ]

    operations = [
        migrations.AddField(
            model_name='systemstatistics',
            name='tasks',
            field=django.contrib.postgres.fields.ArrayField(base_field=models.IntegerField(), blank=True, default=[], size=None),
        ),
    ]
