# -*- coding: utf-8 -*-
# Generated by Django 1.11.6 on 2018-03-15 07:41
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    initial = True

    dependencies = [
    ]

    operations = [
        migrations.CreateModel(
            name='SboxNodes',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.CharField(max_length=50, unique=True)),
                ('ip_addr', models.CharField(blank=True, max_length=45, null=True)),
                ('enabled', models.BooleanField(default=True)),
                ('description', models.CharField(blank=True, max_length=45, null=True)),
            ],
            options={
                'db_table': 'nodes',
            },
        ),
    ]