# -*- coding: utf-8 -*-
# Generated by Django 1.11.6 on 2018-03-22 02:37
from __future__ import unicode_literals

import django.contrib.postgres.fields
import django.contrib.postgres.fields.jsonb
from django.db import migrations, models
import django.db.models.deletion
import time


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('targets', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='PluginsModel',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.IntegerField(auto_created=True, default=time.time)),
                ('name', models.CharField(max_length=45)),
                ('family', models.CharField(blank=True, max_length=45, null=True)),
                ('description', models.CharField(blank=True, max_length=45, null=True)),
                ('enabled', models.BooleanField(default=True)),
                ('required', models.BooleanField(default=True)),
                ('fname', models.CharField(blank=True, max_length=45, null=True)),
            ],
            options={
                'db_table': 'plugins',
            },
        ),
        migrations.CreateModel(
            name='ReportsModel',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.IntegerField(auto_created=True, default=time.time)),
                ('status', models.IntegerField(choices=[(0, 'Init'), (1, 'Processing'), (2, 'Error'), (3, 'Finish')], default=0)),
                ('download_link', models.CharField(blank=True, max_length=225, null=True)),
                ('task', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='reports', to='targets.TasksModel')),
            ],
            options={
                'db_table': 'reports',
            },
        ),
        migrations.CreateModel(
            name='ReportsTemplatesModel',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', django.contrib.postgres.fields.jsonb.JSONField(default={}, unique=True)),
                ('template_filename', models.CharField(blank=True, max_length=225, null=True)),
            ],
            options={
                'db_table': 'reports_templates',
            },
        ),
        migrations.CreateModel(
            name='VulnerabilityModel',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('name', models.TextField(max_length=225)),
                ('synopsis', models.TextField(blank=True, null=True)),
                ('description', models.TextField(blank=True, null=True)),
                ('family', models.CharField(blank=True, max_length=45, null=True)),
                ('impact', models.TextField(blank=True, null=True)),
                ('solution', models.TextField(blank=True, null=True)),
                ('ref', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=225), blank=True, default=[], size=None)),
                ('cve', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=100), blank=True, default=[], size=None)),
                ('cvss', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=100), blank=True, default=[], size=None)),
                ('severity', models.IntegerField(blank=True, null=True)),
                ('created_at', models.IntegerField(blank=True, null=True)),
                ('protocol', models.CharField(blank=True, max_length=45, null=True)),
                ('alert', models.BooleanField(default=0)),
                ('additional_info', models.CharField(blank=True, default='', max_length=500)),
                ('tags', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=50), blank=True, default=[], size=None)),
                ('plugin_id', models.IntegerField(default=0)),
            ],
            options={
                'db_table': 'vulnerability',
            },
        ),
        migrations.CreateModel(
            name='PluginsLicenseModel',
            fields=[
                ('plugin', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='plugins_license', serialize=False, to='sadmin.PluginsModel')),
                ('family', models.CharField(blank=True, max_length=45, null=True)),
                ('name', models.CharField(max_length=45, unique=True)),
                ('license', models.CharField(max_length=45)),
                ('expires', models.IntegerField()),
                ('activated', models.BooleanField(default=True)),
            ],
            options={
                'db_table': 'plugins_license',
            },
        ),
        migrations.AlterUniqueTogether(
            name='vulnerabilitymodel',
            unique_together=set([('name', 'plugin_id')]),
        ),
        migrations.AddField(
            model_name='reportsmodel',
            name='template',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='reports', to='sadmin.ReportsTemplatesModel'),
        ),
        migrations.AlterUniqueTogether(
            name='reportsmodel',
            unique_together=set([('task', 'template')]),
        ),
    ]