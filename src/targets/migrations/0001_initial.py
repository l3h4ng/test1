# -*- coding: utf-8 -*-
# Generated by Django 1.11.6 on 2018-03-22 02:37
from __future__ import unicode_literals

from django.conf import settings
import django.contrib.postgres.fields
import django.contrib.postgres.fields.jsonb
from django.db import migrations, models
import django.db.models.deletion
import time


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        ('nodes', '0001_initial'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('units', '0001_initial'),
    ]

    operations = [
        migrations.CreateModel(
            name='TargetsModel',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('created_at', models.IntegerField(auto_created=True, default=time.time, editable=False)),
                ('name', models.CharField(max_length=225, unique=True)),
                ('address', models.CharField(max_length=225)),
                ('description', models.CharField(blank=True, max_length=225, null=True)),
                ('status', models.IntegerField(choices=[(-1, 'L\u1eadp l\u1ecbch'), (0, 'Kh\u1edfi t\u1ea1o'), (1, '\u0110ang ch\u1edd qu\xe9t'), (2, '\u0110ang qu\xe9t'), (3, 'T\u1ea1m d\u1eebng'), (4, 'Qu\xe9t l\u1ed7i'), (5, 'Ho\xe0n th\xe0nh')], default=0)),
                ('tasks_count', models.IntegerField(blank=True, default=0, null=True)),
                ('last_task_id', models.IntegerField(blank=True, null=True)),
                ('severity', models.IntegerField(default=1)),
                ('report_file', models.CharField(blank=True, max_length=225, null=True)),
            ],
            options={
                'db_table': 'targets',
            },
        ),
        migrations.CreateModel(
            name='TasksModel',
            fields=[
                ('id', models.AutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('start_time', models.IntegerField(auto_created=True, default=time.time)),
                ('name', models.CharField(max_length=225)),
                ('finish_time', models.IntegerField(blank=True, null=True)),
                ('status', models.IntegerField(choices=[(0, 'Kh\u1edfi t\u1ea1o'), (1, '\u0110ang ch\u1edd qu\xe9t'), (2, '\u0110ang qu\xe9t'), (3, 'T\u1ea1m d\u1eebng'), (4, 'Qu\xe9t l\u1ed7i'), (5, 'Ho\xe0n th\xe0nh')], default=0)),
                ('report_file', models.CharField(blank=True, max_length=45, null=True)),
                ('severity', models.IntegerField(blank=True, default=1)),
                ('target_addr', models.CharField(blank=True, max_length=225, null=True)),
                ('is_lasted', models.BooleanField(default=True)),
            ],
            options={
                'db_table': 'tasks',
            },
        ),
        migrations.CreateModel(
            name='TargetConfigurationsModel',
            fields=[
                ('target', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='configuration', serialize=False, to='targets.TargetsModel')),
                ('email_notify', django.contrib.postgres.fields.ArrayField(base_field=models.EmailField(max_length=254), blank=True, default=[], size=None)),
                ('speed', models.IntegerField(choices=[(0, 'C\u1ef1c ch\u1eadm'), (1, 'Ch\u1eadm'), (2, 'Trung b\xecnh'), (3, 'Nhanh')], default=1)),
                ('custom_cookies', django.contrib.postgres.fields.jsonb.JSONField(default={})),
                ('custom_headers', django.contrib.postgres.fields.ArrayField(base_field=models.CharField(max_length=250), default=[], size=None)),
            ],
            options={
                'db_table': 'target_configurations',
            },
        ),
        migrations.CreateModel(
            name='TargetStatisticsModel',
            fields=[
                ('target', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='statistics', serialize=False, to='targets.TargetsModel')),
            ],
            options={
                'db_table': 'target_statistics',
            },
        ),
        migrations.CreateModel(
            name='TaskStatisticsModel',
            fields=[
                ('time_scan', models.IntegerField(auto_created=True, default=time.time)),
                ('task', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='statistics', serialize=False, to='targets.TasksModel')),
                ('hosts_count', models.IntegerField(default=0)),
                ('services_count', models.IntegerField(default=0)),
                ('subdomains_count', models.IntegerField(default=0)),
                ('paths_count', models.IntegerField(default=0)),
                ('server_configs_count', models.IntegerField(default=0)),
                ('db_attack_count', models.IntegerField(default=0)),
                ('vulns_count', models.IntegerField(default=0)),
                ('high_count', models.IntegerField(default=0)),
                ('critical_count', models.IntegerField(default=0)),
                ('medium_count', models.IntegerField(default=0)),
                ('low_count', models.IntegerField(default=0)),
                ('info_count', models.IntegerField(default=0)),
                ('severity', models.IntegerField(default=1)),
            ],
            options={
                'db_table': 'task_statistics',
            },
        ),
        migrations.AddField(
            model_name='tasksmodel',
            name='target',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='tasks', to='targets.TargetsModel'),
        ),
        migrations.AddField(
            model_name='targetsmodel',
            name='office',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='targets', to='units.OfficesModel'),
        ),
        migrations.AddField(
            model_name='targetsmodel',
            name='owner',
            field=models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='targets', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='targetsmodel',
            name='server_node',
            field=models.ForeignKey(default=1, null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='targets', to='nodes.SboxNodes'),
        ),
        migrations.CreateModel(
            name='SchedulerModel',
            fields=[
                ('configurations', models.OneToOneField(on_delete=django.db.models.deletion.CASCADE, primary_key=True, related_name='scheduler', serialize=False, to='targets.TargetConfigurationsModel')),
                ('status', models.BooleanField(default=False)),
                ('time_interval', models.IntegerField(default=0)),
                ('next_time', models.IntegerField(blank=True, null=True)),
                ('last_time', models.IntegerField(blank=True, null=True)),
                ('started_at', models.CharField(blank=True, default='00:00', max_length=10)),
            ],
            options={
                'db_table': 'target_scheduler',
            },
        ),
        migrations.AddField(
            model_name='targetstatisticsmodel',
            name='task',
            field=models.ForeignKey(default=0, on_delete=django.db.models.deletion.SET_DEFAULT, to='targets.TasksModel'),
        ),
        migrations.AlterUniqueTogether(
            name='targetsmodel',
            unique_together=set([('name', 'office')]),
        ),
    ]
