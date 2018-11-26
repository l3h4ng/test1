# -*- coding: utf-8 -*-
from __future__ import unicode_literals

__author__ = 'TOANTV'
import time
from django.db.models import SET_NULL
from nodes.models import SboxNodes
from units.models import OfficesModel
from django.db import models
from one_users.models import OneUsers
from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.fields import JSONField


class TargetsModel(models.Model):
    STATUS = (
        (-1, 'Lập lịch'),
        (0, 'Khởi tạo'),
        (1, 'Đang chờ quét'),
        (2, 'Đang quét'),
        (3, 'Tạm dừng'),
        (4, 'Quét lỗi'),
        (5, 'Hoàn thành')
    )

    name = models.CharField(max_length=225)
    office = models.ForeignKey(OfficesModel, related_name='targets', null=True)
    owner = models.ForeignKey(OneUsers, related_name='targets', null=True)
    address = models.CharField(max_length=225)
    description = models.CharField(max_length=225, blank=True, null=True)
    status = models.IntegerField(choices=STATUS, default=0)
    created_at = models.IntegerField(editable=False, auto_created=True, default=time.time)
    tasks_count = models.IntegerField(blank=True, null=True, default=0)
    last_task_id = models.IntegerField(blank=True, null=True)
    severity = models.IntegerField(default=1)
    report_file = models.CharField(max_length=225, blank=True, null=True)
    # launch_now = models.BooleanField(default=False)
    server_node = models.ForeignKey(SboxNodes, related_name='targets', null=True, default=1, on_delete=SET_NULL)

    class Meta:
        db_table = 'targets'
        unique_together = (("name", "office"),)

    def __str__(self):
        return self.name

        # def create_task(self):
        #     task = TasksModel(target=self, name="%s - %s" % (self.name, str(int(time.time()))),
        #                       target_addr=self.address, status=0)
        #     task.save()
        #
        # def stop_task(self):
        #     task = TasksModel.objects.get(pk=self.last_task_id)
        #     if task.status < 3:
        #         task.status = 3
        #         task.save()
        #
        # def queue_task(self):
        #     task = TasksModel.objects.get(pk=self.last_task_id)
        #     if task.status < 1:
        #         task.status = 1
        #         task.save()
        #
        # def create_configuration(self):
        #     configuration = TargetConfigurationsModel(target=self)
        #     configuration.save_create()
        #
        # def save_basic(self, *args, **kwargs):
        #     super(TargetsModel, self).save(*args, **kwargs)
        #
        # def save(self, *args, **kwargs):
        #     check_update = 0
        #     if self.pk is not None:
        #         time.sleep(0.2)
        #         target_last = TargetsModel.objects.get(pk=self.pk)
        #         if self.status is not None and target_last.status != self.status:
        #             if target_last.status <= 2 and self.status == 0:
        #                 self.status = target_last.status
        #                 raise ValueError("Stop job firse.")
        #             elif self.status == 3 and target_last.status > 3:
        #                 self.status = target_last.status
        #         else:
        #             target_last = None
        #         check_update = 1
        #     else:
        #         target_last = None
        #         self.status = 0
        #     super(TargetsModel, self).save(*args, **kwargs)
        #     if self.status == 0 and check_update == 0:
        #         self.create_task()
        #         self.create_configuration()
        #     elif target_last is not None and check_update == 1:
        #         if self.status == 0:
        #             self.create_task()
        #         elif self.status == 3:
        #             self.stop_task()
        #         elif self.status == 1:
        #             self.queue_task()
        #
        # def delete(self, *args, **kwargs):
        #     if self.status >= 3:
        #         super(TargetsModel, self).delete(*args, **kwargs)
        #     else:
        #         raise Warning("Stop job firse.")


class TargetConfigurationsModel(models.Model):
    SPPED = (
        (0, 'Cực chậm'),
        (1, 'Chậm'),
        (2, 'Trung bình'),
        (3, 'Nhanh')
    )
    target = models.OneToOneField(TargetsModel, on_delete=models.CASCADE, primary_key=True,
                                  related_name='configuration')
    email_notify = ArrayField(models.EmailField(), default=[], blank=True)
    speed = models.IntegerField(choices=SPPED, default=1)
    custom_cookies = JSONField(default={})
    custom_headers = ArrayField(models.CharField(max_length=250), default=[])

    # parallel_mode = models.BooleanField(default=True)

    class Meta:
        db_table = 'target_configurations'

    # def create_scheduler(self):
    #     scheduler = SchedulerModel(configurations=self, status=False)
    #     scheduler.save_basic()
    #
    # def save_create(self, *args, **kwargs):
    #     super(TargetConfigurationsModel, self).save(*args, **kwargs)
    #     self.create_scheduler()

    def __str__(self):
        return str(self.pk)


class SchedulerModel(models.Model):
    configurations = models.OneToOneField(TargetConfigurationsModel, primary_key=True, on_delete=models.CASCADE,
                                          related_name='scheduler')
    status = models.BooleanField(default=False)
    time_interval = models.IntegerField(default=0)
    next_time = models.IntegerField(blank=True, null=True)
    last_time = models.IntegerField(blank=True, null=True)
    started_at = models.CharField(max_length=10, default="00:00", blank=True)

    class Meta:
        db_table = "target_scheduler"

    def __str__(self):
        return str(self.pk)


class TasksModel(models.Model):
    STATUS = (
        (0, 'Khởi tạo'),
        (1, 'Đang chờ quét'),
        (2, 'Đang quét'),
        (3, 'Tạm dừng'),
        (4, 'Quét lỗi'),
        (5, 'Hoàn thành')
    )
    name = models.CharField(max_length=225)
    target = models.ForeignKey(TargetsModel, related_name='tasks', on_delete=models.CASCADE, null=True)
    start_time = models.IntegerField(auto_created=True, default=time.time)
    finish_time = models.IntegerField(blank=True, null=True)
    status = models.IntegerField(choices=STATUS, default=0)
    percent = models.IntegerField(default=0)
    report_file = models.CharField(max_length=45, blank=True, null=True)
    severity = models.IntegerField(blank=True, default=1)
    target_addr = models.CharField(max_length=225, blank=True, null=True)
    is_lasted = models.BooleanField(default=True)

    class Meta:
        db_table = 'tasks'

    def __str__(self):
        return self.name


class TaskStatisticsModel(models.Model):
    task = models.OneToOneField(TasksModel, primary_key=True, on_delete=models.CASCADE, related_name='statistics')
    time_scan = models.IntegerField(auto_created=True, default=time.time)
    hosts_count = models.IntegerField(default=0)
    services_count = models.IntegerField(default=0)
    subdomains_count = models.IntegerField(default=0)
    paths_count = models.IntegerField(default=0)
    server_configs_count = models.IntegerField(default=0)
    vulns_count = models.IntegerField(default=0)
    info_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    critical_count = models.IntegerField(default=0)
    db_attack_count = models.IntegerField(default=0)
    malware_path_count = models.IntegerField(default=0)
    abnormal_alert_count = models.IntegerField(default=0)
    security_alert_count = models.IntegerField(default=0)
    phishing_domain_count = models.IntegerField(default=0)
    domain_blacklist_alert_count = models.IntegerField(default=0)
    website_content_alert_count = models.IntegerField(default=0)
    website_down_status_count = models.IntegerField(default=0)
    severity = models.IntegerField(default=1)

    class Meta:
        db_table = 'task_statistics'

    def __str__(self):
        return str(self.task)


class TargetStatisticsModel(models.Model):
    target = models.OneToOneField(TargetsModel, primary_key=True, on_delete=models.CASCADE, related_name='statistics')
    task = models.ForeignKey(TasksModel, on_delete=models.SET_DEFAULT, default=0)

    class Meta:
        db_table = 'target_statistics'

    def __str__(self):
        return str(self.target)
