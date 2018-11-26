# -*- coding: utf-8 -*-
__author__ = 'TOANTV'
import time

from django.db import models
from targets.models import TasksModel
from sadmin.plugins.models import PluginsModel
from django.contrib.postgres.fields import ArrayField


class ScansModel(models.Model):
    STATUS = (
        (0, 'Khởi tạo'),
        (1, 'Đang chờ quét'),
        (2, 'Đang quét'),
        (3, 'Tạm dừng'),
        (4, 'Quét lỗi'),
        (5, 'Hoàn thành'),
        (6, 'Hoàn thành cơ bản')
    )
    task = models.ForeignKey(TasksModel, related_name='scans', on_delete=models.CASCADE, null=True)
    plugin = models.ForeignKey(PluginsModel, related_name='scans', null=True)
    percent = models.IntegerField(default=0)
    status = models.IntegerField(choices=STATUS, default=0)
    scripted_scan = ArrayField(models.CharField(max_length=60), blank=True, default=[])
    start_time = models.IntegerField(editable=False, auto_created=True, default=time.time)
    finish_time = models.IntegerField(null=True)

    class Meta:
        unique_together = (("task", "plugin"),)
        db_table = 'scans'
