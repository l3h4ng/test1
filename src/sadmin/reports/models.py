# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from units.models import UnitsModel, OfficesModel

__author__ = 'TOANTV'
import time
from django.db import models
from targets.models import TasksModel, TargetsModel
from django.contrib.postgres.fields import JSONField, ArrayField


class ReportsTemplatesModel(models.Model):
    REPORT_TYPE = (
        (0, 'UNIT'),
        (1, 'OFFICE'),
        (2, 'TARGET'),
        (3, 'TASK'),
        (4, 'HOST'),
        (5, 'EVENT'),
        (6, 'SYSTEM')
    )

    type = models.IntegerField(choices=REPORT_TYPE, default=0)
    filter = JSONField(default={})
    name = JSONField(default={})
    file_type = JSONField(default={1: "docx"})

    class Meta:
        unique_together = (("type", "name"),)
        db_table = 'reports_templates'

    def __str__(self):
        return self.name

    def __unicode__(self):
        return '%s' % (self.name)


class ReportsModel(models.Model):
    STATUS = (
        (0, 'Init'),
        (1, 'Processing'),
        (2, 'Error'),
        (3, 'Finish')
    )

    SEVERITY = (
        (0, 'info'),
        (1, 'low'),
        (2, 'medium'),
        (3, 'high'),
        (4, 'critical')
    )

    EVENTS = {
        (0, 'vulnerability'),
        (1, 'penetration'),
        (2, 'abnormal'),
    }

    unit = models.IntegerField(blank=True, null=True, default=0)
    office = models.IntegerField(blank=True, null=True, default=0)
    target = models.IntegerField(blank=True, null=True, default=0)
    task = models.IntegerField(blank=True, null=True, default=0)
    host = models.IntegerField(blank=True, null=True, default=0)
    events = models.CharField(max_length=30, blank=True, null=True, default="")
    order = models.IntegerField(blank=True, null=True, default=0)
    severity = ArrayField(models.IntegerField(), blank=True, default=[])
    filter = ArrayField(models.CharField(max_length=150), null=True, blank=True)
    file_type = models.CharField(max_length=30, blank=True, default="docx")
    template = models.ForeignKey(ReportsTemplatesModel, related_name='reports', null=True)
    created_at = models.IntegerField(auto_created=True, default=time.time)
    status = models.IntegerField(choices=STATUS, default=0)
    download_link = models.CharField(max_length=225, blank=True, null=True)

    class Meta:
        db_table = 'reports'
