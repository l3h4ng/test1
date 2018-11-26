# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from agents.hosts.models import HostsModel

__author__ = 'TOANTV'
import time
from django.contrib.postgres.fields import ArrayField
from django.db import models
from targets.models import TasksModel, TargetsModel


class VulnerabilityModel(models.Model):
    name = models.TextField(max_length=225)
    synopsis = models.TextField(null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    family = models.CharField(max_length=45, blank=True, null=True)
    impact = models.TextField(null=True, blank=True)
    solution = models.TextField(null=True, blank=True)
    ref = ArrayField(models.CharField(max_length=225), default=[], blank=True)
    cve = ArrayField(models.CharField(max_length=100), default=[], blank=True)
    cvss = ArrayField(models.CharField(max_length=100), default=[], blank=True)
    severity = models.IntegerField(blank=True, null=True)
    created_at = models.IntegerField(blank=True, null=True)
    protocol = models.CharField(max_length=45, blank=True, null=True)
    alert = models.BooleanField(default=0)
    additional_info = models.CharField(max_length=500, blank=True, default="")
    tags = ArrayField(models.CharField(max_length=50), blank=True, default=[])
    plugin_id = models.IntegerField(default=0)

    class Meta:
        unique_together = (("name", "plugin_id"),)
        db_table = 'vulnerability'

    def __str__(self):
        return self.name