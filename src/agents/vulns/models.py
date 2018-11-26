# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from agents.hosts.models import HostsModel
from sadmin.plugins.models import PluginsModel
from sadmin.vulnerabilities.models import VulnerabilityModel

__author__ = 'TOANTV'
import time
from django.contrib.postgres.fields import ArrayField
from django.db import models
from targets.models import TasksModel, TargetsModel

class HostVulnerabilityModel(models.Model):
    name = models.TextField(blank=True, null=True)
    host = models.ForeignKey(HostsModel, related_name='vulns', null=True)
    vulnerability = models.ForeignKey(VulnerabilityModel, related_name='hosts', null=True)
    detection_time = models.IntegerField(auto_created=True, default=time.time, blank=True)
    task = models.ForeignKey(TasksModel, related_name='vulns', null=True)
    target = models.ForeignKey(TargetsModel, related_name='vulns', null=True)
    is_fixed = models.BooleanField(default=False)
    is_ignored = models.BooleanField(default=False)
    plugin = models.ForeignKey(PluginsModel, related_name='vulns', null=True)
    attack_details = models.TextField(blank=True, null=True, default="")
    port = models.CharField(max_length=45, blank=True, null=True)
    request = models.TextField(blank=True, null=True, default="")
    output = models.TextField(blank=True, null=True, default="")
    affects = models.TextField(blank=True, null=True)
    scanner_scan_id = models.CharField(max_length=100, default="", null=False, blank=False)
    scanner_vuln_id = models.CharField(max_length=100, default="", null=False, blank=False)

    class Meta:
        db_table = 'host_vulnerability'
        unique_together = (("host", "scanner_scan_id", "scanner_vuln_id"),)

    def __str__(self):
        return self.host.__str__() + " - " + self.name

    # def save(self, *args, **kwargs):
    #     if self.name is None:
    #         self.name = self.vulnerability.name
    #     super(HostVulnerabilityModel, self).save(*args, **kwargs)