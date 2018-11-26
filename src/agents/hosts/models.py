from __future__ import unicode_literals
# -*- coding: utf-8 -*-
__author__ = 'TOANTV'
import time
from django.contrib.postgres.fields import ArrayField
from django.db import models
from targets.models import TasksModel

class HostsModel(models.Model):
    STATUS = (
        (0, 'general purpose'),
        (1, 'router'),
        (2, 'firewall'),
        (3, 'switch'),
        (4, 'printer'),
        (5, 'webcam'),
        (6, 'phone')
    )

    task = models.ForeignKey(TasksModel, related_name='hosts', null=True)
    ip_addr = models.CharField(max_length=250)
    severity = models.IntegerField(default=1)
    device_type = models.IntegerField(choices=STATUS, default=0)
    status = models.IntegerField(default=0)
    edges = ArrayField(models.IntegerField(), blank=True, default=[])
    edges_extend = ArrayField(models.CharField(max_length=20), blank=True, default=[])

    class Meta:
        unique_together = (("task", "ip_addr"),)
        db_table = 'hosts'

    def __str__(self):
        return self.task.name + " - " + self.ip_addr

class HostDetailsModel(models.Model):
    host = models.OneToOneField(HostsModel, primary_key=True, related_name='details')
    hostname = models.CharField(max_length=250, blank=True, null=True)
    os = ArrayField(models.CharField(max_length=100), blank=True, default=[])
    last_boot = models.CharField(max_length=45, blank=True, null=True)
    mac_addr = models.CharField(max_length=45, blank=True, null=True)
    ipv4 = models.CharField(max_length=45, blank=True, null=True)
    ipv6 = models.CharField(max_length=45, blank=True, null=True)
    vendor = models.CharField(max_length=45, blank=True, null=True)
    status = models.CharField(max_length=45, blank=True, null=True)
    state = models.CharField(max_length=45, blank=True, null=True)

    class Meta:
        db_table = 'host_details'

    def __str__(self):
        return self.host.__str__()

    def save(self, *args, **kwargs):
        if self.state is None:
            self.state = "up"
        super(HostDetailsModel, self).save(*args, **kwargs)


class HostStatisticsModel(models.Model):
    host = models.OneToOneField(HostsModel, primary_key=True, related_name='statistics')
    ip_addr = models.CharField(max_length=250, blank=True, null=True)
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
    is_site_down = models.BooleanField(default=False)
    is_blacklist_detected = models.BooleanField(default=False)
    is_website_content_alert = models.BooleanField(default=False)

    class Meta:
        db_table = 'host_statistics'

    def __str__(self):
        return self.host.__str__()