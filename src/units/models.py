from __future__ import unicode_literals
# -*- coding: utf-8 -*-
__author__ = 'TOANTV'
import time
from django.db import models
from one_users.models import OneUsers

# Create your models here.
class UnitsModel(models.Model):
    name = models.CharField(unique=True, max_length=225)
    address = models.CharField(max_length=225, blank=True, null=True)
    description = models.CharField(max_length=45, blank=True, null=True)
    owner = models.ForeignKey(OneUsers, related_name='units', null=True)
    severity = models.IntegerField(default=1)

    class Meta:
        db_table = 'units'

    def save(self, *args, **kwargs):
        # print
        if self.pk is not None:
            print type(self.pk)
            print type(self.name)
        else:
            print "nollllll"
        super(UnitsModel, self).save(*args, **kwargs)
        if self.pk is not None:
            print self.pk
        else:
            print "nollllll"


class OfficesModel(models.Model):
    name = models.CharField(max_length=225)
    address = models.CharField(max_length=45, blank=True, null=True)
    description = models.CharField(max_length=225, blank=True, null=True)
    unit = models.ForeignKey(UnitsModel, related_name='offices', on_delete=models.CASCADE, null=True)
    owner = models.ForeignKey(OneUsers, related_name='offices', null=True)
    severity = models.IntegerField(default=1)

    class Meta:
        unique_together = (("unit", "name"),)
        db_table = 'offices'


class UnitsStatistics(models.Model):
    unit = models.OneToOneField(UnitsModel, primary_key=True, on_delete=models.CASCADE, related_name='statistics')
    last_update = models.IntegerField(editable=False, default=time.time)
    targets_count = models.IntegerField(default=0)
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

    class Meta:
        db_table = 'units_statistic'


class OfficesStatistics(models.Model):
    office = models.OneToOneField(OfficesModel, primary_key=True, on_delete=models.CASCADE, related_name='statistics')
    last_update = models.IntegerField(editable=False, default=time.time)
    targets_count = models.IntegerField(default=0)
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

    class Meta:
        db_table = 'offices_statistic'
