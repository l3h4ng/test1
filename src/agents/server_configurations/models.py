from __future__ import unicode_literals
# -*- coding: utf-8 -*-
__author__ = 'TOANTV'

from agents.hosts.models import HostsModel
from django.db import models


class ServerConfigurationsModel(models.Model):
    website = models.ForeignKey(HostsModel, related_name='config_vulns', null=True)
    name = models.TextField(blank=True, null=True)
    url = models.CharField(max_length=500, blank=False, default="" )
    protocol = models.CharField(max_length=500, blank=True, default="")
    description = models.TextField(blank=True, null=True)
    ref = models.TextField(blank=True, null=True)

    class Meta:
        db_table = 'server_configurations_vulnerability'
        unique_together = (("website", "description"),)

