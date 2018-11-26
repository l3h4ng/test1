from __future__ import unicode_literals
# -*- coding: utf-8 -*-

__author__ = 'TOANTV'
from django.db import models
from agents.hosts.models import HostsModel

class WebsiteTechnologiesModel(models.Model):
    website = models.ForeignKey(HostsModel, related_name='technologies', null=True)
    technology = models.CharField(max_length=200, blank=False, default="")
    app = models.CharField(max_length=200, default="", blank=True)
    version = models.CharField(max_length=20, default="", blank=True)

    class Meta:
        unique_together = (("website", "technology"),)
        db_table = 'website_technology'
