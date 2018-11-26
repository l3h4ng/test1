from __future__ import unicode_literals
# -*- coding: utf-8 -*-
__author__ = 'TOANTV'

from agents.hosts.models import HostsModel
from django.db import models


class CrawlDataModel(models.Model):
    LOCAL_TYPE = (
        (0, 'file'),
        (1, 'folder')
    )

    SECURITY_LEVEL = (
        (0, 'safe'),
        (1, 'suspect'),
        (2, 'malware')
    )

    website = models.ForeignKey(HostsModel, related_name='crawls', null=True)
    path = models.CharField(max_length=250, blank=True, null=True)
    name = models.CharField(max_length=150, blank=True, null=True)
    parent_id = models.IntegerField(blank=True, null=True)
    loc_type = models.IntegerField(choices=LOCAL_TYPE, default=0)
    security_level = models.IntegerField(choices=SECURITY_LEVEL, default=0)

    class Meta:
        unique_together = (("website", "path"),)
        db_table = 'website_crawl_data'

    def __str__(self):
        return self.path.__str__()
