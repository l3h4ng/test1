from __future__ import unicode_literals
# -*- coding: utf-8 -*-
__author__ = 'TOANTV'

from agents.hosts.models import HostsModel
from django.db import models
from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.fields import JSONField
# import jsonfield

class WebsiteDatabasesModel(models.Model):
    website = models.ForeignKey(HostsModel, related_name='database', null=True)
    db_type = models.CharField(max_length=45, blank=True, null=True)
    version = models.CharField(max_length=45, blank=True, null=True)
    user = models.CharField(max_length=45, blank=True, null=True)
    password = models.CharField(max_length=45, blank=True, null=True)
    is_db_administrator = models.BooleanField(default=False)
    databases = JSONField(default={})

    class Meta:
        db_table = 'website_database'

    def __str__(self):
        return self.host.__str__() + " - " + self.website
