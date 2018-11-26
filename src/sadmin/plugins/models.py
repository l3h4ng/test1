# -*- coding: utf-8 -*-
from __future__ import unicode_literals

import time

from django.db import models


# Create your models here.

# class PluginsGroupModel(models.Model):
#     name = models.CharField(max_length=45, blank=True, unique=True, null=True)
#     description = models.CharField(max_length=45, blank=True, null=True)
#     enabled = models.BooleanField(default=True)
#
#     class Meta:
#         db_table = 'plugins_group'
#
#     def __str__(self):
#         return self.name


class PluginsModel(models.Model):
    name = models.CharField(max_length=45)
    family = models.CharField(max_length=45, blank=True, null=True)
    description = models.CharField(max_length=45, blank=True, null=True)
    enabled = models.BooleanField(default=True)
    required = models.BooleanField(default=True)
    fname = models.CharField(max_length=45, blank=True, null=True)
    created_at = models.IntegerField(auto_created=True, default=time.time)

    class Meta:
        db_table = 'plugins'

    def __str__(self):
        return self.name


class PluginsLicenseModel(models.Model):
    plugin = models.OneToOneField(PluginsModel, related_name='plugins_license', primary_key=True)
    family = models.CharField(max_length=45, blank=True, null=True)
    name = models.CharField(max_length=45, unique=True)
    license = models.CharField(max_length=45)
    expires = models.IntegerField()
    activated = models.BooleanField(default=True)

    class Meta:
        db_table = 'plugins_license'

    def __str__(self):
        return self.name
