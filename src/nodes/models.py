from __future__ import unicode_literals
# -*- coding: utf-8 -*-
__author__ = 'TOANTV'
from django.db import models

class SboxNodes(models.Model):
    name = models.CharField(max_length=50, unique=True)
    ip_addr = models.CharField(max_length=45, blank=True, null=True)
    enabled = models.BooleanField(default=True)
    description = models.CharField(max_length=45, blank=True, null=True)

    class Meta:
        db_table = 'nodes'
