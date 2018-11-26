from __future__ import unicode_literals
# -*- coding: utf-8 -*-
__author__ = 'TOANTV'

from agents.hosts.models import HostsModel
from django.db import models


class HostServicesModel(models.Model):
    host = models.ForeignKey(HostsModel, related_name='services', null=True)
    ip_addr = models.CharField(max_length=45, blank=True, null=True)
    name = models.CharField(max_length=45, blank=True, null=True)
    port = models.IntegerField()
    protocol = models.CharField(max_length=45, default="tcp")
    state = models.CharField(max_length=45, default="open")
    version = models.CharField(max_length=150, blank=True, null=True)

    class Meta:
        unique_together = (("port", "host"),)
        db_table = 'host_services'

    def __str__(self):
        return self.host.__str__() + " - " + self.name

    # def save(self, *args, **kwargs):
    #     if self.ip_addr is None:
    #         self.ip_addr = self.host.ip_addr
    #     super(HostServicesModel, self).save(*args, **kwargs)