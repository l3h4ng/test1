from __future__ import unicode_literals
# -*- coding: utf-8 -*-
__author__ = 'TOANTV'

from agents.hosts.models import HostsModel
from django.db import models


class WebsiteSubdomainsModel(models.Model):
    website = models.ForeignKey(HostsModel, related_name='subdomains', null=True)
    subdomain = models.CharField(max_length=200, blank=False)
    ip_addr = models.CharField(max_length=200, default="")
    is_monitor = models.BooleanField(default=False)

    class Meta:
        unique_together = (("subdomain", "website"),)
        db_table = 'website_subdomains'

    def __str__(self):
        return self.host.__str__() + " - " + self.subdomain

    # def save(self, *args, **kwargs):
    #     if self.ip_addr is None:
    #         self.ip_addr = self.host.ip_addr
    #     super(HostServicesModel, self).save(*args, **kwargs)