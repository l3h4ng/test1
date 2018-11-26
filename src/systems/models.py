from __future__ import unicode_literals

import time
from agents.monitor.models import WebsiteSecurityAlertModel

from django.contrib.postgres.fields import ArrayField
from django.db import models

# Create your models here.
from sadmin.plugins.models import PluginsModel
from targets.models import TargetsModel, TasksModel
from django.contrib.postgres.fields import JSONField

class SystemLog(models.Model):
    STATUS = (
        (0, 'Info'),
        (1, 'Warning'),
        (2, 'Error')
    )

    target = models.ForeignKey(TargetsModel, related_name='systems_log', null=True)
    task = models.ForeignKey(TasksModel, related_name='systems_log', null=True)
    content = JSONField()
    type = models.IntegerField(choices=STATUS, default=0)
    plugin = models.ForeignKey(PluginsModel, related_name='systems_log', null=True)
    is_watched = models.BooleanField(default=False)

    class Meta:
        db_table = 'systems_log'


class SystemsAlert(models.Model):
    contents = models.ForeignKey(WebsiteSecurityAlertModel, related_name="alert", null=True)
    created_at = models.IntegerField(editable=False, default=time.time)
    is_watched = models.BooleanField(default=False)

    class Meta:
        db_table = 'systems_alert'


class SystemsEmailNotify(models.Model):
    smtp_server = models.CharField(max_length=45)
    port = models.CharField(max_length=45, blank=True, null=True)
    from_address = models.CharField(max_length=45, blank=True, null=True)
    security = models.CharField(max_length=45, blank=True, null=True)
    username = models.CharField(max_length=45, blank=True, null=True)
    password = models.CharField(max_length=45, blank=True, null=True)
    enable = models.BooleanField(default=False)
    test_connection = models.BooleanField(default=False)

    class Meta:
        db_table = 'systems_email_notify'


class SystemsLicense(models.Model):
    license_key = models.CharField(primary_key=True, max_length=225)
    email = models.EmailField(blank=True, null=True)
    product_code = models.CharField(max_length=45, blank=True, null=True)
    max_scans = models.IntegerField(default=2)
    company = models.CharField(max_length=225, blank=True, null=True)
    country = models.CharField(max_length=45, blank=True, null=True)
    maintenance_expires = models.CharField(max_length=45, blank=True, null=True)
    build_number = models.CharField(max_length=225)
    plugins = ArrayField(models.IntegerField(), blank=True, default=[])

    class Meta:
        db_table = 'systems_license'


class SystemsNetworkConfig(models.Model):
    STATUS = (
        (0, 'USER INTERFACE'),
        (1, 'MANAGERMENT INTERFACE')
    )
    static = models.BooleanField()
    type = models.IntegerField(choices=STATUS, default=0)
    interface = models.CharField(max_length=225, unique=True)
    ip_addr = models.CharField(max_length=45, blank=True, null=True)
    netmask = models.CharField(max_length=45, blank=True, null=True)
    gateway = models.CharField(max_length=45, blank=True, null=True)
    mac_addr = models.CharField(max_length=20, blank=True, null=True)
    test_connection = models.BooleanField(default=False)
    dns_server = models.CharField(max_length=45, blank=True, null=True, default="8.8.8.8")

    class Meta:
        db_table = 'systems_network_config'


class SystemsProxy(models.Model):
    enable = models.BooleanField(default=False)
    protocol = models.CharField(max_length=45, blank=True, null=True)
    address = models.CharField(max_length=45, blank=True, null=True)
    port = models.IntegerField(blank=True, null=True)
    username = models.CharField(max_length=45, blank=True, null=True)
    password = models.CharField(max_length=45, blank=True, null=True)
    test_connection = models.BooleanField(default=False)

    class Meta:
        db_table = 'systems_proxy'


class SystemStatistics(models.Model):
    date_statistic = models.DateField(auto_now_add=True, blank=True)
    updated_time = models.IntegerField(auto_created=time.time)
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
    severity = models.IntegerField(default=1)
    tasks = ArrayField(models.IntegerField(), blank=True, default=[])

    class Meta:
        db_table = 'systems_statistics'

class SystemVPNModel(models.Model):
    enable = models.BooleanField(default=False)
    time_interval = models.IntegerField(default=120, blank=True)

    class Meta:
        db_table = 'systems_vpn'
