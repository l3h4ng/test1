from __future__ import unicode_literals
# -*- coding: utf-8 -*-
import time
from targets.models import TargetsModel

__author__ = 'TOANTV'
from django.db import models
from agents.hosts.models import HostsModel
from django.contrib.postgres.fields import JSONField, ArrayField

class GoogleHackingKeywordModels(models.Model):
    created = models.IntegerField(auto_created=True, default=time.time)
    category = models.CharField(max_length=250, blank=False, default="")
    keyword = models.CharField(max_length=500, blank=True, default="")
    google_search = models.CharField(max_length=500, blank=True, default="")
    summary = models.CharField(max_length=500, blank=True, default="")

    class Meta:
        unique_together = (("category", "keyword"),)
        db_table = 'google_hacking_db'


class WebsiteGoogleHackingDetectModel(models.Model):
    website = models.ForeignKey(HostsModel, related_name='ghdb', null=True)
    keyword = models.ForeignKey(GoogleHackingKeywordModels, related_name='websites', null=True)
    link = models.CharField(max_length=500, blank=True, default="")
    total_results = models.IntegerField(default=0, blank=True)
    results = ArrayField(models.CharField(max_length=500, default=""), blank=True, default=[])

    class Meta:
        unique_together = (("website", "keyword"),)
        db_table = 'website_ghdb_detect'


class WebsitePhishingDomainDetectModel(models.Model):
    SECURITY_LEVEL = (
        (0, 'safe'),
        (1, 'suspect'),
        (2, 'malware')
    )
    website = models.ForeignKey(HostsModel, related_name='phishing', null=True)
    domain = models.CharField(max_length=250, blank=False, default="")
    is_exits = models.BooleanField(default=False)
    security_level = models.IntegerField(choices=SECURITY_LEVEL, default=0)
    ip_addr = models.CharField(max_length=500, blank=True, default="")

    class Meta:
        unique_together = (("website", "domain"),)
        db_table = 'website_phishing_alert'


class WebsiteBlacklistCheckingModel(models.Model):
    BLACKLIST_SITE_CHECK = (
        (0, 'GOOGLE SAFE BROWSING'),
        (1, 'NOTRTON SAFE WEB'),
        (2, 'PHISHTANK'),
        (3, 'OPERA BROWSER'),
        (4, 'SITEADVISOR'),
        (5, 'Sucuri Malware Labs'),
        (6, 'SpamHaus DBL'),
        (7, 'Yandex'),
        (8, 'ESET')
    )

    BLACKLIST_RESULT = (
        (0, 'Clean'),
        (1, 'Warning')
    )

    website = models.ForeignKey(HostsModel, related_name='blacklist', null=True)
    type = models.IntegerField(choices=BLACKLIST_SITE_CHECK, default=0)
    result = models.IntegerField(choices=BLACKLIST_RESULT, default=0)

    class Meta:
        unique_together = (("website", "type"),)
        db_table = 'website_blacklist_check'


class WebsiteMonitorStatusModel(models.Model):
    website = models.ForeignKey(HostsModel, related_name='mstatus', null=True)
    monitor_time = models.IntegerField(auto_created=True, default=time.time, null=True, blank=True)
    ping_status = models.BooleanField(default=False)
    ping_response = models.IntegerField(default=0, blank=True)
    web_status = models.IntegerField(blank=False, default=200)
    web_load_response = models.IntegerField(default=0, blank=True)

    class Meta:
        db_table = 'website_monitor_status'


class WebsiteMonitorUrl(models.Model):
    target =  models.ForeignKey(TargetsModel, related_name='murls', null=True)
    url = models.CharField(max_length=500, blank=False, default="")
    path = models.CharField(max_length=500, blank=False, default="")
    is_enabled = models.BooleanField(default=True)
    content_type = models.CharField(max_length=30, blank=False, default="html")
    max_level = models.IntegerField(default=0)
    is_training = models.BooleanField(default=True)
    counts = models.IntegerField(default=0)

    class Meta:
        unique_together = (("target", "url", "path"),)
        db_table = 'website_monitor_urls'


# class WebsiteContentModel(models.Model):
#     url_monitor = models.ForeignKey(WebsiteMonitorUrl, related_name='dcontents')
#     level = models.IntegerField(default=0, blank=False)
#     tag = models.CharField(max_length=50, blank=False, default="")
#     attrib = models.CharField(max_length=250, blank=True, default="")
#     content = models.TextField(default="", blank=True)
#     position = models.IntegerField(default=0, blank=False)
#     parent = models.ForeignKey("self", blank=True, null=True)
#     children_counts = models.IntegerField(default=0)
#     crawler_time = models.IntegerField(default=0)
#
#     class Meta:
#         db_table = 'website_contents'


class WebsiteContentModel(models.Model):
    url_monitor = models.ForeignKey(WebsiteMonitorUrl, related_name='scontents', null=True)
    monitor_time = models.IntegerField(default=time.time)
    crawler_count = models.IntegerField(default=1)
    content = models.TextField()

    class Meta:
        db_table = 'website_contents'


class WebsiteMonitorContentStatusModel(models.Model):
    url_monitor = models.ForeignKey(WebsiteMonitorUrl, related_name='mcontents', null=True)
    monitor_time = models.IntegerField(default=time.time)
    is_changed = models.BooleanField(default=False)

    class Meta:
        db_table = 'website_content_monitor_status'

class WebsiteMonitorContentChangeModel(models.Model):
    url_monitor = models.ForeignKey(WebsiteMonitorUrl, related_name='content_details', null=True)
    mmonitor_status = models.ForeignKey(WebsiteMonitorContentStatusModel, related_name='pages', null=True)
    monitor_time = models.IntegerField(default=time.time)
    old_contents = JSONField(default={})
    new_contents = JSONField(default={})

    class Meta:
        db_table = 'website_content_changed'


class SecurityEventsModels(models.Model):
    EVENTS_CHOICES = (
        ('HOST', 'host'),
        ('SERVICE', 'service'),
        ('VULNERABLITY', 'vulnerablity'),
        ('PENETRATION', 'Penetration'),
        ('BLACKLIST', 'blacklist'),
        ('MALWARE', 'malware'),
        ('WEB_DEFACE', 'Web deface'),
        ('SITE_DOWN', 'Site down')
    )

    ALERT_STATUS = (
        ('NEW_DEVICE', 'New device detected'),
        ('DEVICE_TURN_OFF', 'Device is turn off'),
        ('DEVICE_CHANGE_IP', 'Device is changed ip'),
        ('CANNOT_CONNECT_TO_TARGET', 'Cannot connect to target scan.'),

        ('NEW_SERVICE', 'New service detected'),
        ('SERVICE_CHANGED', 'Service is changed'),
        ('SERVICE_CLOSED', 'Service is closed'),
        ('SERVICE_VERSION_TOO_OLD', 'Service verion is too old'),

        ('NEW_VULNERABILITY', 'New vulnerability'),
        ('VULNERABILITY_IS_NOT_FIX', 'Vulnerability is not fix'),

        ('NEW_SESSION', 'New session'),
        ('NEW_PENETRATION', 'New penetration testing attack is successful'),

        ('BKACLIST_DETECTED', 'Blackist detected'),
        ('MALWARE_DETECTED', 'Malware is detected'),

        ('WEBSITE_CONTENT_DETECTED', 'Website content is change detected'),
        ('SERVER_STATUS', 'Website is down'),
        ('SERVICE_STATUS', 'Services is down'),
    )

    SEVERITY_LEVEL = (
        (0, 'info'),
        (1, 'low'),
        (2, 'medium'),
        (3, 'high'),
        (4, 'critical')
    )

    type = models.CharField(choices=EVENTS_CHOICES, max_length=30, default='IP ADDRESS')
    alert = models.CharField(choices=ALERT_STATUS, max_length=50, default="NEW_DEVICE")
    severity = models.IntegerField(choices=SEVERITY_LEVEL, default=1)

    class Meta:
        unique_together = (("type", "alert", "severity"),)
        db_table = 'security_events'


class WebsiteSecurityAlertModel(models.Model):
    ALERT_TYPE = (
        ('VULNERABILITY', 'vulnerability'),
        ('ABNORMAL', 'Abnormal'),
        ('PENETRATION', 'Penetration testing'),
        ('MALWARE', 'Malware'),
        ('BLACKLIST', 'Blacklist'),
        ('WEB_DEFACE', 'Web deface'),
        ('SITE_DOWN', 'Site down'),
    )

    DESCRIPTION_LIST = (
        ('NEW_DEVICE', 'Detect new device in your network.'),
        ('DEVICE_TURN_OFF', 'A device is turn off in your network.'),
        ('DEVICE_CHANGE_IP', 'Ip address of device is changed.'),
        ('CANNOT_CONNECT_TO_TARGET', 'Cannot connect to target scan.'),

        ('NEW_SERVICE', 'New service is open on your device.'),
        ('SERVICE_CHANGED', 'A service is change information.'),
        ('SERVICE_CLOSED', 'A service is closed on your device.'),
        ('SERVICE_VERSION_TOO_OLD', 'The version of service is too old.'),

        ('NEW_VULNERABILITY', ''),
        ('VULNERABILITY_IS_NOT_FIX', ''),

        ('NEW_SESSION', 'Penetration testing is successful. A new session is created.'),
        ('NEW_PENETRATION', 'Penetration testing is successful.'),

        ('BKACLIST_DETECTED', 'Your domain is making blacklist by domain blacklists checker.'),
        ('MALWARE_DETECTED', 'A malware is detect in website link.'),

        ('WEBSITE_CONTENT_DETECTED', 'Website content is changed.'),
        ('SERVER_STATUS', 'Cannot connect to http website.'),
        ('SERVICE_STATUS', 'services status'),
    )

    SOLUTION_LIST = (
        ('NEW_DEVICE', 'Please check list devices connected in your network.'),
        ('DEVICE_TURN_OFF', 'Please check your network connection with your device.'),
        ('DEVICE_CHANGE_IP', 'Please check network connection if you don\'t setting dhcp.'),
        ('CANNOT_CONNECT_TO_TARGET', 'Please check your network connection of your device and your targets.'),

        ('NEW_SERVICE', 'Please check the service of your device is you don\'t open port.'),
        ('SERVICE_CHANGED', 'Please check the service of your device is you don\'t do this.'),
        ('SERVICE_CLOSED', 'Please check the service of your device is you don\'t close port.'),
        ('SERVICE_VERSION_TOO_OLD', 'Please update the last version of software.'),

        ('NEW_VULNERABILITY', ''),
        ('VULNERABILITY_IS_NOT_FIX', ''),

        ('NEW_SESSION', ''),
        ('NEW_PENETRATION', 'Please fix the vulnerability.'),

        ('BKACLIST_DETECTED', 'Please check mail or website content or contact domain blacklists checker with to unblock.'),
        ('MALWARE_DETECTED', 'Please check website content source security.'),

        ('WEBSITE_CONTENT_DETECTED', 'Please check website status if you don\'t do this.'),
        ('SERVER_STATUS', 'Please check http service in website.'),
        ('SERVICE_STATUS', 'services status'),
    )

    type = models.CharField(choices=ALERT_TYPE, max_length=200, default='ABNORMAL')
    name = models.CharField(max_length=250, blank=False, default="")
    host = models.ForeignKey(HostsModel, related_name='msecurity', null=True)
    events = models.ForeignKey(SecurityEventsModels, related_name="msecurity", null=True)
    details = JSONField(default={})
    # description = models.CharField(max_length=200, default="")
    # solution = models.CharField(max_length=200, default="")
    description = models.TextField(choices=DESCRIPTION_LIST, default="", null=True, blank=True)
    solution = models.TextField(choices=SOLUTION_LIST,  default="", null=True, blank=True)
    time_created = models.IntegerField(default=time.time)
    resolve = models.BooleanField(default=False)

    class Meta:
        db_table = 'security_event_alerts'


class SoftwareLastVersionModel(models.Model):
    service_name = models.CharField(max_length=100, null=False)
    software_name = models.CharField(max_length=100, null=True, default="")
    homepage = models.CharField(max_length=200, null=True, blank=True)
    version = models.CharField(max_length=25, null=True, blank=True)

    class Meta:
        unique_together = (("service_name", "software_name"),)
        db_table = 'software_last_version'


class TargetTechnologyVersionModel(models.Model):
    target = models.ForeignKey(TargetsModel, related_name='technology_verions', null=True)
    host = models.ForeignKey(HostsModel, related_name='technology_verions', null=True)
    service_name = models.CharField(max_length=100, null=False)
    software_name = models.CharField(max_length=100, null=True, default="")
    version = models.CharField(max_length=25, null=True, blank=True)

    class Meta:
        db_table = 'software_current_version'