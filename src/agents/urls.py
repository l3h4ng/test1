# -*- coding: utf-8 -*-
from agents.monitor.views import GoogleHackingKeywordListView, GoogleHackingKeywordView, WebsiteMonitorStatusListView, \
    WebsiteMonitorStatusDetailsView, WebsiteMonitorUrlListView, \
    WebsiteMonitorUrlDetailsView, WebsiteMonitorContentDetailsView, \
    WebsiteSecurityAlertListView, WebsiteSecurityAlertDetailsView, WebsiteGoogleHackingDetectListView, \
    WebsiteGoogleHackingDetectView, WebsitePhishingDomainDetectListView, WebsitePhishingDomainDetectView, \
    WebsiteBlacklistCheckingListView, WebsiteBlacklistCheckingView, WebsiteContentMonitorStatusListView, \
    WebsiteLastContentDetailsView, WebsiteContentDetailsView, \
    WebsiteContentListView, WebsiteMonitorContentChangeListView, WebsiteMonitorContentChangeDetailsView
from agents.technologies.views import WebsiteTechnologiesListView, WebsiteTechnologiesDetailsView

__author__ = 'TOANTV'

from django.conf.urls import url
from agents.hosts.views import HostsListView, HostViews, HostInfoViews, ListHostsOfLastTaskAllTarget
from agents.services.views import HostServicesList, HostServiceDetails
from agents.vulns.views import HostVulnerabilitysList, HostVulnerabilityDetails
from agents.crawldata.views import CrawlDataListView, CrawlDataDetails
from agents.database.views import WebsiteDatabaseListView, WebsiteDatabaseDetailsView
from agents.scans.views import ScansList, ScanDetails
from agents.server_configurations.views import ServerConfigurationsDetails, ServerConfigurationsListView
from agents.subdomains.views import WebsiteSubdomainsList, WebsiteSubdomainsDetails
from agents.targets.views import TargetsListView, TargetDetailsView, TargetSchedulerView, TargetSchedulerDetailsView
from sadmin.reports.views import ReportAgentDetailsView, ReportsAgentsListView

urlpatterns = [
    url(r'^targets$', TargetsListView.as_view(), name='target-list'),
    url(r'^targets/(?P<pk>[0-9]+)$', TargetDetailsView.as_view(), name='target-info'),
    url(r'^targets/schedulers$', TargetSchedulerView.as_view(), name='target-scheduler'),
    url(r'^targets/schedulers/(?P<pk>[0-9]+)$', TargetSchedulerDetailsView.as_view(), name='target-scheduler-details'),

    url(r'^hosts$', HostsListView.as_view(), name='hosts-list'),
    url(r'^hosts/(?P<pk>[0-9]+)$', HostViews.as_view(), name='host-info'),
    url(r'^hosts/(?P<pk>[0-9]+)/info$', HostInfoViews.as_view(), name='host-info-only'),
    url(r'^hosts/lasted$', ListHostsOfLastTaskAllTarget.as_view(), name='host-lasted'),

    url(r'^technologies$', WebsiteTechnologiesListView.as_view(), name='hosts-technology-list'),
    url(r'^technologies/(?P<pk>[0-9]+)$', WebsiteTechnologiesDetailsView.as_view(), name='hosts-technology-info'),

    url(r'^services$', HostServicesList.as_view(), name='hosts-services-list'),
    url(r'^services/(?P<pk>[0-9]+)$', HostServiceDetails.as_view(), name='hosts-services-info'),

    url(r'^crawldata$', CrawlDataListView.as_view(), name='hosts-crawler-list'),
    url(r'^crawldata/(?P<pk>[0-9]+)$', CrawlDataDetails.as_view(), name='hosts-crawler-info'),

    url(r'^subdomains$', WebsiteSubdomainsList.as_view(), name='hosts-subdomain-list'),
    url(r'^subdomains/(?P<pk>[0-9]+)$', WebsiteSubdomainsDetails.as_view(), name='hosts-subdomain-info'),

    url(r'^databases$', WebsiteDatabaseListView.as_view(), name='hosts-database-list'),
    url(r'^databases/(?P<pk>[0-9]+)$', WebsiteDatabaseDetailsView.as_view(), name='hosts-database-info'),

    url(r'^configvulns$', ServerConfigurationsListView.as_view(), name='hosts-configvulns-list'),
    url(r'^configvulns/(?P<pk>[0-9]+)$', ServerConfigurationsDetails.as_view(), name='hosts-configvulns-info'),

    url(r'^vulns$', HostVulnerabilitysList.as_view(), name='hosts-vulns-list'),
    url(r'^vulns/(?P<pk>[0-9]+)$', HostVulnerabilityDetails.as_view(), name='hosts-vuln-info'),

    url(r'^scans$', ScansList.as_view(), name='scans-list'),
    url(r'^scans/(?P<pk>[0-9]+)$', ScanDetails.as_view(), name='scan-info'),

    url(r'^reports$', ReportsAgentsListView.as_view(), name='scans-list'),
    url(r'^reports/(?P<pk>[0-9]+)$', ReportAgentDetailsView.as_view(), name='scan-info'),

    url(r'^ghdb$', GoogleHackingKeywordListView.as_view(), name='hosts-vulns-list'),
    url(r'^ghdb/(?P<pk>[0-9]+)$', GoogleHackingKeywordView.as_view(), name='hosts-vuln-info'),

    url(r'^ghdbdetect$', WebsiteGoogleHackingDetectListView.as_view(), name='hosts-ghdbdetect-list'),
    url(r'^ghdbdetect/(?P<pk>[0-9]+)$', WebsiteGoogleHackingDetectView.as_view(), name='hosts-ghdbdetect-info'),

    url(r'^phishingdetect$', WebsitePhishingDomainDetectListView.as_view(), name='hosts-phishingdetect-list'),
    url(r'^phishingdetect/(?P<pk>[0-9]+)$', WebsitePhishingDomainDetectView.as_view(),
        name='hosts-phishingdetect-info'),

    url(r'^blacklistdetect$', WebsiteBlacklistCheckingListView.as_view(), name='hosts-blacklistdetect-list'),
    url(r'^blacklistdetect/(?P<pk>[0-9]+)$', WebsiteBlacklistCheckingView.as_view(), name='hosts-blacklistdetect-info'),

    url(r'^ghdb$', GoogleHackingKeywordListView.as_view(), name='hosts-vulns-list'),
    url(r'^ghdb/(?P<pk>[0-9]+)$', GoogleHackingKeywordView.as_view(), name='hosts-vuln-info'),

    url(r'^webstatus$', WebsiteMonitorStatusListView.as_view(), name='hosts-status-list'),
    url(r'^webstatus/(?P<pk>[0-9]+)$', WebsiteMonitorStatusDetailsView.as_view(), name='hosts-status-info'),

    url(r'^urlmonitors$', WebsiteMonitorUrlListView.as_view(), name='hosts-urlmonitor-list'),
    url(r'^urlmonitors/(?P<pk>[0-9]+)$', WebsiteMonitorUrlDetailsView.as_view(), name='hosts-urlmonitor-info'),
    url(r'^urlmonitors/(?P<pk>[0-9]+)/lastcontents$', WebsiteLastContentDetailsView.as_view(),
        name='url-lastcontent-info'),

    url(r'^contents$', WebsiteContentListView.as_view(), name='hosts-content-list'),
    url(r'^contents/(?P<pk>[0-9]+)$', WebsiteContentDetailsView.as_view(), name='hosts-content-info'),

    url(r'^mcontents$', WebsiteMonitorContentChangeListView.as_view(), name='hosts-mcontents-status-list'),
    url(r'^mcontents/(?P<pk>[0-9]+)$', WebsiteMonitorContentChangeDetailsView.as_view(),
        name='hosts-mcontents-status-info'),

    url(r'^mcstatus$', WebsiteContentMonitorStatusListView.as_view(), name='hosts-mcontents-status-list'),
    url(r'^mcstatus/(?P<pk>[0-9]+)$', WebsiteMonitorContentDetailsView.as_view(), name='hosts-mcontents-status-info'),

    url(r'^msecurity$', WebsiteSecurityAlertListView.as_view(), name='hosts-mcontents-list'),
    url(r'^msecurity/(?P<pk>[0-9]+)$', WebsiteSecurityAlertDetailsView.as_view(), name='hosts-mcontents-info'),
]
