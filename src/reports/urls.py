from django.conf.urls import url

from reports.views import HostOfTaskDetailsViews, HostsDetailsOfTaskList, HostDetailsOfTaskViews, \
    HostVulnerabilitiesDetailsOfTaskViews, HostsVulnerabilitiesOfTaskList, \
    WebsiteCrawlerOfTaskList, WebsiteCrawlerDetailsOfTaskViews, WebsiteSubdomainsDetailsOfTaskViews, \
    WebsiteSubdomainsOfTaskList, WebsiteDatabasesDetailsOfTaskViews, WebsiteDatabasesOfTaskList, \
    WebsiteConfigurationsVulnsOfTaskList, WebsiteConfigurationsVulnsDetailsOfTaskViews, \
    WebsiteSubdomainsMonitorTaskViews, StatusOfWebsiteHistory, StatusOfWebsiteViews, LastStatusOfWebsiteViews, \
    ContentsMonitorOfWebsiteViews, LastContentsMonitorOfWebsiteList, WebsiteBlacklistAlertViews, WebsiteBlacklistAlertList, WebsitePhishingDomainViews, WebsitePhishingDomainList, \
    WebsiteGHDBAlertList, WebsiteGHDBAlertViews, WebsiteSecurityAlertDetailsOfHostView, \
    WebsiteSecurityAlertOfHostListView, WebsiteSecurityAlertOfTaskListView, ContentsMonitorOfWebsiteHistoryViews, \
    WebsiteAbnormalEventsOfTaskListView, WebsiteAbnormalEventsOfHostListView, WebsiteAbnormalEventsDetailsOfHostView

urlpatterns = [
    # url(r'^$', HostsOfTaskList.as_view(), name='hosts-list'),
    url(r'^(?P<pk4>[0-9]+)$', HostOfTaskDetailsViews.as_view(), name='host-of-task-info'),

    url(r'^details$', HostsDetailsOfTaskList.as_view(), name='host-of-task-details-lisy'),
    url(r'^(?P<pk4>[0-9]+)/details$', HostDetailsOfTaskViews.as_view(), name='host-of-task-details'),

    url(r'^vulns$', HostsVulnerabilitiesOfTaskList.as_view(), name='hosts-vulns-list'),
    url(r'^(?P<pk4>[0-9]+)/vulns$', HostVulnerabilitiesDetailsOfTaskViews.as_view(), name='hosts-vuln-info'),

    url(r'^crawler$', WebsiteCrawlerOfTaskList.as_view(), name='hosts-crawler-list'),
    url(r'^(?P<pk4>[0-9]+)/crawler$', WebsiteCrawlerDetailsOfTaskViews.as_view(), name='hosts-crawler-info'),

    url(r'^subdomains$', WebsiteSubdomainsOfTaskList.as_view(), name='hosts-subdomain-list'),
    url(r'^(?P<pk4>[0-9]+)/subdomains$', WebsiteSubdomainsDetailsOfTaskViews.as_view(), name='hosts-subdomain-info'),
    url(r'^(?P<pk4>[0-9]+)/subdomains/(?P<pk5>[0-9]+)$', WebsiteSubdomainsMonitorTaskViews.as_view(), name='hosts-subdomain-update'),

    url(r'^databases$', WebsiteDatabasesOfTaskList.as_view(), name='hosts-database-list'),
    url(r'^(?P<pk4>[0-9]+)/databases$', WebsiteDatabasesDetailsOfTaskViews.as_view(), name='hosts-database-info'),

    url(r'^configvulns$', WebsiteConfigurationsVulnsOfTaskList.as_view(), name='hosts-configvulns-list'),
    url(r'^(?P<pk4>[0-9]+)/configvulns$', WebsiteConfigurationsVulnsDetailsOfTaskViews.as_view(), name='hosts-configvulns-info'),

    # url(r'^webstatus$', WebsiteConfigurationsVulnsOfTaskList.as_view(), name='hosts-configvulns-list'),
    url(r'^(?P<pk4>[0-9]+)/webstatus$', LastStatusOfWebsiteViews.as_view(), name='hosts-last-webstatus-info'),
    url(r'^(?P<pk4>[0-9]+)/webstatus/(?P<pk5>[0-9]+)$', StatusOfWebsiteViews.as_view(), name='hosts-webstatus-info'),
    url(r'^(?P<pk4>[0-9]+)/webstatus/history$', StatusOfWebsiteHistory.as_view(), name='hosts-webstatus-history-info'),

    # url(r'^msecurity$', WebsiteConfigurationsVulnsDetailsOfTaskViews.as_view(), name='hosts-configvulns-info'),
    url(r'^(?P<pk4>[0-9]+)/mghdb$', WebsiteGHDBAlertList.as_view(), name='hosts-mghdb-info'),
    url(r'^(?P<pk4>[0-9]+)/mghdb/(?P<pk5>[0-9]+)$', WebsiteGHDBAlertViews.as_view(), name='hosts-mghdb-details'),

    # url(r'^msecurity$', WebsiteConfigurationsVulnsDetailsOfTaskViews.as_view(), name='hosts-configvulns-info'),
    url(r'^(?P<pk4>[0-9]+)/mphishing$', WebsitePhishingDomainList.as_view(), name='hosts-mphishing-info'),
    url(r'^(?P<pk4>[0-9]+)/mphishing/(?P<pk5>[0-9]+)$', WebsitePhishingDomainViews.as_view(), name='hosts-mphishing-details'),

    # url(r'^msecurity$', WebsiteConfigurationsVulnsDetailsOfTaskViews.as_view(), name='hosts-configvulns-info'),
    url(r'^(?P<pk4>[0-9]+)/mblacklist$', WebsiteBlacklistAlertList.as_view(), name='hosts-mblacklist-info'),
    url(r'^(?P<pk4>[0-9]+)/mblacklist/(?P<pk5>[0-9]+)$', WebsiteBlacklistAlertViews.as_view(), name='hosts-mblacklist-details'),

    url(r'^msecurity$', WebsiteSecurityAlertOfTaskListView.as_view(), name='msecurity-task-info'),
    url(r'^(?P<pk4>[0-9]+)/msecurity$', WebsiteSecurityAlertOfHostListView.as_view(), name='msecurity-host-list'),
    url(r'^(?P<pk4>[0-9]+)/msecurity/(?P<pk5>[0-9]+)$', WebsiteSecurityAlertDetailsOfHostView.as_view(), name='msecurity-host-details'),


    url(r'^abnormal$', WebsiteAbnormalEventsOfTaskListView.as_view(), name='abnormal-task-info'),
    url(r'^(?P<pk4>[0-9]+)/abnormal$', WebsiteAbnormalEventsOfHostListView.as_view(), name='abnormal-host-list'),
    url(r'^(?P<pk4>[0-9]+)/abnormal/(?P<pk5>[0-9]+)$', WebsiteAbnormalEventsDetailsOfHostView.as_view(), name='abnormal-host-details'),


    # url(r'^mcontents$', WebsiteConfigurationsVulnsDetailsOfTaskViews.as_view(), name='hosts-configvulns-info'),
    # url(r'^mcontents$', ContentsMonitorOfTaskList.as_view(), name='task-mcontents-info'),
    url(r'^(?P<pk4>[0-9]+)/mcontents$', LastContentsMonitorOfWebsiteList.as_view(), name='last-hosts-mcontents-info'),
    url(r'^(?P<pk4>[0-9]+)/mcontents/(?P<pk5>[0-9]+)$', ContentsMonitorOfWebsiteViews.as_view(), name='hosts-mcontents-details'),
    url(r'^(?P<pk4>[0-9]+)/mcontents/history$', ContentsMonitorOfWebsiteHistoryViews.as_view(), name='hosts-mcontents-list'),
]
