"""sbox4web URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.9/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from threading import Thread
from agents.hosts.models import HostsModel
from django.conf.urls import url, include
from agents.vulns.views import HostVulnerabilitysListDetails
from nodes.views import SboxNodesListView, SboxNodesDetailsView

from sadmin.vulnerabilities.views import VulnerabilitysList
from one_users.views import OneUsersList, OneAuthenticatedUserDetail
from sadmin.plugins.views import PluginsList, PluginDetails, PluginLicenseDetails
from sadmin.reports.views import ReportsListView
from sbox4web.libs import *
from sbox4web.startup import update_ip_addr_currents
from targets.models import TasksModel
from targets.view import TargetsListView
from units.views import UnitsList, TargetTreeView, SystemScanStatusView
from agents.monitor.views import SecurityEventsListView, SecurityEventsDetailsView, WebsiteSecurityAlertDetailsView, \
    WebsiteSecurityAlertLastedListView

handler400 = 'sbox4web.views.custom400'
handler403 = 'sbox4web.views.custom403'
handler404 = 'sbox4web.views.custom404'
handler500 = 'sbox4web.views.custom500'

urlpatterns = [
    url(r'^auth/', include('one_auth.urls')),
    url(r'^users$', OneUsersList.as_view(), name='users-list'),
    url(r'^users/', include('one_users.urls')),
    url(r'^me$', OneAuthenticatedUserDetail.as_view(), name='user-profile'),
    url(r'^me/', include('one_users.urls_me')),

    url(r'^snodes$', SboxNodesListView.as_view(), name='snodes-list'),
    url(r'^snodes/(?P<pk>[0-9]+)$', SboxNodesDetailsView.as_view(), name='snodes-details'),

    url(r'^units$', UnitsList.as_view(), name='units-list'),
    url(r'^units/', include('units.urls')),
    url(r'^targets$', TargetsListView.as_view(), name='target-list'),
    url(r'^reports$', ReportsListView.as_view(), name='report-list'),
    url(r'^reports/', include('sadmin.reports.urls')),

    # url(r'^hosts$', HostsListView.as_view(), name='target-list'),
    # url(r'^hosts/', include('hosts.host_urls')),
    url(r'^systems/', include('systems.urls')),
    # url(r'^pgroups$', PluginsGrouspList.as_view(), name='pluginsgroup-list'),
    # url(r'^pgroups/', include('sadmin.plugins.urls')),

    url(r'^plugins$', PluginsList.as_view(), name='plugins-list'),
    url(r'^plugins/(?P<pk>[0-9]+)$', PluginDetails.as_view(), name='plugin-info'),
    url(r'^plugins/(?P<pk>[0-9]+)/license$', PluginLicenseDetails.as_view(), name='plugin-license-info'),

    # url(r'^plugins/', include('plugins.urls')),
    # url(r'^logging/', include('systems.logging_urls')),
    url(r'^agents/', include('agents.urls')),
    url(r'^vulns$', HostVulnerabilitysListDetails.as_view(), name='host-vulns-list'),
    url(r'^vulnerabilities$', VulnerabilitysList.as_view(), name='vulnerabillity-list'),
    url(r'^vulnerabilities/', include('sadmin.vulnerabilities.urls')),

    url(r'^sevents$', SecurityEventsListView.as_view(), name='security-events-list'),
    url(r'^sevents/(?P<pk>[0-9]+)$', SecurityEventsDetailsView.as_view(), name='security-events-info'),

    url(r'^msecurity$', WebsiteSecurityAlertLastedListView.as_view(), name='security-alert-list'),
    url(r'^msecurity/(?P<pk>[0-9]+)$', WebsiteSecurityAlertDetailsView.as_view(), name='security-alert-info'),

    url(r'^maps$', TargetTreeView.as_view(), name='target-maps'),
    url(r'^scanstatus$', SystemScanStatusView.as_view(), name='system-scan-status'),
]
# update_all_scan_target()
# update_all_msecurity()
# update_all_statistic()
# update_task_statistic(task)
# update_ip_addr_currents()
# thread_status = Thread(target = status_monitor_scheduler, args = ())
# thread_status.start()
# thread_mcontent = Thread(target = website_content_monitor_scheduler, args = ())
# thread_mcontent.start()
# update_all_scan_target()
# update_all_msecurity()
# host = HostsModel.objects.get(pk=1596)
# task = TasksModel.objects.get(pk=1856)
# update_host_statistic(host)
# update_task_statistic(task)
# update_target_statistic(task.target)
# update_system_update_time()
# update_system_statisticsv2()
# update_all_statistic()
# update_system_update_time()