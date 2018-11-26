from django.conf.urls import url, include

from reports.views import HostsOfTaskList
from sadmin.reports.views import ReportsOfTaskListView, ReportsOfTargetListView
from targets.view import *

urlpatterns = [
    # url(r'^$', TargetsView.as_view(), name='targets_list'),
    url(r'^(?P<pk2>[0-9]+)/statistics$', ListStatisticsView.as_view(), name='target-statistics'),
    url(r'^(?P<pk2>[0-9]+)/reports$', ReportsOfTargetListView.as_view(), name='target-reports'),
    # url(r'^schedulers/(?P<pk>[0-9]+)/$', SchedulersDetailView.as_view(), name='targets_schedulers_detail'),
    url(r'^(?P<pk2>[0-9]+)$', TargetDetails.as_view(), name='target-detail'),
    # url(r'^(?P<pk2>[0-9]+)/configurations$', TargetConfigutionDetails.as_view(), name='configurations-detail'),
    # url(r'^(?P<pk>[0-9]+)/schedulers$', TargetSchedulerDetails.as_view(), name='configurations-detail'),
    url(r'^(?P<pk2>[0-9]+)/tasks$', TasksListOfTarget.as_view(), name='tasks-list-of-target'),
    # url(r'^(?P<pk2>[0-9]+)/tasks/compares$', TasksCompare2Views.as_view(), name='tasks-report-compare'),
    url(r'^(?P<pk2>[0-9]+)/tasks/(?P<pk3>[0-9]+)$', TasksDetails.as_view(), name='tasks-detail-of-target'),
    url(r'^(?P<pk2>[0-9]+)/tasks/(?P<pk3>[0-9]+)/statistics$', ListStatisticsView.as_view(), name='task-statistics'),
    url(r'^(?P<pk2>[0-9]+)/tasks/(?P<pk3>[0-9]+)/reports$', ReportsOfTaskListView.as_view(), name='task-reports'),
    url(r'^(?P<pk2>[0-9]+)/tasks/(?P<pk3>[0-9]+)/vulnalerts$', TopVulnsAlertOfTask.as_view(), name='tasks-vuln-alerts'),
    url(r'^status/$', GetTargetsStatus.as_view(), name='sum status '),
    url(r'^(?P<pk2>[0-9]+)/tasks/(?P<pk3>[0-9]+)/scans$', ListScanOfTask.as_view(),
        name='tasks-detail-of-target-info'),
    url(r'^(?P<pk2>[0-9]+)/tasks/(?P<pk3>[0-9]+)/scans/(?P<pk4>[0-9]+)$', ScanTaskDetails.as_view(),
        name='scans-details'),
    url(r'^(?P<pk2>[0-9]+)/tasks/(?P<pk3>[0-9]+)/prev-curent-next$', PrevCurentNext.as_view(), name='prev-crent-next'),
    url(r'^(?P<pk2>[0-9]+)/tasks/(?P<pk3>[0-9]+)/hosts$', HostsOfTaskList.as_view(), name='prev-crent-next'),
    url(r'^(?P<pk2>[0-9]+)/tasks/(?P<pk3>[0-9]+)/hosts/', include("reports.urls")),
]
