from django.conf.urls import url

from systems.views import LoggingAlertList, LoggingSystemList, LoggingAlertDetail, LoggingSystemDetail

urlpatterns =[
    url(r'^alert/$', LoggingAlertList.as_view(), name='alert-list'),
    url(r'^alert/(?P<pk>[0-9]+)/$', LoggingAlertDetail.as_view(), name='alert-list'),
    url(r'^system/(?P<pk>[0-9]+)/$', LoggingSystemDetail.as_view(), name='system-list'),
    url(r'^system/$', LoggingSystemList.as_view(), name='system-list'),
]