"""tutorial URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.8/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Add an import:  from blog import urls as blog_urls
    2. Add a URL to urlpatterns:  url(r'^blog/', include(blog_urls))
"""
from django.conf.urls import url, include

from targets.view import TargetsOfUnitView
from units.views import UnitsList, UnitDetails, OfficesOfUnitList, OfficeOfUnitDetails, UnitStatisticView, \
    UnitTopTargetsView, OfficeStatisticView, OfficeTopTargetsView

urlpatterns = [
    # url(r'^$', UnitsList.as_view(), name='units-list'),
    url(r'^(?P<pk>[0-9]+)$', UnitDetails.as_view(), name='unit-detail'),
    url(r'^(?P<pk>[0-9]+)/statistics$', UnitStatisticView.as_view(), name='unit-statistic'),
    url(r'^(?P<pk>[0-9]+)/toptargets$', UnitTopTargetsView.as_view(), name='unit-targets'),
    url(r'^(?P<pk>[0-9]+)/topvulns$', UnitDetails.as_view(), name='unit-detail'),
    url(r'^(?P<pk>[0-9]+)/topservices$', UnitDetails.as_view(), name='unit-detail'),

    url(r'^(?P<pk>[0-9]+)/offices$', OfficesOfUnitList.as_view(), name='unit-offices-list'),
    url(r'^(?P<pk>[0-9]+)/offices/(?P<pk1>[0-9]+)$', OfficeOfUnitDetails.as_view(), name='unit-offices-detail'),
    url(r'^(?P<pk>[0-9]+)/offices/(?P<pk1>[0-9]+)/statistics$', OfficeStatisticView.as_view(), name='targets_list'),
    url(r'^(?P<pk>[0-9]+)/offices/(?P<pk1>[0-9]+)/toptargets$', OfficeTopTargetsView.as_view(), name='targets_list'),
    url(r'^(?P<pk>[0-9]+)/offices/(?P<pk1>[0-9]+)/targets$', TargetsOfUnitView.as_view(), name='targets_list'),
    url(r'^(?P<pk>[0-9]+)/offices/(?P<pk1>[0-9]+)/targets/', include('targets.urls')),
]
