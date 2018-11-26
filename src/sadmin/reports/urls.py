# -*- coding: utf-8 -*-
__author__ = 'TOANTV'

from sadmin.reports.views import ReportDetailsView, ReportsTemplateListView, ReportTemplateDetails
from django.conf.urls import url

urlpatterns = [
    # url(r'^$', VulnerabilitysList.as_view(), name='vulneratbilities-list'),
    url(r'^(?P<pk>[0-9]+)$', ReportDetailsView.as_view(), name='reports-details'),
    url(r'^templates$', ReportsTemplateListView.as_view(), name='list-report-templates'),
    url(r'^templates/(?P<pk>[0-9]+)$', ReportTemplateDetails.as_view(), name='report-templates-details'),
]
