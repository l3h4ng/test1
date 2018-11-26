# -*- coding: utf-8 -*-
__author__ = 'TOANTV'

from django.conf.urls import url

from sadmin.vulnerabilities.views import VulnerabilityDetails

urlpatterns = [
    # url(r'^$', VulnerabilitysList.as_view(), name='vulneratbilities-list'),
    url(r'^(?P<pk>[0-9]+)$', VulnerabilityDetails.as_view(), name='vulneratbility-details'),
]