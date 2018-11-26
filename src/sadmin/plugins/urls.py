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
from django.conf.urls import url
from sadmin.plugins.views import PluginsList, PluginDetails, PluginLicenseDetails, PluginLicensesList, PluginsGroupDetails

urlpatterns = [
    # url(r'^$', PluginsList.as_view(), name='plugins-list'),
    url(r'^(?P<pk>[0-9]+)$', PluginsGroupDetails.as_view(), name='pluginsgroup-info'),
    url(r'^(?P<pk>[0-9]+)/plugins$', PluginsList.as_view(), name='plugins-list'),
    url(r'^(?P<pk>[0-9]+)/plugins/(?P<pk1>[0-9]+)$', PluginDetails.as_view(), name='plugin-info'),
    url(r'^(?P<pk>[0-9]+)/plugins/(?P<pk1>[0-9]+)/license$', PluginLicenseDetails.as_view(), name='plugin-license-info'),
]
