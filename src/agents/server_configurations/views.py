# -*- coding: utf-8 -*-
__author__ = 'TOANTV'
from agents.crawldata.models import CrawlDataModel
from agents.server_configurations.models import ServerConfigurationsModel
from agents.server_configurations.serializers import ServerConfigurationsSerializer
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from rest_framework import generics
from rest_framework import status
from rest_framework.renderers import JSONRenderer

from one_auth.authentication import OneTokenAuthentication
from one_users.permissions import IsOneUserAuthenticatedReadOnlyOrScanner
from sbox4web.views import JSONResponse
# /crawldata
class ServerConfigurationsListView(generics.ListCreateAPIView):
    serializer_class = ServerConfigurationsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('website', 'name', 'description')
    search_fields = ('name',)

    def get_queryset(self):
        queryset = ServerConfigurationsModel.objects.all().order_by('url')
        return queryset


# /crawldata/pk/
class ServerConfigurationsDetails(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = ServerConfigurationsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        queryset = ServerConfigurationsModel.objects.filter(pk=pk)
        return queryset

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()

        # Update host statistics
        website_statistic = instance.website.statistics
        website_statistic.server_config_vulns -= 1
        website_statistic.save()

        # Update task statistics
        task_statistic = instance.website.task.statistics
        task_statistic.server_config_vulns -= 1
        task_statistic.save()
        self.perform_destroy(instance)
        return JSONResponse({}, status=status.HTTP_204_NO_CONTENT)
