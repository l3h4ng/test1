# -*- coding: utf-8 -*-
import urllib

from agents.crawldata.models import CrawlDataModel
from agents.crawldata.serializers import CrawlDataSerializer
from agents.monitor.sbox_monitor import SboxSecurityMonitor
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from rest_framework import generics
from rest_framework import status
from rest_framework.renderers import JSONRenderer
from one_auth.authentication import OneTokenAuthentication
from one_users.permissions import IsOneUserAuthenticatedReadOnlyOrScanner
from sbox4web.libs import update_host_statistic, update_target_statistic, update_host_task_statistic, \
    update_host_task_system_statistic
from sbox4web.libs import update_task_statistic
from sbox4web.rabbitmq import Rabbitmq
from sbox4web.views import JSONResponse

__author__ = 'TOANTV'

# /crawldata
class CrawlDataListView(generics.ListCreateAPIView):
    queryset = CrawlDataModel.objects.all().order_by('path')
    serializer_class = CrawlDataSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('website', 'parent_id', 'loc_type', 'path',)
    search_fields = ('name',)

    def get_queryset(self):
        queryset = CrawlDataModel.objects.all().order_by('path')
        return queryset

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = self.perform_create(serializer)
        instance.path = urllib.unquote(urllib.unquote(instance.path))
        instance.save()

        update_host_task_statistic(instance.website)
        # Check security for path
        try:
            server_node_name = instance.website.task.target.server_node.name
            queue_name = "{}_malwares".format(server_node_name)
            rabbitmq = Rabbitmq(queue_name)
            rabbitmq.add(str(instance.id))
        except Exception, ex:
            print "Cannot add url id to rabbitmq server, exception {}".format(str(ex))
        return JSONResponse(CrawlDataModel(instance).data, status=status.HTTP_201_CREATED)


# /crawldata/pk/
class CrawlDataDetails(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = CrawlDataSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        queryset = CrawlDataModel.objects.filter(pk=pk)
        return queryset

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        old_security_level = instance.security_level
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()

        # Update malware path count
        if instance.security_level >= 1:
            # malware monitor alert
            SboxSecurityMonitor("MALWARE").monitor(instance)
        return JSONResponse(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        update_host_task_system_statistic(instance.website)
        return JSONResponse({}, status=status.HTTP_204_NO_CONTENT)
