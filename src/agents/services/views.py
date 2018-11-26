# -*- coding: utf-8 -*-
from agents.monitor.sbox_monitor import SboxSecurityMonitor
from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from rest_framework import generics
from rest_framework import status
from rest_framework.renderers import JSONRenderer

from agents.services.models import HostServicesModel
from agents.services.serializers import ServiceSerializer
from one_auth.authentication import OneTokenAuthentication
from one_users.permissions import IsOneUserAuthenticatedReadOnlyOrScanner
from sbox4web.views import JSONResponse

__author__ = 'TOANTV'

# /hosts/hid/services/
class HostServicesList(generics.ListCreateAPIView):
    serializer_class = ServiceSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('ip_addr', 'name', 'port', 'host', 'state',)
    search_fields = ('ip_addr', 'name', 'port', 'host',)

    def get_queryset(self):
        queryset = HostServicesModel.objects.all().order_by('-id')
        queryset = queryset.select_related('host__task')

        task_query = self.request.GET.get('task', None)
        if task_query is not None and task_query != "":
            queryset = queryset.filter(Q(host__task_id=task_query))
        return queryset

    def create(self, request, *args, **kwargs):
        if "state" in request.data and request.data["state"].lower() == "open":
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            service = serializer.save()

            # detect monitor alert
            SboxSecurityMonitor("SERVICE").monitor(service)
            return JSONResponse(serializer.data, status=status.HTTP_201_CREATED)
        else:
            error = {"status": "error",
                     "exception": "Port status is not open"
                     }
            return JSONResponse(error, status=status.HTTP_400_BAD_REQUEST)

# /hosts/hid/services/pk1/
class HostServiceDetails(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = ServiceSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        queryset = HostServicesModel.objects.filter(pk=pk)
        return queryset

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()

        # Update host statistics
        host_statistic = instance.host.statistics
        host_statistic.services_count -= 1
        host_statistic.save()

        # Update task statistics
        task_statistic = instance.host.task.statistics
        task_statistic.services_count -= 1
        task_statistic.save()
        self.perform_destroy(instance)
        return JSONResponse({}, status=status.HTTP_204_NO_CONTENT)