# -*- coding: utf-8 -*-
from agents.database.models import WebsiteDatabasesModel
from agents.database.serializers import WebsiteDatabaseSerializer
from agents.monitor.sbox_monitor import SboxSecurityMonitor
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from rest_framework import generics
from rest_framework import status
from rest_framework.renderers import JSONRenderer

from one_auth.authentication import OneTokenAuthentication
from one_users.permissions import IsOneUserAuthenticatedReadOnlyOrScanner
from sbox4web.libs import update_host_task_statistic, update_host_task_system_statistic
from sbox4web.views import JSONResponse

__author__ = 'TOANTV'

# /hosts/hid/services/
class WebsiteDatabaseListView(generics.ListCreateAPIView):
    queryset = WebsiteDatabasesModel.objects.all().order_by('-id')
    serializer_class = WebsiteDatabaseSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('website',)
    search_fields = ('website',)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()

        SboxSecurityMonitor("PENETRATION").monitor(instance)
        return JSONResponse(serializer.data, status=status.HTTP_201_CREATED)


# /hosts/hid/services/pk1/
class WebsiteDatabaseDetailsView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = WebsiteDatabaseSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        queryset = WebsiteDatabasesModel.objects.filter(pk=pk)
        return queryset

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()

        self.perform_destroy(instance)
        update_host_task_system_statistic(instance.website)
        return JSONResponse({}, status=status.HTTP_204_NO_CONTENT)
