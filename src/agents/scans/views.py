# -*- coding: utf-8 -*-

__author__ = 'TOANTV'
from agents.scans.models import ScansModel
from agents.scans.serializers import ScansSerializer
from one_users.permissions import IsOneUserAuthenticatedReadOnly, IsOneUserScanner
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import generics
from rest_framework.renderers import JSONRenderer
from one_auth.authentication import OneTokenAuthentication
from sbox4web.views import JSONResponse
from rest_framework import status

# /scans/
class ScansList(generics.ListAPIView):
    serializer_class = ScansSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('task', 'status', 'plugin',)

    def get_queryset(self):
        queryset = ScansModel.objects.all().order_by('id')
        queryset = queryset.select_related('task', 'task__target', 'task__target__configuration')
        return queryset


# /scans/id
class ScanDetails(generics.RetrieveUpdateAPIView):
    serializer_class = ScansSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        queryset = ScansModel.objects.all().order_by('id')
        queryset = queryset.select_related('task', 'task__target', 'task__target__configuration',
                                           'task__target__configuration__scheduler')
        return queryset
