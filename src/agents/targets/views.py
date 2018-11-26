# -*- coding: utf-8 -*-
__author__ = 'TOANTV'
from agents.targets.serializers import TargetSchedulerSerializers, TargetTimeDetailsInfoSerializer
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import generics
from rest_framework.renderers import JSONRenderer
from rest_framework import filters

from one_auth.authentication import OneTokenAuthentication
from one_users.permissions import IsOneUserAuthenticated
from targets.models import TargetsModel, SchedulerModel

# /agents/targets
class TargetsListView(generics.ListAPIView):
    serializer_class = TargetTimeDetailsInfoSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('name', 'status', 'office', 'address', 'severity')
    search_fields = ('name', 'address')

    def get_queryset(self):
        queryset = TargetsModel.objects.all().order_by('-id')
        queryset = queryset.select_related('configuration', 'configuration__scheduler')
        queryset = queryset.select_related('office', 'office__unit')
        queryset = queryset.prefetch_related('tasks')
        return queryset


# /agents/targets/id
class TargetDetailsView(generics.RetrieveUpdateAPIView):
    serializer_class = TargetTimeDetailsInfoSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('name', 'status', 'office', 'address', 'severity')
    search_fields = ('name', 'address')

    def get_queryset(self):
        queryset = TargetsModel.objects.all().order_by('-id')
        queryset = queryset.select_related('configuration', 'configuration__scheduler')
        queryset = queryset.select_related('office', 'office__unit')
        queryset = queryset.prefetch_related('tasks')
        return queryset


class TargetSchedulerView(generics.ListAPIView):
    serializer_class = TargetSchedulerSerializers
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('status', 'next_time',)

    def get_queryset(self):
        queryset = SchedulerModel.objects.all()
        date_gte = self.request.GET.get('date_gte', None)
        date_lte = self.request.GET.get('date_lte', None)
        if date_gte is not None:
            queryset = queryset.filter(next_time__gte=date_gte)
        if date_lte is not None:
            queryset = queryset.filter(next_time__lte=date_lte)
        return queryset


class TargetSchedulerDetailsView(generics.RetrieveUpdateAPIView):
    serializer_class = TargetSchedulerSerializers
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('status', 'next_time',)

    def get_queryset(self):
        queryset = SchedulerModel.objects.all()
        return queryset
