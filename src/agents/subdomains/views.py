# -*- coding: utf-8 -*-
from agents.subdomains.models import WebsiteSubdomainsModel
from agents.subdomains.serializers import WebsiteSubdomainsSerializer
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

# /agents/subdomains
class WebsiteSubdomainsList(generics.ListCreateAPIView):
    queryset = WebsiteSubdomainsModel.objects.all().order_by('-id')
    serializer_class = WebsiteSubdomainsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('ip_addr', 'subdomain', 'website', )
    search_fields = ('subdomain', )

# /agents/subdomains/pk/
class WebsiteSubdomainsDetails(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = WebsiteSubdomainsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        queryset = WebsiteSubdomainsModel.objects.filter(pk=pk)
        return queryset

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()

        # Update host statistics
        host_statistic = instance.website.statistics
        host_statistic.subdomains_count -= 1
        host_statistic.save()

        # Update task statistics
        task_statistic = instance.website.task.statistics
        task_statistic.subdomains_count -= 1
        task_statistic.save()
        self.perform_destroy(instance)
        return JSONResponse({}, status=status.HTTP_204_NO_CONTENT)
