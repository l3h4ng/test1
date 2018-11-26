# -*- coding: utf-8 -*-
from agents.technologies.models import WebsiteTechnologiesModel
from agents.technologies.serializers import WebsiteTechnologiesSerializer

__author__ = 'TOANTV'
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import generics
from rest_framework import status
from rest_framework import filters
from rest_framework.exceptions import ValidationError
from rest_framework.renderers import JSONRenderer

from agents.hosts.models import HostsModel, HostDetailsModel
from agents.hosts.serializers import HostCreateDetailsSerializer, HostCreateUpdateSerializer, HostStatisticSerializer, \
    HostInfoSerializer, InfoSerializer
from one_auth.authentication import OneTokenAuthentication
from one_users.permissions import IsOneUserAuthenticatedReadOnlyOrScanner
from sbox4web.views import JSONResponse
from targets.models import TasksModel

# /agents/technology
class WebsiteTechnologiesListView(generics.ListCreateAPIView):
    queryset = WebsiteTechnologiesModel.objects.all().order_by('-id')
    serializer_class = WebsiteTechnologiesSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('version', 'technology', 'website', )
    search_fields = ('website', 'technology',)

# /agents/subdomains/pk/
class WebsiteTechnologiesDetailsView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = WebsiteTechnologiesSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        queryset = WebsiteTechnologiesModel.objects.filter(pk=pk)
        return queryset
