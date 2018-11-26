# -*- coding: utf-8 -*-
from agents.database.models import WebsiteDatabasesModel
from agents.database.serializers import WebsiteDatabaseSerializer
from django_filters.rest_framework import DjangoFilterBackend
from nodes.models import SboxNodes
from nodes.serializers import SboxNodesSerializer
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
class SboxNodesListView(generics.ListCreateAPIView):
    queryset = SboxNodes.objects.all().order_by('-id')
    serializer_class = SboxNodesSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('name', )
    search_fields = ('name', )

# /hosts/hid/services/pk1/
class SboxNodesDetailsView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = SboxNodesSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        queryset = SboxNodes.objects.filter(pk=pk)
        return queryset