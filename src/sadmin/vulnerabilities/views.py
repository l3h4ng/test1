# -*- coding: utf-8 -*-
import time
from rest_framework import status

from agents.vulns.models import VulnerabilityModel, HostVulnerabilityModel
from agents.vulns.serializers import HostVulneratbilitySerializer, VulneratbilitySerializer, \
    HostVulnerabilityDetailSerializer, HostVulnrabilitiesCreateSerializer
from one_auth.authentication import OneTokenAuthentication
from one_users.permissions import IsOneUserAuthenticatedReadOnlyOrScanner
from sbox4web.views import JSONResponse

__author__ = 'TOANTV'

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from rest_framework import generics
from rest_framework.renderers import JSONRenderer


# /vulnerabilities
class VulnerabilitysList(generics.ListCreateAPIView):
    queryset = VulnerabilityModel.objects.all()
    serializer_class = VulneratbilitySerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('name', 'plugin_id', 'family', 'alert', 'severity', 'impact',)
    search_fields = ('name', 'severity',)

    def get_queryset(self):
        queryset = VulnerabilityModel.objects.all()
        cve_search = self.request.GET.get('cve', None)
        if cve_search is not None:
            queryset = queryset.filter(cve__contains=[cve_search])

        tags_search = self.request.GET.get('tags', None)
        if tags_search is not None:
            queryset = queryset.filter(tags__contains=[tags_search])

        return queryset

    def post(self, request, *args, **kwargs):
        data = request.data
        if "cve" in data and (isinstance(data["cve"], str) or isinstance(data["cve"], unicode)):
            if data["cve"] != "":
                data["cve"] = data["cve"].split(',')
            else:
                data["cve"] = []

        if "tags" in data and (isinstance(data["tags"], str) or isinstance(data["tags"], unicode)):
            if data["tags"] != "":
                data["tags"] = data["tags"].split(',')
            else:
                data["tags"] = []

        if "ref" in data and (isinstance(data["ref"], str) or isinstance(data["ref"], unicode)):
            if data["ref"] != "":
                data["ref"] = data["ref"].split(',')
            else:
                data["ref"] = []
        if "cvss" in data and (isinstance(data["cvss"], str) or isinstance(data["cvss"], unicode)):
            if data["cvss"] != "":
                data["cvss"] = data["cvss"].split(',')
            else:
                data["cvss"] = []

        data["created_at"] = int(time.time())
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return JSONResponse(serializer.data, status=status.HTTP_201_CREATED)


# /vulnerabilities/pk/
class VulnerabilityDetails(generics.RetrieveUpdateAPIView):
    serializer_class = VulneratbilitySerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        queryset = VulnerabilityModel.objects.filter(pk=pk)
        return queryset

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        data = request.data
        if "cve" in data and (isinstance(data["cve"], str) or isinstance(data["cve"], unicode)):
            if data["cve"] != "":
                data["cve"] = data["cve"].split(',')
            else:
                data["cve"] = []

        if "ref" in data and (isinstance(data["ref"], str) or isinstance(data["ref"], unicode)):
            if data["ref"] != "":
                data["ref"] = data["ref"].split(',')
            else:
                data["ref"] = []
        if "cvss" in data and (isinstance(data["cvss"], str) or isinstance(data["cvss"], unicode)):
            if data["cvss"] != "":
                data["cvss"] = data["cvss"].split(',')
            else:
                data["cvss"] = []

        serializer = self.get_serializer(instance, data=data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return JSONResponse(serializer.data, status=status.HTTP_200_OK)
