# -*- coding: utf-8 -*-
from agents.monitor.sbox_monitor import SboxSecurityMonitor
from django.db.models import Q

from rest_framework import status

from agents.vulns.models import VulnerabilityModel, HostVulnerabilityModel
from agents.vulns.serializers import HostVulneratbilitySerializer, HostVulnerabilityDetailSerializer, \
    HostVulnrabilitiesCreateSerializer, HostVulnerabilityListDetailsSerializer
from one_auth.authentication import OneTokenAuthentication
from one_users.permissions import IsOneUserAuthenticatedReadOnlyOrScanner
from sbox4web.views import JSONResponse

__author__ = 'TOANTV'

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from rest_framework import generics
from rest_framework.renderers import JSONRenderer


# agents/vulns
class HostVulnerabilitysList(generics.ListCreateAPIView):
    serializer_class = HostVulnerabilityDetailSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = (
        'host', 'name', 'is_fixed', 'is_ignored', 'plugin', 'port', 'attack_details', 'vulnerability',)
    search_fields = ('host', 'name', 'port',)

    def get_queryset(self):
        queryset = HostVulnerabilityModel.objects.all()
        queryset = queryset.select_related('vulnerability')

        # cve search
        cve_search = self.request.GET.get('cve', None)
        if cve_search is not None:
            queryset = queryset.filter(vulnerability__cve__contains=[cve_search])

        # tags search
        tags_search = self.request.GET.get('tags', None)
        if tags_search is not None:
            queryset = queryset.filter(vulnerability__tags__contains=[tags_search])

        # severity search
        severity_search = self.request.GET.get('severity', None)
        if severity_search is not None:
            queryset = queryset.filter(vulnerability__severity__contains=severity_search)

        # host search
        host_search = self.request.GET.get('host', None)
        if host_search is not None:
            queryset = queryset.filter(host=host_search)
            queryset = queryset.order_by('-vulnerability__severity')
        else:
            queryset = queryset.order_by('-id')
        return queryset

    def post(self, request, *args, **kwargs):
        data = request.data
        if "vulnerability" in data and isinstance(data["vulnerability"], dict):
            try:
                vulnerability = VulnerabilityModel.objects.get(name=data["vulnerability"]["name"],
                                                               plugin_id=data["vulnerability"]["plugin_id"])
                data["vulnerability"] = vulnerability.id
                self.serializer_class = HostVulneratbilitySerializer
            except VulnerabilityModel.DoNotExits():
                self.serializer_class = HostVulnrabilitiesCreateSerializer
                if "cve" in data["vulnerability"] and (
                            isinstance(data["vulnerability"]["cve"], str) or isinstance(data["vulnerability"]["cve"],
                                                                                        unicode)):
                    if data["vulnerability"]["cve"] != "":
                        data["vulnerability"]["cve"] = data["vulnerability"]["cve"].split(',')
                    else:
                        data["vulnerability"]["cve"] = []

                if "ref" in data["vulnerability"] and (
                            isinstance(data["vulnerability"]["ref"], str) or isinstance(data["vulnerability"]["ref"],
                                                                                        unicode)):
                    if data["vulnerability"]["ref"] != "":
                        data["vulnerability"]["ref"] = data["vulnerability"]["ref"].split(',')
                    else:
                        data["vulnerability"]["ref"] = []
                if "cvss" in data["vulnerability"] and (
                            isinstance(data["vulnerability"]["cvss"], str) or isinstance(data["vulnerability"]["cvss"],
                                                                                         unicode)):
                    if data["vulnerability"]["cvss"] != "":
                        data["vulnerability"]["cvss"] = data["vulnerability"]["cvss"].split(',')
                    else:
                        data["vulnerability"]["cvss"] = []

        else:
            self.serializer_class = HostVulneratbilitySerializer
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        host_vuln_model = serializer.save()

        # detect monitor alert
        SboxSecurityMonitor("VULNERABLITY").monitor(host_vuln_model)
        return JSONResponse(HostVulnerabilityDetailSerializer(host_vuln_model).data, status=status.HTTP_201_CREATED)


# /agents/vulns/pk/
class HostVulnerabilityDetails(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = HostVulnerabilityDetailSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        queryset = HostVulnerabilityModel.objects.filter(pk=pk)
        queryset = queryset.select_related('vulnerability')
        return queryset

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()

        # Update host statistics
        host_statistic = instance.host.statistics
        host_statistic.vulns_count -= 1

        task_statistic = instance.task.statistics
        task_statistic.vulns_count -= 1

        if instance.vulnerability.severity == 0:
            host_statistic.info_count -= 1
            host_statistic.info_count -= 1
        if instance.vulnerability.severity == 1:
            host_statistic.low_count -= 1
            host_statistic.low_count -= 1
        if instance.vulnerability.severity == 2:
            host_statistic.medium_count -= 1
            host_statistic.medium_count -= 1
        if instance.vulnerability.severity == 3:
            host_statistic.high_count -= 1
            host_statistic.high_count -= 1
        if instance.vulnerability.severity == 4:
            host_statistic.critical_count -= 1
            host_statistic.critical_count -= 1

        # re caculator serverty
        if host_statistic.critical_count > 0 or host_statistic.high_count > 0:
            instance.host.severity = 3
        elif host_statistic.medium_count > 0:
            instance.host.severity = 2
        else:
            instance.host.severity = 1

        # re caculator serverty
        if task_statistic.critical_count > 0 or task_statistic.high_count > 0:
            task_statistic.severity = 3
        elif task_statistic.medium_count > 0:
            task_statistic.severity = 2
        else:
            task_statistic.severity = 1

        host_statistic.save()
        task_statistic.save()
        instance.host.save()
        self.perform_destroy(instance)
        return JSONResponse({}, status=status.HTTP_204_NO_CONTENT)


# /vulns
class HostVulnerabilitysListDetails(generics.ListCreateAPIView):
    serializer_class = HostVulnerabilityListDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('host', 'name', 'is_fixed', 'is_ignored', 'plugin', 'port', 'task',)
    # search_fields = ('name', 'port',)

    def get_queryset(self):
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            queryset = HostVulnerabilityModel.objects.select_related('target__owner').all()
        else:
            queryset = HostVulnerabilityModel.objects.select_related('target__owner').filter(
                target__owner=self.request.user)
        queryset = queryset.select_related('vulnerability', 'task', 'target', 'host', 'target__office',
                                           'target__office__unit')

        # # cve search
        # cve_search = self.request.GET.get('cve', None)
        # if cve_search is not None:
        #     queryset = queryset.filter(vulnerability__cve__contains=[cve_search])
        #
        # # tags search
        # tags_search = self.request.GET.get('tags', None)
        # if tags_search is not None:
        #     queryset = queryset.filter(vulnerability__tags__contains=[tags_search])

        # severity search
        severity_search = self.request.GET.get('severity', None)
        if severity_search is not None:
            queryset = queryset.filter(vulnerability__severity__contains=severity_search)

        # host search
        host_search = self.request.GET.get('host', None)
        if host_search is not None:
            queryset = queryset.filter(host=host_search)
            queryset = queryset.order_by('-vulnerability__severity')
        else:
            queryset = queryset.order_by('-id')

        # search field
        search_query = self.request.GET.get('search', None)
        if search_query is not None:
            queryset = queryset.filter(
                Q(task__target_addr__contains=search_query) | Q(target__name__istartswith=search_query) | Q(
                    host__ip_addr__contains=search_query) | Q(vulnerability__cve__iregex=search_query) | Q(
                    vulnerability__tags__iregex=search_query) | Q(name__istartswith=search_query))
        return queryset
