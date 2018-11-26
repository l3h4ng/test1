# Create your views here.
from agents.crawldata.models import CrawlDataModel
from agents.crawldata.serializers import CrawlDataSerializer
from agents.database.models import WebsiteDatabasesModel
from agents.database.serializers import WebsiteDatabaseSerializer
from agents.monitor.models import WebsiteMonitorStatusModel, WebsiteMonitorContentStatusModel, \
    WebsiteSecurityAlertModel, \
    WebsiteMonitorUrl, WebsitePhishingDomainDetectModel, WebsiteBlacklistCheckingModel, WebsiteGoogleHackingDetectModel
from agents.monitor.serializers import WebsiteMonitorContentDetailsSerializer, \
    WebsiteSecurityAlertDetailsSerializer, WebsitePhishingDomainDetectDetailsSerializer, \
    WebsiteBlacklistCheckingDetailsSerializer, WebsiteGoogleHackingDetectWebsiteDetailsSerializer, \
    WebsiteSecurityAlertSerializer, WebsiteMonitorContentHistoryInfoSerializer, \
    WebsiteMonitorContentHistoryInfoSerializer, WebsiteMonitorContentHistoryDetailsSerializer
from agents.server_configurations.models import ServerConfigurationsModel
from agents.server_configurations.serializers import ServerConfigurationsSerializer
from agents.subdomains.models import WebsiteSubdomainsModel
from agents.subdomains.serializers import WebsiteSubdomainsSerializer
from agents.vulns.models import HostVulnerabilityModel
from agents.vulns.serializers import HostVulnerabilityDetailSerializer, HostVulnrabilitiesCreateSerializer
from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from rest_framework import generics
from rest_framework.renderers import JSONRenderer
from rest_framework import status
from agents.hosts.models import HostsModel
from one_auth.authentication import OneTokenAuthentication
from one_users.permissions import IsOneUserAuthenticatedReadOnlyOrScanner
from reports.serializers import GatheringInformationSerializer, HostOfTaskOverviewsSerializer, \
    PentestrationTestingSerializer, VunerabilitiesScanSerializer
from sbox4web.views import JSONResponse
from targets.models import TargetsModel, TasksModel
from units.models import OfficesModel
from agents.monitor.serializers import WebsiteMonitorStatusSerializer

########################################################################################################################
###                                                 HOSTS OVERVIEW                                                   ###
########################################################################################################################
# GET /unit/id/office/id/targets/id/tasks/id/hosts
class HostsOfTaskList(generics.ListAPIView):
    serializer_class = HostOfTaskOverviewsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('task', 'ip_addr', 'severity', 'status', 'device_type',)
    # search_fields = ('task', 'ip_addr',)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

        queryset = HostsModel.objects.select_related('task').filter(task=task)

        queryset = queryset.select_related('statistics')

        # # search filter
        # queryset = queryset.select_related('details')
        #
        # ip_addr_search = self.request.GET.get('ip_addr', None)
        # if ip_addr_search is not None:
        #     queryset = queryset.filter(Q(ip_addr__istartswith=ip_addr_search))
        #
        # os_search = self.request.GET.get('os', None)
        # if os_search is not None:
        #     queryset = queryset.filter(Q(details__os__iregex=os_search))
        #
        # mac_search = self.request.GET.get('mac_addr', None)
        # if mac_search is not None:
        #     queryset = queryset.filter(Q(details__mac_addr__istartswith=mac_search))
        #
        # vuln_search = self.request.GET.get('vuln', None)
        # if vuln_search is not None:
        #     queryset = queryset.prefetch_related('vulns')
        #     queryset = queryset.filter(Q(vulns__name__istartswith=vuln_search))

        # service_search = self.request.GET.get('service', None)
        # if service_search is not None:
        #     queryset = queryset.prefetch_related('services')
        #     queryset = queryset.filter(
        #         Q(services__name__istartswith=service_search) | Q(services__port__contains=service_search))

        vuln_severity_search = self.request.GET.get('vuln_severity', None)
        if vuln_severity_search is not None and vuln_severity_search != '':
            list_severities = vuln_severity_search.split(',')
            queryset = queryset.filter(vulns__vulnerability__severity__in=list_severities)

        abnormal_severity_search = self.request.GET.get('abnormal_severity', None)
        if abnormal_severity_search is not None and abnormal_severity_search != '':
            queryset = queryset.prefetch_related('msecurity', 'msecurity__events')
            list_severities = abnormal_severity_search.split(',')
            queryset = queryset.filter(msecurity__events__severity__in=list_severities)

        # search field
        search_query = self.request.GET.get('search', None)
        if search_query is not None and search_query != "":
            queryset = queryset.select_related('details')
            queryset = queryset.prefetch_related('vulns', 'services', 'vulns__vulnerability', 'sessions', 'msecurity')
            # queryset = queryset.filter(
            #     Q(ip_addr__contains=search_query))
            list_search = search_query.split(',')
            query = Q()
            for seach in list_search:
                query_tem = Q(ip_addr__istartswith=seach) | Q(details__os__iregex=seach) | Q(
                    details__mac_addr__istartswith=seach) | Q(details__hostname__iregex=seach) | Q(
                    services__name__istartswith=seach) | Q(services__port__contains=seach) | Q(
                    msecurity__name__contains=seach) | Q(
                    sessions__name__contains=seach) | Q(sessions__attack_module__contains=seach) | Q(
                    vulns__name__icontains=seach) | Q(vulns__vulnerability__cve__iregex=seach) | Q(
                    vulns__vulnerability__tags__iregex=seach)
                query = query & query_tem
            queryset = queryset.filter(query)

        # Order by
        order_by_search = self.request.GET.get('order_by', None)
        if order_by_search is not None:
            if order_by_search == "ip_addr":
                queryset = queryset.order_by('ip_addr')
            elif order_by_search == "vulns":
                queryset = queryset.order_by('-statistics__critical_count',
                                             '-statistics__high_count',
                                             '-statistics__medium_count',
                                             '-statistics__low_count')
        else:
            # order_by
            queryset = queryset.order_by('-statistics__db_attack_count',
                                         '-statistics__malware_path_count',
                                         '-statistics__critical_count',
                                         '-statistics__high_count',
                                         '-statistics__medium_count',
                                         '-statistics__low_count',
                                         'ip_addr')
        queryset = queryset.distinct()
        return queryset


################################################# HOSTS INFO ###########################################################
# # /unit/id/office/id/targets/id/tasks/id/hosts/pk4
class HostOfTaskDetailsViews(generics.RetrieveAPIView):
    serializer_class = HostOfTaskOverviewsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        self.kwargs['pk'] = pk4
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            queryset = HostsModel.objects.select_related('task').filter(task=task, pk=pk4).order_by('-severity')
            queryset = queryset.select_related('statistics')
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            queryset = HostsModel.objects.select_related('task').filter(task=task, pk=pk4).order_by('-severity')
            queryset = queryset.select_related('statistics')
        return queryset


########################################################################################################################
###                                                 HOSTS DETAILS                                                    ###
########################################################################################################################
# GET /unit/id/office/id/targets/id/tasks/id/hosts/details
class HostsDetailsOfTaskList(generics.ListAPIView):
    serializer_class = GatheringInformationSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('task', 'ip_addr', 'severity', 'status', 'device_type',)
    search_fields = ('ip_addr', 'details__os__contains', 'details__vendor__contains', 'services__port__contains',
                     'services__name__contains',)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']

        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

        queryset = HostsModel.objects.select_related('task').filter(task=task)
        queryset = queryset.select_related('details')
        queryset = queryset.select_related('statistics')
        queryset = queryset.prefetch_related('services')

        # Filter
        os_search = self.request.GET.get('os', None)
        if os_search is not None:
            queryset = queryset.filter(details__os__contains=[os_search])

        vendor_search = self.request.GET.get('vendor', None)
        if vendor_search is not None:
            queryset = queryset.filter(details__vendor__contains=vendor_search)

        port_search = self.request.GET.get('port', None)
        if port_search is not None:
            queryset = queryset.filter(services__port__contains=port_search)

        service_name_search = self.request.GET.get('service_name', None)
        if service_name_search is not None:
            queryset = queryset.filter(services__name__contains=service_name_search)

        order_by_search = self.request.GET.get('order_by', None)
        if order_by_search is not None:
            if order_by_search == "ip_addr":
                queryset = queryset.order_by('ip_addr')
            elif order_by_search == "vulns":
                queryset = queryset.order_by('-statistics__critical_count',
                                             '-statistics__high_count',
                                             '-statistics__medium_count',
                                             '-statistics__low_count')
        else:
            # order_by
            queryset = queryset.order_by('-statistics__critical_count',
                                         '-statistics__high_count',
                                         '-statistics__medium_count',
                                         '-statistics__low_count',
                                         'ip_addr')

        return queryset


################################################# HOSTS INFO ###########################################################
# # /unit/id/office/id/targets/id/tasks/id/hosts/pk4/details
class HostDetailsOfTaskViews(generics.RetrieveAPIView):
    serializer_class = GatheringInformationSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        self.kwargs['pk'] = pk4
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            queryset = HostsModel.objects.select_related('task').filter(task=task, pk=pk4)
            queryset = queryset.select_related('details')
            queryset = queryset.select_related('statistics')
            queryset = queryset.prefetch_related('services')
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            queryset = HostsModel.objects.select_related('task').filter(task=task, pk=pk4)
            queryset = queryset.select_related('details')
            queryset = queryset.select_related('statistics')
            queryset = queryset.prefetch_related('services')
        return queryset


########################################################################################################################
###                                                 HOSTS SESSION                                                    ###
########################################################################################################################
# GET /unit/id/office/id/targets/id/tasks/id/sessions
class HostsSesionOfTaskList(generics.ListAPIView):
    serializer_class = PentestrationTestingSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('task', 'ip_addr', 'severity', 'status', 'device_type',)
    search_fields = ('task', 'ip_addr',)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            queryset = HostsModel.objects.select_related('task').filter(task=task)
            queryset = queryset.select_related('statistics')
            queryset = queryset.prefetch_related('sessions', 'sessions__vulnerability')
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            queryset = HostsModel.objects.select_related('task').filter(task=task)
            queryset = queryset.select_related('statistics')
            queryset = queryset.prefetch_related('sessions', 'sessions__vulnerability')

        # order_by
        order_by_search = self.request.GET.get('order_by', None)
        if order_by_search is not None:
            if order_by_search == "ip_addr":
                queryset = queryset.order_by('ip_addr')
            elif order_by_search == "vulns":
                queryset = queryset.order_by('-statistics__critical_count',
                                             '-statistics__high_count',
                                             '-statistics__medium_count',
                                             '-statistics__low_count')
        else:
            # order_by
            queryset = queryset.order_by('-statistics__critical_count',
                                         '-statistics__high_count',
                                         '-statistics__medium_count',
                                         '-statistics__low_count',
                                         'ip_addr')
        return queryset


################################################# HOSTS INFO ###########################################################
# # /unit/id/office/id/targets/id/tasks/id/hosts/pk4/sessions
class HostSessionDetailsOfTaskViews(generics.RetrieveAPIView):
    serializer_class = PentestrationTestingSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        self.kwargs['pk'] = pk4
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            queryset = HostsModel.objects.select_related('task').filter(task=task, pk=pk4).order_by('-severity')
            queryset = queryset.select_related('statistics')
            queryset = queryset.prefetch_related('sessions', 'sessions__vulnerability')
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            queryset = HostsModel.objects.select_related('task').filter(task=task, pk=pk4).order_by('-severity')
            queryset = queryset.select_related('statistics')
            queryset = queryset.prefetch_related('sessions', 'sessions__vulnerability')
        return queryset


########################################################################################################################
###                                                 HOSTS VULNERABILITY                                              ###
########################################################################################################################
# GET /unit/id/office/id/targets/id/tasks/id/sessions
class HostsVulnerabilitiesOfTaskList(generics.ListAPIView):
    serializer_class = VunerabilitiesScanSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('task', 'ip_addr', 'severity', 'status', 'device_type',)
    search_fields = ('task', 'ip_addr',)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            queryset = HostsModel.objects.select_related('task').filter(task=task).order_by('-severity')
            queryset = queryset.select_related('statistics')
            queryset = queryset.prefetch_related('vulns', 'vulns__vulnerability')
        else:
            target = TargetsModel.objects.select_related('owner').select_related('office').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            queryset = HostsModel.objects.select_related('task').filter(task=task).order_by('-severity')
            queryset = queryset.select_related('statistics')
            queryset = queryset.prefetch_related('vulns', 'vulns__vulnerability')

        # order_by
        queryset = queryset.order_by('-statistics__critical_count',
                                     '-statistics__high_count',
                                     '-statistics__medium_count',
                                     '-statistics__low_count',
                                     'ip_addr')
        return queryset


################################################# HOSTS INFO ###########################################################
# # /unit/id/office/id/targets/id/tasks/id/hosts/pk4/sessions
class HostVulnerabilitiesDetailsOfTaskViews2(generics.RetrieveAPIView):
    serializer_class = HostOfTaskOverviewsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        self.kwargs['pk'] = pk4
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            queryset = HostsModel.objects.select_related('task').filter(task=task, pk=pk4).order_by('-severity')
            queryset = queryset.select_related('statistics')
            # queryset = queryset.prefetch_related('vulns', 'vulns__vulnerability')
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            queryset = HostsModel.objects.select_related('task').filter(task=task, pk=pk4).order_by('-severity')
            queryset = queryset.select_related('statistics')
            # queryset = queryset.prefetch_related('vulns', 'vulns__vulnerability')
        return queryset

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        limit = request.GET.get('limit', None)
        offset = request.GET.get('offset', 0)
        severity = request.GET.get('severity', "")
        if severity is None or severity == "":
            if limit is not None:
                host_vulns = HostVulnerabilityModel.objects.filter(host=instance).order_by("name")[
                             int(offset):int(offset) + int(limit)]
            else:
                host_vulns = HostVulnerabilityModel.objects.filter(host=instance).order_by("name")
        else:
            list_severities = severity.split(',')
            if limit is not None:
                host_vulns = HostVulnerabilityModel.objects.select_related('vulnerability').filter(host=instance,
                                                                                                   vulnerability__severity__in=list_severities).order_by(
                    "-vulnerability__severity", "name")[int(offset):int(offset) + int(limit)]
            else:

                host_vulns = HostVulnerabilityModel.objects.select_related('vulnerability').filter(host=instance,
                                                                                                   vulnerability__severity__in=list_severities).order_by(
                    "-vulnerability__severity", "name")
        host_vulns_data = HostVulnerabilityDetailSerializer(host_vulns, many=True).data
        host_data = HostOfTaskOverviewsSerializer(instance).data
        host_data["vulns"] = host_vulns_data
        return JSONResponse(host_data, status=status.HTTP_200_OK)


# /unit/id/office/id/targets/id/tasks/id/hosts/pk4/vulns
class HostVulnerabilitiesDetailsOfTaskViews(generics.ListAPIView):
    serializer_class = HostVulnrabilitiesCreateSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('host', 'name',)
    # search_fields = ('name',)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        self.kwargs['pk'] = pk4
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.select_related('task').filter(task=task, pk=pk4)
            queryset = HostVulnerabilityModel.objects.select_related('vulnerability').filter(host=host).order_by(
                '-vulnerability__severity')
            # queryset = queryset.prefetch_related('vulns', 'vulns__vulnerability')
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.select_related('task').filter(task=task, pk=pk4)
            queryset = HostVulnerabilityModel.objects.select_related('vulnerability').filter(host=host).order_by(
                '-vulnerability__severity')

        severity_search = self.request.GET.get('severity', None)
        if severity_search is not None and severity_search != '':
            list_severities = severity_search.split(',')
            queryset = queryset.filter(vulnerability__severity__in=list_severities)

        # search field
        search_query = self.request.GET.get('search', None)
        if search_query is not None and search_query != "":
            queryset = queryset.select_related('host')
            queryset1 = queryset
            query = Q()
            list_search = search_query.split(',')
            for seach in list_search:
                query_temp = Q(name__icontains=seach) | Q(target__name__istartswith=seach) | Q(
                    host__ip_addr__istartswith=seach) | Q(vulnerability__cve__iregex=seach) | Q(
                    vulnerability__tags__iregex=seach) | Q(name__istartswith=seach)
                query = query & query_temp
            queryset = queryset.filter(query)
            if queryset.count() == 0:
                queryset = queryset1
        return queryset

########################################################################################################################
###                                                 WEBSITE CRAWLER                                                  ###
########################################################################################################################
# GET /unit/id/office/id/targets/id/tasks/id/hosts/crawlerdata
class WebsiteCrawlerOfTaskList2(generics.ListAPIView):
    serializer_class = CrawlDataSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('task', 'ip_addr', 'severity', 'status', 'device_type',)
    search_fields = ('task', 'ip_addr',)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)
        else:
            target = TargetsModel.objects.select_related('owner').select_related('office').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

        queryset = HostsModel.objects.select_related('task').filter(task=task).order_by('-severity')
        queryset = queryset.select_related('statistics')
        queryset = queryset.prefetch_related('crawls')

        # order_by
        queryset = queryset.order_by('-statistics__critical_count',
                                     '-statistics__high_count',
                                     '-statistics__medium_count',
                                     '-statistics__low_count',
                                     'ip_addr')
        return queryset

    def list(self, request, *args, **kwargs):
        limit = request.GET.get('limit', None)
        offset = request.GET.get('offset', 0)
        hosts = self.get_queryset()
        website_crawlers = []
        for host in hosts:
            if limit is not None:
                crawlers = CrawlDataModel.objects.filter(website=host).order_by("path")[
                           int(offset):int(offset) + int(limit)]
            else:
                crawlers = CrawlDataModel.objects.filter(website=host).order_by("path")
            crawlers_data = CrawlDataSerializer(crawlers, many=True).data
            host_data = HostOfTaskOverviewsSerializer(host).data
            host_data["crawls"] = crawlers_data
            website_crawlers.append(host_data)
        return JSONResponse(website_crawlers, status=status.HTTP_200_OK)


class WebsiteCrawlerOfTaskList(generics.ListAPIView):
    serializer_class = CrawlDataSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('website', 'path', 'name', 'security_level',)
    search_fields = ('path', 'name',)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)
        else:
            target = TargetsModel.objects.select_related('owner').select_related('office').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

        # host =  HostsModel.objects.select_related('task').filter(task=task).order_by('-severity')
        queryset = CrawlDataModel.objects.select_related('website', 'website__task').filter(website__task=task)

        # order_by
        filter_search = self.request.GET.get('order', None)
        if filter_search is not None and filter_search != '':
            if filter_search == "-security_level":
                queryset = queryset.order_by('-security_level', 'name')
            elif filter_search == "security_level":
                queryset = queryset.order_by('security_level', 'name')
            elif filter_search == "name":
                queryset = queryset.order_by('name',
                                             '-security_level')
            elif filter_search == "-name":
                queryset = queryset.order_by('-name',
                                             '-security_level')
            else:
                queryset = queryset.order_by('-security_level',
                                             'name')
        else:
            queryset = queryset.order_by('-security_level',
                                         'name')
        return queryset

    # def list(self, request, *args, **kwargs):
    #     limit = request.GET.get('limit', None)
    #     offset = request.GET.get('offset', 0)
    #     hosts = self.get_queryset()
    #     website_crawlers = []
    #     for host in hosts:
    #         if limit is not None:
    #             crawlers = CrawlDataModel.objects.filter(website=host).order_by("path")[
    #                        int(offset):int(offset) + int(limit)]
    #         else:
    #             crawlers = CrawlDataModel.objects.filter(website=host).order_by("path")
    #         crawlers_data = CrawlDataSerializer(crawlers, many=True).data
    #         host_data = HostOfTaskOverviewsSerializer(host).data
    #         host_data["crawls"] = crawlers_data
    #         website_crawlers.append(host_data)
    #     return JSONResponse(website_crawlers, status=status.HTTP_200_OK)

################################################# HOSTS INFO ###########################################################
# # /unit/id/office/id/targets/id/tasks/id/hosts/pk4/crawlerdata
class WebsiteCrawlerDetailsOfTaskViews2(generics.RetrieveAPIView):
    serializer_class = CrawlDataSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        self.kwargs['pk'] = pk4
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            queryset = HostsModel.objects.select_related('task').filter(task=task, pk=pk4)
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            queryset = HostsModel.objects.select_related('task').filter(task=task, pk=pk4)
        return queryset

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        limit = request.GET.get('limit', None)
        offset = request.GET.get('offset', 0)
        if limit is not None:
            crawlers = CrawlDataModel.objects.filter(website=instance).order_by("-security_level", "path")[
                       int(offset):int(offset) + int(limit)]
        else:
            crawlers = CrawlDataModel.objects.filter(website=instance).order_by("-security_level", "path")
        crawlers_data = CrawlDataSerializer(crawlers, many=True).data
        host_data = HostOfTaskOverviewsSerializer(instance).data
        host_data["crawls"] = crawlers_data
        return JSONResponse(host_data, status=status.HTTP_200_OK)

# /unit/id/office/id/targets/id/tasks/id/hosts/pk4/crawlerdata
class WebsiteCrawlerDetailsOfTaskViews(generics.ListAPIView):
    serializer_class = CrawlDataSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('website', 'security_level', 'loc_type',)
    # search_fields = ('path', 'name',)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        self.kwargs['pk'] = pk4
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)
        else:
            target = TargetsModel.objects.select_related('owner').select_related('office').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

        host = HostsModel.objects.select_related('task').get(task=task, pk=pk4)
        queryset = CrawlDataModel.objects.select_related('website', 'website__task').filter(website=host)

        # search field
        search_query = self.request.GET.get('search', None)
        if search_query is not None and search_query != "":
            list_search = search_query.split(',')
            query = Q()
            for seach in list_search:
                query_tem = Q(website__ip_addr__istartswith=seach) | Q(path__contains=seach) | Q(name__contains=seach)
                query = query & query_tem
            queryset = queryset.filter(query)

        # order_by
        filter_search = self.request.GET.get('order', None)
        if filter_search is not None and filter_search != '':
            if filter_search == "-security_level":
                queryset = queryset.order_by('-security_level', 'name')
            elif filter_search == "security_level":
                queryset = queryset.order_by('security_level', 'name')
            elif filter_search == "name":
                queryset = queryset.order_by('name',
                                             '-security_level')
            elif filter_search == "-name":
                queryset = queryset.order_by('-name',
                                             '-security_level')
            else:
                queryset = queryset.order_by('-security_level',
                                             'name')
        else:
            queryset = queryset.order_by('-security_level',
                                         'name')
        return queryset


# ################################################# HOSTS INFO ###########################################################
# # # /unit/id/office/id/targets/id/tasks/id/hosts/pk4/crawlerdata
# class WebsiteCrawlerDetailsOfTaskViews(generics.ListAPIView):
#     serializer_class = CrawlDataSerializer
#     authentication_classes = (OneTokenAuthentication,)
#     permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
#     renderer_classes = (JSONRenderer,)
#
#     def get_queryset(self):
#         pk = self.kwargs['pk']
#         pk1 = self.kwargs['pk1']
#         pk2 = self.kwargs['pk2']
#         pk3 = self.kwargs['pk3']
#         pk4 = self.kwargs['pk4']
#         self.kwargs['pk'] = pk4
#         office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)
#
#         if self.request.user.is_smod == 1 or self.request.user.is_superuser:
#             target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
#             task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)
#
#             host = HostsModel.objects.select_related('task').filter(task=task, pk=pk4)
#         else:
#             target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
#                                                                                                owner=self.request.user)
#             task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)
#
#             host = HostsModel.objects.select_related('task').filter(task=task, pk=pk4)
#         queryset = CrawlDataModel.objects.filter(website=host)
#         return queryset

# GET /unit/id/office/id/targets/id/tasks/id/hosts/subdomains
class WebsiteSubdomainsOfTaskList(generics.ListAPIView):
    serializer_class = CrawlDataSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('ip_addr',)
    search_fields = ('ip_addr',)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)
        else:
            target = TargetsModel.objects.select_related('owner').select_related('office').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

        queryset = HostsModel.objects.select_related('task').filter(task=task).order_by('-severity')
        queryset = queryset.select_related('statistics')
        queryset = queryset.prefetch_related('subdomains')

        # order_by
        queryset = queryset.order_by('-statistics__critical_count',
                                     '-statistics__high_count',
                                     '-statistics__medium_count',
                                     '-statistics__low_count',
                                     'ip_addr')
        return queryset

    def list(self, request, *args, **kwargs):
        limit = request.GET.get('limit', None)
        offset = request.GET.get('offset', 0)
        hosts = self.get_queryset()
        website_subdomains = []
        for host in hosts:
            if limit is not None:
                subdomains = WebsiteSubdomainsModel.objects.filter(website=host).order_by("subdomain")[
                             int(offset):int(offset) + int(limit)]
            else:
                subdomains = WebsiteSubdomainsModel.objects.filter(website=host).order_by("subdomain")
            subdomains_data = WebsiteSubdomainsSerializer(subdomains, many=True).data
            host_data = HostOfTaskOverviewsSerializer(host).data
            host_data["subdomains"] = subdomains_data
            website_subdomains.append(host_data)
        return JSONResponse(website_subdomains, status=status.HTTP_200_OK)


# subdomain
class WebsiteSubdomainsDetailsOfTaskViews(generics.RetrieveAPIView):
    serializer_class = WebsiteSubdomainsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        self.kwargs['pk'] = pk4
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            queryset = HostsModel.objects.select_related('task').filter(task=task, pk=pk4)
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            queryset = HostsModel.objects.select_related('task').filter(task=task, pk=pk4)
        return queryset

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        limit = request.GET.get('limit', None)
        offset = request.GET.get('offset', 0)
        if limit is not None:
            subdomains = WebsiteSubdomainsModel.objects.filter(website=instance)[int(offset):int(offset) + int(limit)]
        else:
            subdomains = WebsiteSubdomainsModel.objects.filter(website=instance).order_by("subdomain")
        crawlers_data = WebsiteSubdomainsSerializer(subdomains, many=True).data
        host_data = HostOfTaskOverviewsSerializer(instance).data
        host_data["subdomains"] = crawlers_data
        return JSONResponse(host_data, status=status.HTTP_200_OK)


# PUT /unit/id/office/id/targets/id/tasks/id/hosts/id/subdomains/id/
class WebsiteSubdomainsMonitorTaskViews(generics.RetrieveUpdateAPIView):
    serializer_class = WebsiteSubdomainsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        pk5 = self.kwargs['pk5']
        self.kwargs['pk'] = pk5
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)
            host = HostsModel.objects.filter(task=task, pk=pk4)

            queryset = WebsiteSubdomainsModel.objects.filter(website=host, pk=pk5)
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)
            host = HostsModel.objects.filter(task=task, pk=pk4)

            queryset = WebsiteSubdomainsModel.objects.filter(website=host, pk=pk5)
        return queryset


# GET /unit/id/office/id/targets/id/tasks/id/hosts/databases
class WebsiteDatabasesOfTaskList(generics.ListAPIView):
    serializer_class = WebsiteDatabaseSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('website',)
    search_fields = ('website',)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)
        else:
            target = TargetsModel.objects.select_related('owner').select_related('office').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

        queryset = HostsModel.objects.select_related('task').filter(task=task).order_by('-severity')
        queryset = queryset.select_related('statistics')
        queryset = queryset.prefetch_related('subdomains')

        # order_by
        queryset = queryset.order_by('-statistics__critical_count',
                                     '-statistics__high_count',
                                     '-statistics__medium_count',
                                     '-statistics__low_count',
                                     'ip_addr')
        return queryset

    def list(self, request, *args, **kwargs):
        limit = request.GET.get('limit', None)
        offset = request.GET.get('offset', 0)
        hosts = self.get_queryset()
        website_subdomains = []
        for host in hosts:
            if limit is not None:
                databases = WebsiteDatabasesModel.objects.filter(website=host)[int(offset):int(offset) + int(limit)]
            else:
                databases = WebsiteDatabasesModel.objects.filter(website=host)
            databases_data = WebsiteDatabaseSerializer(databases, many=True).data
            host_data = HostOfTaskOverviewsSerializer(host).data
            host_data["databases"] = databases_data
            website_subdomains.append(host_data)
        return JSONResponse(website_subdomains, status=status.HTTP_200_OK)


# subdomain
class WebsiteDatabasesDetailsOfTaskViews(generics.RetrieveAPIView):
    serializer_class = WebsiteDatabaseSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        self.kwargs['pk'] = pk4
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            queryset = HostsModel.objects.select_related('task').filter(task=task, pk=pk4)
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            queryset = HostsModel.objects.select_related('task').filter(task=task, pk=pk4)
        return queryset

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        limit = request.GET.get('limit', None)
        offset = request.GET.get('offset', 0)
        if limit is not None:
            databases = WebsiteDatabasesModel.objects.filter(website=instance)[int(offset):int(offset) + int(limit)]
        else:
            databases = WebsiteDatabasesModel.objects.filter(website=instance)
        databases_data = WebsiteDatabaseSerializer(databases, many=True).data
        host_data = HostOfTaskOverviewsSerializer(instance).data
        host_data["databases"] = databases_data
        return JSONResponse(host_data, status=status.HTTP_200_OK)


# GET /unit/id/office/id/targets/id/tasks/id/hosts/configvulns
class WebsiteConfigurationsVulnsOfTaskList(generics.ListAPIView):
    serializer_class = ServerConfigurationsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('website',)
    search_fields = ('website',)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)
        else:
            target = TargetsModel.objects.select_related('owner').select_related('office').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

        queryset = HostsModel.objects.select_related('task').filter(task=task).order_by('-severity')
        queryset = queryset.select_related('statistics')
        queryset = queryset.prefetch_related('config_vulns')

        # order_by
        queryset = queryset.order_by('-statistics__critical_count',
                                     '-statistics__high_count',
                                     '-statistics__medium_count',
                                     '-statistics__low_count',
                                     'ip_addr')
        return queryset

    def list(self, request, *args, **kwargs):
        limit = request.GET.get('limit', None)
        offset = request.GET.get('offset', 0)
        hosts = self.get_queryset()
        website_subdomains = []
        for host in hosts:
            if limit is not None:
                configuration_vulns = ServerConfigurationsModel.objects.filter(website=host)[
                                      int(offset):int(offset) + int(limit)]
            else:
                configuration_vulns = ServerConfigurationsModel.objects.filter(website=host)
            config_vulns_data = ServerConfigurationsSerializer(configuration_vulns, many=True).data
            host_data = HostOfTaskOverviewsSerializer(host).data
            host_data["config_vulns"] = config_vulns_data
            website_subdomains.append(host_data)
        return JSONResponse(website_subdomains, status=status.HTTP_200_OK)


# GET /unit/id/office/id/targets/id/tasks/id/hosts/hid/configvulns
class WebsiteConfigurationsVulnsDetailsOfTaskViews(generics.RetrieveAPIView):
    serializer_class = ServerConfigurationsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        self.kwargs['pk'] = pk4
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            queryset = HostsModel.objects.select_related('task').filter(task=task, pk=pk4)
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            queryset = HostsModel.objects.select_related('task').filter(task=task, pk=pk4)
        return queryset

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        limit = request.GET.get('limit', None)
        offset = request.GET.get('offset', 0)
        if limit is not None:
            configuration_vulns = ServerConfigurationsModel.objects.filter(website=instance)[
                                  int(offset):int(offset) + int(limit)]
        else:
            configuration_vulns = ServerConfigurationsModel.objects.filter(website=instance)
        config_vulns_data = ServerConfigurationsSerializer(configuration_vulns, many=True).data
        host_data = HostOfTaskOverviewsSerializer(instance).data
        host_data["config_vulns"] = config_vulns_data
        return JSONResponse(host_data, status=status.HTTP_200_OK)


########################################################################################################################
#####                                            WEBSITE STATUS MONITOR                                            #####
########################################################################################################################
# GET /unit/id/office/id/targets/id/tasks/id/hosts/webstatus
class StatusOfWebsiteHistory(generics.ListAPIView):
    serializer_class = WebsiteMonitorStatusSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('website',)
    search_fields = ('website',)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        self.kwargs['pk'] = pk4
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.filter(task=task, pk=pk4)
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.filter(task=task, pk=pk4)

        queryset = WebsiteMonitorStatusModel.objects.all().order_by('-id')
        queryset = queryset.filter(website=host)[:20]
        return queryset


# GET /unit/id/office/id/targets/id/tasks/id/hosts/hid/webstatus/wstatusid
class StatusOfWebsiteViews(generics.RetrieveAPIView):
    serializer_class = WebsiteMonitorStatusSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        pk5 = self.kwargs['pk5']
        self.kwargs['pk'] = pk5
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.filter(task=task, pk=pk4)
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.filter(task=task, pk=pk4)

        queryset = WebsiteMonitorStatusModel.objects.filter(website=host, id=pk5).order_by('-id')
        return queryset


# GET /unit/id/office/id/targets/id/tasks/id/hosts/hid/webstatus
class LastStatusOfWebsiteViews(generics.RetrieveAPIView):
    serializer_class = WebsiteMonitorStatusSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        self.kwargs['pk'] = pk4
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.filter(task=task, pk=pk4)
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.filter(task=task, pk=pk4)

        queryset = WebsiteMonitorStatusModel.objects.filter(website=host).order_by('-id').first()
        return queryset

    def get_object(self):
        return self.get_queryset()


########################################################################################################################
#####                                            WEBSITE PHISHING DOMAIN ALERT                                     #####
########################################################################################################################
# GET /unit/id/office/id/targets/id/tasks/id/hosts/mphishing
class WebsitePhishingDomainList(generics.ListAPIView):
    serializer_class = WebsitePhishingDomainDetectDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('website', 'domain', 'is_exits', 'ip_addr',)
    search_fields = ('domain', 'ip_addr',)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        self.kwargs['pk'] = pk4
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.filter(task=task, pk=pk4)
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.filter(task=task, pk=pk4)

        queryset = WebsitePhishingDomainDetectModel.objects.filter(website=host).order_by('-security_level', '-id')
        return queryset

    def list(self, request, *args, **kwargs):
        host_id = self.kwargs['pk4']
        queryset = self.filter_queryset(self.get_queryset())
        serializer = self.get_serializer(queryset, many=True)
        data = {
            "total_domains": WebsitePhishingDomainDetectModel.objects.filter(website_id=host_id).count(),
            "phishing_domains": WebsitePhishingDomainDetectModel.objects.filter(website_id=host_id,
                                                                                is_exits=True, security_level__gt=0).count(),
            "details": serializer.data
        }
        return JSONResponse(data, status=status.HTTP_200_OK)


# GET /unit/id/office/id/targets/id/tasks/id/hosts/hid/mphishing/mphishingid
class WebsitePhishingDomainViews(generics.RetrieveAPIView):
    serializer_class = WebsitePhishingDomainDetectDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        pk5 = self.kwargs['pk5']
        self.kwargs['pk'] = pk5
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.filter(task=task, pk=pk4)
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.filter(task=task, pk=pk4)

        queryset = WebsitePhishingDomainDetectModel.objects.filter(website=host, id=pk5).order_by('-id')
        return queryset


########################################################################################################################
#####                                            WEBSITE BLACKLIST MONITOR                                         #####
########################################################################################################################
# GET /unit/id/office/id/targets/id/tasks/id/hosts/mblacklist
class WebsiteBlacklistAlertList(generics.ListAPIView):
    serializer_class = WebsiteBlacklistCheckingDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('website', 'type', 'result',)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        self.kwargs['pk'] = pk4
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.filter(task=task, pk=pk4)
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.filter(task=task, pk=pk4)

        queryset = WebsiteBlacklistCheckingModel.objects.filter(website=host).order_by('-id')
        return queryset


# GET /unit/id/office/id/targets/id/tasks/id/hosts/hid/mblacklist/mblacklistid
class WebsiteBlacklistAlertViews(generics.RetrieveAPIView):
    serializer_class = WebsiteBlacklistCheckingDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        pk5 = self.kwargs['pk5']
        self.kwargs['pk'] = pk5
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.filter(task=task, pk=pk4)
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.filter(task=task, pk=pk4)

        queryset = WebsiteBlacklistCheckingModel.objects.filter(website=host, id=pk5).order_by('-id')
        return queryset


########################################################################################################################
#####                                            WEBSITE GHDB ALERT                                                #####
########################################################################################################################
# GET /unit/id/office/id/targets/id/tasks/id/hosts/mghdb
class WebsiteGHDBAlertList(generics.ListAPIView):
    serializer_class = WebsiteGoogleHackingDetectWebsiteDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('website', 'keyword',)
    search_fields = ('link')

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        self.kwargs['pk'] = pk4
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.filter(task=task, pk=pk4)
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.filter(task=task, pk=pk4)

        queryset = WebsiteGoogleHackingDetectModel.objects.filter(website=host).order_by('-id')
        return queryset


# GET /unit/id/office/id/targets/id/tasks/id/hosts/hid/mghdb/mghdbid
class WebsiteGHDBAlertViews(generics.RetrieveAPIView):
    serializer_class = WebsiteGoogleHackingDetectWebsiteDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        pk5 = self.kwargs['pk5']
        self.kwargs['pk'] = pk5
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.filter(task=task, pk=pk4)
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.filter(task=task, pk=pk4)

        queryset = WebsiteGoogleHackingDetectModel.objects.filter(website=host, id=pk5).order_by('-id')
        return queryset


########################################################################################################################
#####                                            WEBSITE CONTENT MONITOR                                           #####
########################################################################################################################
# GET /unit/id/office/id/targets/id/tasks/id/hosts/hid/mcontents
class LastContentsMonitorOfWebsiteList(generics.RetrieveAPIView):
    serializer_class = WebsiteMonitorContentHistoryDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('url_monitor',)
    search_fields = ('url_monitor',)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.filter(task=task, pk=pk4)
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.filter(task=task, pk=pk4)
        list_url_monitor = WebsiteMonitorUrl.objects.filter(target=target).values_list('id')
        queryset = WebsiteMonitorContentStatusModel.objects.filter(url_monitor_id__in=list(list_url_monitor)).order_by(
            '-id').first()
        return queryset

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_queryset()
        serializer = self.get_serializer(instance)
        return JSONResponse(serializer.data, status=status.HTTP_200_OK)


# GET /unit/id/office/id/targets/id/tasks/id/hosts/hid/mcontents/mcontents_id
class ContentsMonitorOfWebsiteViews(generics.RetrieveAPIView):
    serializer_class = WebsiteMonitorContentHistoryDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        pk5 = self.kwargs['pk5']
        self.kwargs['pk'] = pk5
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.filter(task=task, pk=pk4)
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.filter(task=task, pk=pk4)
        list_url_monitor = WebsiteMonitorUrl.objects.filter(target=target).values_list('id')
        queryset = WebsiteMonitorContentStatusModel.objects.filter(url_monitor_id__in=list(list_url_monitor), id=pk5)
        return queryset


# GET /unit/id/office/id/targets/id/tasks/id/hosts/hid/mcontents/history
class ContentsMonitorOfWebsiteHistoryViews(generics.ListAPIView):
    serializer_class = WebsiteMonitorContentHistoryInfoSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        self.kwargs['pk'] = pk4
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.get(task=task, pk=pk4)
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            host = HostsModel.objects.get(task=task, pk=pk4)

        list_url_monitor = WebsiteMonitorUrl.objects.filter(target=target, url=host.ip_addr,
                                                            path=host.ip_addr).values_list('id')
        queryset = WebsiteMonitorContentStatusModel.objects.filter(url_monitor_id__in=list(list_url_monitor)).order_by('-monitor_time')
        return queryset


# GET /unit/pk/office/pk1/targets/pk2/tasks/pk3/hosts/mcontents
class ContentsMonitorOfTaskList(generics.ListAPIView):
    serializer_class = WebsiteMonitorContentDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        self.kwargs['pk'] = pk3
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

        url_monitor = WebsiteMonitorUrl.objects.filter(target=target)
        queryset = WebsiteMonitorContentStatusModel.objects.filter(url_monitor=url_monitor).order_by('-id')
        return queryset


########################################################################################################################
#####                                            WEBSITE SECURITY ALERT                                            #####
########################################################################################################################
# /unit/id/office/id/targets/id/tasks/id/hosts/msecurity
class WebsiteSecurityAlertOfTaskListView(generics.ListAPIView):
    serializer_class = WebsiteSecurityAlertSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('type','host',)
    # search_fields = ('host',)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            queryset = WebsiteSecurityAlertModel.objects.select_related('events', 'host', 'host__task').filter(
                host__task=task)
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)
            queryset = WebsiteSecurityAlertModel.objects.select_related('events', 'host', 'host__task').filter(
                host__task=task)

        # severity search
        severity_search = self.request.GET.get('severity', None)
        if severity_search is not None and severity_search != '':
            list_severities = severity_search.split(',')
            queryset = queryset.filter(events__severity__in=list_severities)

        # # # type search
        # type_search = self.request.GET.get('type', None)
        # if type_search is not None and type_search != '':
        #     queryset = queryset.filter(type=type_search)

        # alert search
        alert_search = self.request.GET.get('alert', None)
        if alert_search is not None and alert_search != '':
            queryset = queryset.filter(events__alert=alert_search)

        # search field
        search_query = self.request.GET.get('search', None)
        if search_query is not None and search_query != "":
            list_search = search_query.split(',')
            query = Q()
            for seach in list_search:
                query_tem = Q(host__ip_addr__istartswith=seach) | Q(
                    description__icontains=seach) | Q(name__icontains=seach)
                query = query & query_tem
            queryset = queryset.filter(query)

        # order_by search
        filter_search = self.request.GET.get('filter', None)
        if filter_search is not None and filter_search != '':
            if filter_search == "host":
                queryset = queryset.order_by('host',
                                             '-events__severity')
            elif filter_search == "severity":
                queryset = queryset.order_by('events__severity',
                                             'host')
            elif filter_search == "-severity":
                queryset = queryset.order_by('-events__severity',
                                             'host')
            else:
                queryset = queryset.order_by('-events__severity',
                                         '-id')
        else:
            queryset = queryset.order_by('-events__severity',
                                         '-id')
        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = WebsiteSecurityAlertDetailsSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = WebsiteSecurityAlertDetailsSerializer(queryset, many=True)
        return JSONResponse(serializer.data, status=status.HTTP_200_OK)
        # return JSONResponse({"1": _("Detect new device in your network.")}, status=status.HTTP_200_OK)


# /unit/id/office/id/targets/id/tasks/id/hosts/pk4/msecurity
class WebsiteSecurityAlertOfHostListView(generics.ListAPIView):
    serializer_class = WebsiteSecurityAlertSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('host', 'events', 'resolve', 'type',)
    # search_fields = ('host',)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        self.kwargs['pk'] = pk4
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)
            host = HostsModel.objects.select_related('task').filter(task=task, pk=pk4)
            queryset = WebsiteSecurityAlertModel.objects.select_related('events', 'host').filter(host=host)
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)
            host = HostsModel.objects.select_related('task').filter(task=task, pk=pk4)
            queryset = WebsiteSecurityAlertModel.objects.select_related('events', 'host').filter(host=host)

        # severity search
        severity_search = self.request.GET.get('severity', None)
        if severity_search is not None and severity_search != '':
            list_severities = severity_search.split(',')
            queryset = queryset.filter(events__severity__in=list_severities)

        # # type search
        # type_search = self.request.GET.get('type', None)
        # if type_search is not None and type_search != '':
        #     queryset = queryset.filter(events__type=type_search)

        # alert search
        alert_search = self.request.GET.get('alert', None)
        if alert_search is not None and alert_search != '':
            queryset = queryset.filter(events__alert=alert_search)

        # search field
        search_query = self.request.GET.get('search', None)
        if search_query is not None and search_query != "":
            list_search = search_query.split(',')
            query = Q()
            for seach in list_search:
                query_tem = Q(host__ip_addr__istartswith=seach) | Q(
                    description__icontains=seach) | Q(name__icontains=seach)
                query = query & query_tem
            queryset = queryset.filter(query)

        # order_by search
        filter_search = self.request.GET.get('filter', None)
        if filter_search is not None and filter_search != '':
            if filter_search == "host":
                queryset = queryset.order_by('host',
                                             '-events__severity')
            elif filter_search == "severity":
                queryset = queryset.order_by('-events__severity',
                                             'host')
            else:
                queryset = queryset.order_by('-events__severity',
                                         '-id')
        else:
            queryset = queryset.order_by('-events__severity',
                                         '-id')
        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = WebsiteSecurityAlertDetailsSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = WebsiteSecurityAlertDetailsSerializer(queryset, many=True)
        return JSONResponse(serializer.data, status=status.HTTP_200_OK)


# /unit/id/office/id/targets/id/tasks/id/hosts/pk4/msecurity/pk5
class WebsiteSecurityAlertDetailsOfHostView(generics.RetrieveAPIView):
    serializer_class = WebsiteSecurityAlertDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        pk5 = self.kwargs['pk5']
        self.kwargs['pk'] = pk5
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)
            host = HostsModel.objects.select_related('task').filter(task=task, pk=pk4)
            queryset = WebsiteSecurityAlertModel.objects.select_related('host').filter(host=host, pk=pk5).order_by(
                '-severity', 'events')
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)
            host = HostsModel.objects.select_related('task').filter(task=task, pk=pk4)
            queryset = WebsiteSecurityAlertModel.objects.select_related('host').filter(host=host, pk=pk5).order_by(
                '-events__severity', 'events')
        return queryset


########################################################################################################################
#####                                            WEBSITE ABNORMAL EVENTS                                           #####
########################################################################################################################
# /unit/id/office/id/targets/id/tasks/id/msecurity
class WebsiteAbnormalEventsOfTaskListView(generics.ListAPIView):
    serializer_class = WebsiteSecurityAlertSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('host', 'events', 'resolve',)
    search_fields = ('host',)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)

            queryset = WebsiteSecurityAlertModel.objects.select_related('events', 'host', 'host__task').filter(
                host__task=task, type='ABNORMAL').filter(type='ABNORMAL').order_by('-events__severity', 'events')
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)
            queryset = WebsiteSecurityAlertModel.objects.select_related('events', 'host', 'host__task').filter(
                host__task=task, type='ABNORMAL').order_by('-events__severity', 'events')

        # severity search
        severity_search = self.request.GET.get('severity', None)
        if severity_search is not None and severity_search != '':
            list_severities = severity_search.split(',')
            queryset = queryset.filter(events__severity__in=list_severities)

        # type search
        # type_search = self.request.GET.get('type', None)
        # if type_search is not None and type_search != '':
        #     queryset = queryset.filter(events__type=type_search)

        # alert search
        alert_search = self.request.GET.get('alert', None)
        if alert_search is not None and alert_search != '':
            queryset = queryset.filter(events__alert=alert_search)

        # order_by search
        filter_search = self.request.GET.get('filter', None)
        if filter_search is not None and filter_search != '':
            if filter_search == "host":
                queryset = queryset.order_by('host',
                                             '-events__severity')
            elif filter_search == "severity":
                queryset = queryset.order_by('-events__severity',
                                             'host')
            else:
                queryset = queryset.order_by('host',
                                             '-events__severity',
                                             'events')

        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = WebsiteSecurityAlertDetailsSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = WebsiteSecurityAlertDetailsSerializer(queryset, many=True)
        return JSONResponse(serializer.data, status=status.HTTP_200_OK)
        # return JSONResponse({"1": _("Detect new device in your network.")}, status=status.HTTP_200_OK)


# /unit/id/office/id/targets/id/tasks/id/hosts/pk4/msecurity
class WebsiteAbnormalEventsOfHostListView(generics.ListAPIView):
    serializer_class = WebsiteSecurityAlertSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('host', 'events', 'resolve',)
    # search_fields = ('host',)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        self.kwargs['pk'] = pk4
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)
            host = HostsModel.objects.select_related('task').filter(task=task, pk=pk4)
            queryset = WebsiteSecurityAlertModel.objects.select_related('events', 'host').filter(host=host, type='ABNORMAL')
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)
            host = HostsModel.objects.select_related('task').filter(task=task, pk=pk4)
            queryset = WebsiteSecurityAlertModel.objects.select_related('events', 'host').filter(host=host, type='ABNORMAL')

        # severity search
        severity_search = self.request.GET.get('severity', None)
        if severity_search is not None and severity_search != '':
            list_severities = severity_search.split(',')
            queryset = queryset.filter(events__severity__in=list_severities)

        # type search
        # type_search = self.request.GET.get('type', None)
        # if type_search is not None and type_search != '':
        #     queryset = queryset.filter(events__type=type_search)

        # alert search
        alert_search = self.request.GET.get('alert', None)
        if alert_search is not None and alert_search != '':
            queryset = queryset.filter(events__alert=alert_search)

        # search field
        search_query = self.request.GET.get('search', None)
        if search_query is not None and search_query != "":
            list_search = search_query.split(',')
            query = Q()
            for seach in list_search:
                query_tem = Q(host__ip_addr__istartswith=seach) | Q(
                    description__icontains=seach) | Q(name__icontains=seach)
                query = query & query_tem
            queryset = queryset.filter(query)

        # order_by search
        filter_search = self.request.GET.get('filter', None)
        if filter_search is not None and filter_search != '':
            if filter_search == "host":
                queryset = queryset.order_by('host',
                                             '-events__severity')
            elif filter_search == "severity":
                queryset = queryset.order_by('-events__severity',
                                             'host')
            else:
                queryset = queryset.order_by('-events__severity',
                                             'host',
                                             'events')
        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = WebsiteSecurityAlertDetailsSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = WebsiteSecurityAlertDetailsSerializer(queryset, many=True)
        return JSONResponse(serializer.data, status=status.HTTP_200_OK)


# /unit/id/office/id/targets/id/tasks/id/hosts/pk4/msecurity/pk5
class WebsiteAbnormalEventsDetailsOfHostView(generics.RetrieveAPIView):
    serializer_class = WebsiteSecurityAlertDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        pk4 = self.kwargs['pk4']
        pk5 = self.kwargs['pk5']
        self.kwargs['pk'] = pk5
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.select_related('office').get(pk=pk2, office=office)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)
            host = HostsModel.objects.select_related('task').filter(task=task, pk=pk4)
            queryset = WebsiteSecurityAlertModel.objects.select_related('host').filter(host=host, type='ABNORMAL', pk=pk5).order_by(
                '-severity', 'events')
        else:
            target = TargetsModel.objects.select_related('office').select_related('owner').get(pk=pk2, office=office,
                                                                                               owner=self.request.user)
            task = TasksModel.objects.select_related('target').get(pk=pk3, target=target)
            host = HostsModel.objects.select_related('task').filter(task=task, pk=pk4)
            queryset = WebsiteSecurityAlertModel.objects.select_related('host').filter(host=host, type='ABNORMAL', pk=pk5).order_by(
                '-events__severity', 'events')
        return queryset
