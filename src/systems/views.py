# Create your views here.
from collections import OrderedDict
import datetime
from sys import platform
from time import sleep
import subprocess
from agents.monitor.models import WebsiteGoogleHackingDetectModel, WebsitePhishingDomainDetectModel, \
    WebsiteBlacklistCheckingModel, WebsiteMonitorStatusModel, WebsiteSecurityAlertModel
from agents.monitor.serializers import WebsiteGoogleHackingDetectSerializer, \
    WebsitePhishingDomainDetectDetailsSerializer, WebsiteBlacklistCheckingSerializer, \
    WebsiteBlacklistCheckingDetailsSerializer, WebsiteMonitorStatusSerializer, WebsiteMonitorStatusDetailsSerializer, \
    WebsiteGoogleHackingDetectDetailsSerializer, WebsiteGoogleHackingDetectWebsiteDetailsSerializer, \
    SecurityAlertInfoSerializer

from django.conf import settings
from django.db.models import Count
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import generics, status, filters
from rest_framework.permissions import AllowAny, SAFE_METHODS
from rest_framework.renderers import JSONRenderer
from rest_framework.views import APIView
from agents.hosts.models import HostsModel
from agents.vulns.models import VulnerabilityModel
from one_auth.authentication import OneTokenAuthentication
from one_users.permissions import AllowAnyReadOnly, \
    IsOneUserAuthenticated, IsOneUserAuthenticatedReadOnlyOrScanner, \
    IsOneUserAuthenticatedReadOnlyOrAdmin, IsOneUserAdmin, IsAnyOneReadOnly
from sbox4web.libs import ping_window, update_system_statisticsv2
from sbox4web.libs import ping_linux
from sbox4web.rabbitmq import Rabbitmq
from sbox4web.views import JSONResponse
from systems.check_proxy import is_working_proxy
from systems.check_smtp import connect_to_mail
from systems.models import SystemsNetworkConfig, SystemsProxy, SystemsEmailNotify, SystemStatistics, SystemsLicense, \
    SystemsAlert, SystemLog, SystemVPNModel
from systems.serializers import NetworkConfigSerializer, SystemsEmailSerializers, SystemsProxySerializers, \
    SystemStatisticsSerializers, SystemsLicenseSerializers, LoggingSystemSerializers, \
    SystemStatisticTopHostsDangerousSerializers, SystemStatisticTopVulnSerializers, LoggingAlertDetailsSerializers, \
    LoggingSystemDetailsSerializers, SystemVPNSerializers
from targets.models import TargetsModel, TasksModel

if platform == "win32":
    from systems.network_config_win import net_ipconfig
else:
    from systems.network_config import net_ipconfig


class NetworkConfigView(generics.RetrieveUpdateAPIView):
    serializer_class = NetworkConfigSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get(self, request, *args, **kwargs):
        list_ips = SystemsNetworkConfig.objects.all()
        if len(list_ips) == 0:
            network_manager = net_ipconfig()
            list_interface = network_manager.list_iface_all()
            for interface in list_interface:
                if interface not in settings.EXCLUDE_INTERFACE:
                    ip_info = network_manager.list_ifconfig_detail(interface)
                    if interface in settings.ADMIN_INTERFACE:
                        ip_info["type"] = 1
                        ip_info["static"] = 1
                    else:
                        ip_info["type"] = 0
                        ip_info["static"] = 0
                SystemsNetworkConfig.objects.create(**ip_info)
            list_ips = SystemsNetworkConfig.objects.all()
        serializer = self.get_serializer(list_ips, many=True)
        return JSONResponse(serializer.data, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        if request.data["static"]:
            partial = kwargs.pop('partial', True)
        request_data = request.data
        try:
            if "interface" in request_data:
                instance = SystemsNetworkConfig.objects.get(interface=request_data["interface"])
                # update ip address
                serializer = self.get_serializer(instance, data=request_data, partial=partial)
                serializer.is_valid(raise_exception=True)
                self.perform_update(serializer)

                ipconfig = net_ipconfig()
                network_info = ipconfig.choose_mode(instance)
                # network config error
                if "exception" in network_info:
                    return JSONResponse(network_info, status=status.HTTP_404_NOT_FOUND)

                # network config is ok
                if not network_info["static"]:
                    serializer = self.get_serializer(instance, data=network_info, partial=partial)
                    serializer.is_valid(raise_exception=True)
                    self.perform_update(serializer)
                return JSONResponse(serializer.data, status=status.HTTP_200_OK)
            else:
                error = {"status": "error",
                         "exception": "instance is the required fields"
                         }
                return JSONResponse(error, status=status.HTTP_400_BAD_REQUEST)

        except SystemsNetworkConfig.DoesNotExist:
            error = {"status": "error",
                     "exception": "interface is not exits in device."
                     }
            return JSONResponse(error, status=status.HTTP_400_BAD_REQUEST)


class NetworkConnectionPingView(generics.RetrieveAPIView):
    serializer_class = SystemVPNSerializers
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get(self, request, *args, **kwargs):
        ip_addr = request.GET.get('address', None)
        if ip_addr is not None and ip_addr is not "":
            if platform == "win32":
                response = ping_window(ip_addr)
            else:
                response = ping_linux(ip_addr)
            return JSONResponse({'results': response}, status=status.HTTP_200_OK)
        else:
            return JSONResponse({'status': 'error', "error": "Address field is requirements!!!"},
                                status=status.HTTP_400_BAD_REQUEST)


class SMPTView(generics.RetrieveUpdateAPIView):
    serializer_class = SystemsEmailSerializers
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrAdmin,)
    renderer_classes = (JSONRenderer,)

    def get(self, request, *args, **kwargs):
        try:
            instance = SystemsEmailNotify.objects.get(pk=1)
            serializer = self.get_serializer(instance)
            return JSONResponse(serializer.data, status=status.HTTP_200_OK)
        except SystemsEmailNotify.DoesNotExist:
            return JSONResponse({}, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', True)
        if request.data["enable"]:
            partial = kwargs.pop('partial', False)
        try:
            instance = SystemsEmailNotify.objects.get(pk=1)
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            if "password" in request.data and "username" in request.data:
                serializer.save(test_connection=False)
            else:
                serializer.save(password=None, username=None, test_connection=False)
            instance = connect_to_mail(smtp=SystemsEmailNotify.objects.get(pk=1))
            serializer = self.get_serializer(instance)
            return JSONResponse(serializer.data, status=status.HTTP_200_OK)

        except SystemsEmailNotify.DoesNotExist:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            instance = serializer.save(pk=1)
            connect_to_mail(smtp=instance)
            serializer = self.get_serializer(instance)
            return JSONResponse(serializer.data, status=status.HTTP_200_OK)


class VpnNetworkView(generics.RetrieveUpdateAPIView):
    serializer_class = SystemVPNSerializers
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get(self, request, *args, **kwargs):
        try:
            instance = SystemVPNModel.objects.get(pk=1)
            serializer = self.get_serializer(instance)
            return JSONResponse(serializer.data, status=status.HTTP_200_OK)
        except SystemVPNModel.DoesNotExist:
            data = {
                "enable": False,
                "time_interval": 0
            }
            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            serializer.save(id=1)
            return JSONResponse(serializer.data, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', True)
        try:
            instance = SystemVPNModel.objects.get(pk=1)
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            vpn_model = serializer.save()
            self.send_vpn_config(vpn_model)
            return JSONResponse(serializer.data, status=status.HTTP_200_OK)
        except SystemVPNModel.DoesNotExist:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            vpn_model = serializer.save(id=1)
            self.send_vpn_config(vpn_model)
            return JSONResponse(serializer.data, status=status.HTTP_200_OK)

    def send_vpn_config(self, vpn_model):
        try:
            time_interval = 0
            if vpn_model.enable and vpn_model.time_interval > 0:
                time_interval = vpn_model.time_interval
            queue_name = "vpn_configs"
            rabbitmq = Rabbitmq(queue_name)
            rabbitmq.add(str(time_interval))
        except Exception, ex:
            print "Cannot add vpn config to server, exception {}".format(str(ex))


class ProxyView(generics.RetrieveUpdateAPIView):
    serializer_class = SystemsProxySerializers
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get(self, request, *args, **kwargs):
        try:
            instance = SystemsProxy.objects.get(pk=1)
            serializer = self.get_serializer(instance)
            return JSONResponse(serializer.data, status=status.HTTP_200_OK)
        except SystemsProxy.DoesNotExist:
            return JSONResponse({}, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', True)
        if request.data["enable"]:
            partial = kwargs.pop('partial', False)
        try:
            instance = SystemsProxy.objects.get(pk=1)
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            if "password" in request.data and "username" in request.data:
                proxy = serializer.save(test_connection=False)
            else:
                proxy = serializer.save(password=None, username=None, test_connection=False)
            data = is_working_proxy(ProxyModel=proxy)
            return JSONResponse(data, status=status.HTTP_200_OK)

        except SystemsProxy.DoesNotExist:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            proxy = serializer.save(id=1)
            data = is_working_proxy(ProxyModel=proxy)
            return JSONResponse(data, status=status.HTTP_200_OK)


class SystemsLicenseView(generics.RetrieveUpdateAPIView):
    serializer_class = SystemsLicenseSerializers
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get(self, request, *args, **kwargs):
        instance = SystemsLicense.objects.all().first()
        serializer = self.get_serializer(instance)
        return JSONResponse(serializer.data, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', True)
        try:
            instance = SystemsLicense.objects.all().first()
            serializer = self.get_serializer(instance, data=request.data, partial=partial)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return JSONResponse(serializer.data, status=status.HTTP_200_OK)

        except SystemsLicense.DoesNotExist:
            serializer = self.get_serializer(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return JSONResponse(serializer.data, status=status.HTTP_200_OK)


class LoggingAlertList(generics.ListAPIView):
    serializer_class = LoggingAlertDetailsSerializers
    authentication_classes = []
    permission_classes = (IsAnyOneReadOnly,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = (
        'contents', 'created_at', 'is_watched')

    def get_queryset(self):
        queryset = SystemsAlert.objects.all().order_by('-id')
        queryset = queryset.select_related("contents")
        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        unread_count = queryset.filter(is_watched=False).count()

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data, unread_count)
        serializer = self.get_serializer(queryset, many=True)
        return JSONResponse(serializer.data)

    def get_paginated_response(self, data, unread_count):
        return JSONResponse(OrderedDict([
            ('count', self.paginator.count),
            ('next', self.paginator.get_next_link()),
            ('previous', self.paginator.get_previous_link()),
            ('unread', unread_count),
            ('results', data)
        ]))

    def get_authenticators(self):
        """
        Instantiates and returns the list of authenticators that this view can use.
        """
        if self.request.method in SAFE_METHODS:
            return []
        else:
            self.authentication_classes = (OneTokenAuthentication,)
            return [auth() for auth in self.authentication_classes]

class LoggingAlertReadAllView(generics.ListAPIView):
    serializer_class = LoggingAlertDetailsSerializers
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = (
        'contents', 'created_at', 'is_watched')

    def get_queryset(self):
        queryset = SystemsAlert.objects.filter(is_watched=False).order_by('-id')
        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        for alert in queryset.all():
            alert.is_watched = True
            alert.save()
        return JSONResponse({}, status=status.HTTP_200_OK)

class LoggingAlertDetail(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = LoggingAlertDetailsSerializers
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        queryset = SystemsAlert.objects.all().order_by('-id')
        queryset = queryset.select_related("contents")
        return queryset


class LoggingAlertReadDetail(generics.RetrieveAPIView):
    serializer_class = LoggingAlertDetailsSerializers
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        queryset = SystemsAlert.objects.all().order_by('-id')
        queryset = queryset.select_related("contents")
        return queryset

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.is_watched = True
        instance.save()
        serializer = self.get_serializer(instance)
        return JSONResponse(serializer.data)

class LoggingSystemList(generics.ListCreateAPIView):
    serializer_class = LoggingSystemDetailsSerializers
    authentication_classes = []
    permission_classes = (IsAnyOneReadOnly,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = (
        'target', 'task', 'type', 'plugin')

    def get_queryset(self):
        queryset = SystemLog.objects.all().order_by('-id')
        queryset = queryset.select_related("task", "target", "target__office", "target__office__unit")
        return queryset

    def create(self, request, *args, **kwargs):
        serializer = LoggingSystemSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        return JSONResponse(LoggingSystemDetailsSerializers(instance).data, status=status.HTTP_201_CREATED)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        unread_count = queryset.filter(is_watched=False).count()

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data, unread_count)

        serializer = self.get_serializer(queryset, many=True)
        return JSONResponse(serializer.data, status=status.HTTP_200_OK)

    def get_paginated_response(self, data, unread_count):
        return JSONResponse(OrderedDict([
            ('count', self.paginator.count),
            ('next', self.paginator.get_next_link()),
            ('previous', self.paginator.get_previous_link()),
            ('unread', unread_count),
            ('results', data)
        ]))

    def get_authenticators(self):
        """
        Instantiates and returns the list of authenticators that this view can use.
        """
        if self.request.method in SAFE_METHODS:
            return []
        else:
            self.authentication_classes = (OneTokenAuthentication,)
            return [auth() for auth in self.authentication_classes]

class LoggingSystemReadAllView(generics.ListAPIView):
    serializer_class = LoggingSystemDetailsSerializers
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = (
        'target', 'task', 'type', 'plugin')

    def get_queryset(self):
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            queryset = SystemLog.objects.all().order_by('-id')
        else:
            queryset = SystemLog.objects.select_related('target__owner').filter(
                target__owner=self.request.user).order_by('-id')
        queryset = queryset.select_related("task", "target", "target__office", "target__office__unit")
        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        for alert in queryset.all():
            alert.is_watched = True
            alert.save()
        return JSONResponse({}, status=status.HTTP_200_OK)

class LoggingSystemDetail(generics.RetrieveDestroyAPIView):
    serializer_class = LoggingSystemDetailsSerializers
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        queryset = SystemLog.objects.all().order_by('-id')
        queryset = queryset.select_related("task", "target", "target__office", "target__office__unit")
        return queryset

class LoggingSystemReadDetail(generics.RetrieveDestroyAPIView):
    serializer_class = LoggingSystemDetailsSerializers
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        queryset = SystemLog.objects.all().order_by('-id')
        queryset = queryset.select_related("task", "target", "target__office", "target__office__unit")
        return queryset

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.is_watched = True
        instance.save()
        serializer = self.get_serializer(instance)
        return JSONResponse(serializer.data)


class GetSystemsStatus(generics.ListAPIView):
    renderer_classes = (JSONRenderer,)
    permission_classes = (AllowAny,)

    def list(self, request, *args, **kwargs):
        system_status = {}
        status_scans = {"total": 0,
                        "init": TargetsModel.objects.filter(status=0).count(),
                        "running": TargetsModel.objects.filter(status=2).count(),
                        "waitting": TargetsModel.objects.filter(status=1).count(),
                        "stopped": TargetsModel.objects.filter(status=3).count(),
                        "error": TargetsModel.objects.filter(status=4).count(),
                        "finish": TargetsModel.objects.filter(status=5).count()}
        status_scans["total"] = status_scans["waitting"] + status_scans["running"] + \
                                status_scans["stopped"] + status_scans["error"] + status_scans["finish"]
        system_status["targets"] = status_scans
        queryset = SystemStatistics.objects.all().order_by('-id')
        obj = queryset.first()
        system_status["statistic"] = SystemStatisticsSerializers(obj).data
        return JSONResponse(system_status, status=status.HTTP_200_OK)


class ListIface(APIView):
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)

    def get(self, request, *args, **kwargs):
        network = request.query_params.get('network', None)
        ipconfig = net_ipconfig()
        if network is not None:
            network = ipconfig.list_ifconfig_detail(str(network))
            if 'status' in network:
                return JSONResponse(network, status=status.HTTP_404_NOT_FOUND)
            return JSONResponse(network, status=status.HTTP_200_OK)
        list_iface = ipconfig.list_iface_all()
        if list_iface is None:
            return JSONResponse(list_iface, status=status.HTTP_404_NOT_FOUND)
        return JSONResponse(list_iface, status=status.HTTP_200_OK)


class ShutDown(generics.CreateAPIView):
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAdmin,)
    renderer_classes = (JSONRenderer,)

    def post(self, request, *args, **kwargs):
        get_status = request.data
        if "status" in get_status:
            if get_status["status"] == "shutdown":
                command = "sudo poweroff"
                subprocess.Popen(command, shell=True)
                command = "shutdown -t 1 -s -f"
                subprocess.Popen(command, shell=True)
                sleep(5)
            elif get_status["status"] == "restart":
                command = "sudo reboot"
                subprocess.Popen(command, shell=True)
                command = "shutdown -t 1 -r -f"
                subprocess.Popen(command, shell=True)
                sleep(5)
        data = {
            "status": "error",
            "exception": "Can not restart or shutdown."
        }
        return JSONResponse(data, status=status.HTTP_400_BAD_REQUEST)


########################################################################################################################
###                                               STATISTIC API                                                      ###
########################################################################################################################
# /systems/statistics
class SystemStatisticNow(generics.RetrieveAPIView):
    queryset = SystemStatistics.objects.all().order_by('-id')
    serializer_class = SystemStatisticsSerializers
    authentication_classes = []
    permission_classes = (IsAnyOneReadOnly,)
    renderer_classes = (JSONRenderer,)

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())
        date_now = datetime.datetime.today().date()
        queryset = queryset.filter(date_statistic=date_now)
        obj = queryset.first()
        self.check_object_permissions(self.request, obj)
        return obj

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance is None:
            instance = update_system_statisticsv2()
        serializer = self.get_serializer(instance)

        target_statistics = {"total": 0,
                             "init": TargetsModel.objects.filter(status=0).count(),
                             "running": TargetsModel.objects.filter(status=2).count(),
                             "waitting": TargetsModel.objects.filter(status=1).count(),
                             "stopped": TargetsModel.objects.filter(status=3).count(),
                             "error": TargetsModel.objects.filter(status=4).count(),
                             "finish": TargetsModel.objects.filter(status=5).count()}
        target_statistics["total"] = target_statistics["waitting"] + target_statistics["running"] + \
                                     target_statistics["stopped"] + target_statistics["error"] + target_statistics[
                                         "finish"]

        data = {"statistic": serializer.data,
                "targets": target_statistics
                }
        return JSONResponse(data, status=status.HTTP_200_OK)


class SystemStatisticList(generics.ListAPIView):
    queryset = SystemStatistics.objects.all().order_by('-id')[:10]
    serializer_class = SystemStatisticsSerializers
    authentication_classes = []
    permission_classes = (IsAnyOneReadOnly,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = (
        'date_statistic', 'services_count', 'vulns_count', 'high_count', 'medium_count', 'low_count',
        'info_count', 'critical_count')

    def get_queryset(self):
        queryset = SystemStatistics.objects.all().order_by('-id')[:10]
        return queryset



class SystemStatisticTopVulnerability(generics.ListAPIView):
    serializer_class = SystemStatisticTopVulnSerializers
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (AllowAnyReadOnly,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('name',)

    def get_queryset(self):
        queryset = VulnerabilityModel.objects.all()
        queryset = queryset.prefetch_related('hosts', 'hosts__host')
        queryset = queryset.annotate(host_counts=Count('hosts')).order_by('-host_counts')[:10]
        return queryset


class SystemStatisticTopHostsVulnerbility(generics.ListAPIView):
    queryset = HostsModel.objects.all().order_by('-id')
    serializer_class = SystemStatisticTopHostsDangerousSerializers
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (AllowAnyReadOnly,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('ip_addr',)

    def get_queryset(self):
        queryset = HostsModel.objects.select_related('task', 'statistics', 'task__target', 'task__target__office',
                                                     'task__target__office__unit').filter(task__is_lasted=True,
                                                                                          severity=3).order_by(
            '-statistics__security_alert_count')[:10]
        return queryset

class SystemStatisticTopSecurityAlert(generics.ListAPIView):
    serializer_class = SecurityAlertInfoSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (AllowAnyReadOnly,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)

    def get_queryset(self):
        queryset = WebsiteSecurityAlertModel.objects.select_related('events').filter(events__severity__in=[3,4])
        queryset.select_related('host', 'host__task')
        return queryset

    def list(self, request, *args, **kwargs):
        list_targets = TargetsModel.objects.all()
        list_tasks = []
        for target in list_targets:
            last_task_finish = TasksModel.objects.filter(target=target, status=5).order_by('-id').first()
            if last_task_finish is None:
                last_task_finish = TasksModel.objects.filter(target=target).order_by('-id').first()
            list_tasks.append(last_task_finish)

        list_mscurities = self.filter_queryset(self.get_queryset())
        list_mscurities = list_mscurities.filter(host__task__in=list_tasks)
        list_mscurities = list_mscurities.values('name').order_by('-name_counts').annotate(name_counts=Count('name'))[:10]

        data = []
        for security_event in list_mscurities:
            instance = WebsiteSecurityAlertModel.objects.filter(name=security_event["name"]).first()
            info = SecurityAlertInfoSerializer(instance).data
            info["counts"]= security_event["name_counts"]

            list_host_objects = []
            list_hosts_info = []
            list_hosts = HostsModel.objects.prefetch_related("msecurity", "task").filter(msecurity__name=security_event["name"], task__in=list_tasks)
            for host in list_hosts:
                if host not in list_host_objects:
                    list_host_objects.append(host)
                    list_hosts_info.append({"id": host.id, "ip_addr": host.ip_addr, "count": 1})
                else:
                    index = list_host_objects.index(host)
                    list_hosts_info[index]["count"] += 1
            info["list_hosts"] = list_hosts_info
            data.append(info)
        return JSONResponse(data, status=status.HTTP_200_OK)

# /systems/statistic/ghdb
class WebsiteGoogleHackingDetectListView(generics.ListAPIView):
    queryset = WebsiteGoogleHackingDetectModel.objects.all().order_by('-id')
    serializer_class = WebsiteGoogleHackingDetectWebsiteDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (AllowAny,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('website', 'keyword',)
    search_fields = ('link')


# /systems/statistic/phishing
class WebsitePhishingDomainDetectListView(generics.ListCreateAPIView):
    queryset = WebsitePhishingDomainDetectModel.objects.all().order_by('-id')
    serializer_class = WebsitePhishingDomainDetectDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (AllowAny,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('website', 'domain', 'is_exits', 'ip_addr', 'security_level',)
    search_fields = ('domain', 'ip_addr',)


# /systems/statistic/blacklist
class WebsiteBlacklistCheckingListView(generics.ListCreateAPIView):
    queryset = WebsiteBlacklistCheckingModel.objects.all().order_by('-id')
    serializer_class = WebsiteBlacklistCheckingDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (AllowAny,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('website', 'type', 'result',)


# /systems/statistic/webstatus
class WebsiteMonitorStatusListView(generics.ListCreateAPIView):
    queryset = WebsiteMonitorStatusModel.objects.all().order_by('-id')
    serializer_class = WebsiteMonitorStatusDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (AllowAny,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('website', 'monitor_time',)
    search_fields = ('website',)
