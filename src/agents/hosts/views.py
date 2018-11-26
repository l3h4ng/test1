# -*- coding: utf-8 -*-
from agents.monitor.models import WebsiteMonitorUrl
from agents.monitor.sbox_monitor import SboxSecurityMonitor
from sbox4web.rabbitmq import Rabbitmq

__author__ = 'TOANTV'
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import generics
from rest_framework import status
from rest_framework import filters
from rest_framework.exceptions import ValidationError
from rest_framework.renderers import JSONRenderer

from agents.hosts.models import HostsModel, HostDetailsModel
from agents.hosts.serializers import HostCreateDetailsSerializer, HostCreateUpdateSerializer, HostStatisticSerializer, \
    HostInfoSerializer, InfoSerializer, HostSerializer
from one_auth.authentication import OneTokenAuthentication
from one_users.permissions import IsOneUserAuthenticatedReadOnlyOrScanner
from sbox4web.views import JSONResponse
from targets.models import TasksModel, TargetsModel



# /hosts
class HostsListView(generics.ListCreateAPIView):
    serializer_class = HostStatisticSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('task', 'ip_addr', 'severity', 'device_type')
    search_fields = ('task', 'ip_addr',)

    def get_queryset(self):
        queryset = HostsModel.objects.all().order_by('-id')
        queryset = queryset.select_related('details')
        queryset = queryset.select_related('statistics')
        os_search = self.request.GET.get('os', None)
        if os_search is not None:
            queryset = queryset.filter(os__contains=[os_search])
        return queryset

    def post(self, request, *args, **kwargs):
        try:
            data = request.data
            if "details" in request.data:
                self.serializer_class = HostCreateDetailsSerializer
                if "os" in data["details"]:
                    if isinstance(data["details"]["os"], str) or isinstance(data["details"]["os"], unicode):
                        if data["details"]["os"] != "":
                            data["details"]["os"] = data["details"]["os"].split(',')
                        else:
                            data["details"]["os"] = []
            else:
                self.serializer_class = HostCreateUpdateSerializer
            serializer = self.get_serializer(data=data)
            serializer.is_valid(raise_exception=True)
            host_model = serializer.save()

            # Check status network
            try:
                server_node_name = host_model.task.target.server_node.name
                queue_name = "{}_mstatus".format(server_node_name)
                rabbitmq = Rabbitmq(queue_name)
                rabbitmq.add(str(host_model.id))
            except Exception, ex:
                print "Cannot add message to server, exception {}".format(str(ex))

            # create url monitor
            print "Checking add url {} to url monitor".format(str(host_model.ip_addr))
            url_monitor = WebsiteMonitorUrl.objects.filter(target=host_model.task.target,
                                                           url=host_model.ip_addr,
                                                           path=host_model.ip_addr)
            if url_monitor.count() == 0:
                print "Create url {} to url monitor".format(str(host_model.ip_addr))
                url_monitor = WebsiteMonitorUrl.objects.create(target=host_model.task.target, url=host_model.ip_addr,
                                                               path=host_model.ip_addr)
                url_monitor.save()

            # detect monitor alert
            SboxSecurityMonitor("HOST").monitor(host_model)
            return JSONResponse(HostInfoSerializer(host_model).data, status=status.HTTP_201_CREATED)
        except ValidationError:
            if "ip_addr" in request.data and "task" in request.data:
                host_model = HostsModel.objects.get(ip_addr=request.data["ip_addr"],
                                                    task=TasksModel.objects.get(pk=request.data["task"]))
                return JSONResponse(HostInfoSerializer(host_model).data, status=status.HTTP_201_CREATED)
            else:
                error = {"status": "error",
                         "exception": "ip_addr and task is the required fields"
                         }
                return JSONResponse(error, status=status.HTTP_400_BAD_REQUEST)


# /hosts/hostid
class HostViews(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = HostInfoSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        queryset = HostsModel.objects.all()
        queryset = queryset.select_related('details')
        queryset = queryset.select_related('statistics')
        return queryset

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        data = request.data
        if "details" in request.data:
            self.serializer_class = HostCreateDetailsSerializer
            if "os" in data["details"]:
                if isinstance(data["details"]["os"], str) or isinstance(data["details"]["os"], unicode):
                    if data["details"]["os"] != "":
                        data["details"]["os"] = data["details"]["os"].split(',')
                    else:
                        data["details"]["os"] = []
        else:
            self.serializer_class = HostCreateUpdateSerializer
        serializer = self.get_serializer(instance, data=data, partial=partial)
        serializer.is_valid(raise_exception=True)
        host_model = serializer.save()
        return JSONResponse(HostInfoSerializer(host_model).data, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()

        # Update task statistic
        if instance.task.statistics.hosts_count > 1:
            instance.task.statistics.hosts_count -= 1
            instance.task.statistics.save()
        self.perform_destroy(instance)
        return JSONResponse({}, status=status.HTTP_204_NO_CONTENT)


# /hosts/hostid/details
class HostInfoViews(generics.RetrieveUpdateAPIView):
    serializer_class = InfoSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        queryset = HostDetailsModel.objects.all()
        queryset = queryset.select_related('host').filter(host_id=pk)
        return queryset


# /lastshosts
class ListHostsOfLastTaskAllTarget(generics.ListAPIView):
    serializer_class = HostSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        list_task = TargetsModel.objects.values_list('last_task_id', flat=True)
        query_set = HostsModel.objects.prefetch_related('task').filter(task_id__in=list(list_task))
        return query_set
