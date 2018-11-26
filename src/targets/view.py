from django.db.models import Q
from django.utils.translation import ugettext_lazy as _
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from rest_framework import generics
from rest_framework import status
from rest_framework.generics import get_object_or_404
from rest_framework.renderers import JSONRenderer

from agents.hosts.models import HostsModel
from agents.scans.models import ScansModel
from agents.scans.serializers import ScansSerializer
from one_auth.authentication import OneTokenAuthentication
from one_users.permissions import IsOneUserAuthenticated, IsAnyOneReadOnly
from sadmin.vulnerabilities.models import VulnerabilityModel
from sadmin.vulnerabilities.serializers import VulneratbilitySerializer
from sbox4web.libs import update_system_statistics
from sbox4web.repeater import forward_request
from sbox4web.views import JSONResponse
from systems.serializers import LoggingAlertSerializers
from targets.controller import get_list_email, prev_in_order, next_in_order
from targets.models import TasksModel, TargetsModel
from targets.serializers import StatisticsSerializers, TasksSerializerInfoScans, \
    TaskShortSerializers, TargetDetailsInfoSerializer, \
    TargetCreateSerializer, TaskCompareSerializer, HostShortInfoSerializer, TaskCompareListHostSerializer
from units.models import UnitsModel, OfficesModel
import numpy as np


########################################################################################################################
###                                           TARGET API                                                             ###
########################################################################################################################
# GET LIST TARGET
# /unit/id/office/id/targets/
class TargetsOfUnitView(generics.ListCreateAPIView):
    serializer_class = TargetDetailsInfoSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('name', 'status', 'office', 'address', 'severity')
    search_fields = ('name', 'address')

    def get_queryset(self):
        # Valid unit and office id
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        # unit = UnitsModel.objects.get(pk=pk)
        # office = OfficesModel.objects.get(pk=pk1, unit=unit)
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)
        queryset = TargetsModel.objects.all().order_by('-id')
        queryset = queryset.select_related('configuration', 'configuration__scheduler')
        queryset = queryset.select_related('statistics', 'statistics__task', 'statistics__task__statistics')
        queryset = queryset.select_related('owner')
        queryset = queryset.select_related('office', 'office__unit')
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            queryset = queryset.filter(office=office)
            return queryset
        else:
            queryset = queryset.filter(owner=self.request.user, office=office)
            return queryset

    def post(self, request, *args, **kwargs):
        self.serializer_class = TargetCreateSerializer
        pk1 = self.kwargs['pk1']
        office = OfficesModel.objects.get(pk=pk1)
        data = request.data
        if "office" in data:
            data["office"] = office.id

        if "configuration" in request.data:
            data = request.data["configuration"]
            if "email_notify" in data:
                list_email = get_list_email()
                for email in data["email_notify"]:
                    if email not in list_email:
                        data = {
                            "status": "error",
                            "exception": "Email: %s is not in list email user registers." % email
                        }
                        return JSONResponse(data, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        target_model = serializer.save(owner=self.request.user)
        # setTimeScheduler(scheduler=target_model.configuration.scheduler)
        # create_tasks(target=target_model)
        # target_statistics = TargetStatisticsModel(target=target_model, task=TasksModel(pk=target_model.last_task_id))
        # target_statistics.save()
        return JSONResponse(TargetDetailsInfoSerializer(target_model).data, status=status.HTTP_201_CREATED)

# /targets
class TargetsListView(generics.ListAPIView):
    serializer_class = TargetDetailsInfoSerializer
    authentication_classes = []
    permission_classes = (IsAnyOneReadOnly,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('name', 'status', 'office', 'address', 'severity',)
    search_fields = ('name', 'address',)

    def get_queryset(self):
        queryset = TargetsModel.objects.all().select_related('owner').order_by('-id')
        queryset = queryset.select_related('configuration', 'configuration__scheduler')
        queryset = queryset.select_related('statistics', 'statistics__task', 'statistics__task__statistics')
        queryset = queryset.select_related('office', 'office__unit')
        return queryset

########## TARGET DETAILS ##########
# /units/uid/offices/oid/targets/tid
class TargetDetails(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = TargetDetailsInfoSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        # Valid unit and office id
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        # unit = UnitsModel.objects.get(pk=pk)
        # office = OfficesModel.objects.get(pk=pk1, unit=unit)
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)
        self.kwargs['pk'] = pk2

        queryset = TargetsModel.objects.all().order_by('-id')
        queryset = queryset.select_related('configuration', 'configuration__scheduler')
        queryset = queryset.select_related('statistics', 'statistics__task', 'statistics__task__statistics')
        queryset = queryset.select_related('owner')
        queryset = queryset.select_related('office', 'office__unit')
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            queryset = queryset.filter(office=office, pk=pk2)
            return queryset
        else:
            queryset = queryset.filter(owner=self.request.user, office=office, pk=pk2)
            return queryset

    # def retrieve(self, request, *args, **kwargs):
    #     instance = self.get_object()
    #     serializer = self.get_serializer(instance).data
    #     try:
    #         last_task = TasksModel.objects.get(pk=serializer["last_task_id"])
    #         last_task_data = TasksSerializer(last_task).data
    #         statistics = last_task.statistics
    #         statistics_data = StatisticsSerializers(statistics).data
    #     except:
    #         last_task_data = None
    #         statistics_data = None
    #     office = OfficesModel.objects.get(pk=serializer["office"])
    #     serializer.update({"last_task": last_task_data,
    #                        "statistics": statistics_data,
    #                        "unit": UnitsShortInfoSerializer(office.unit).data,
    #                        "office": OfficesShortInfoSerializer(office).data})
    #     serializer["configuration"]["email_notify"] = get_list_email_notify(serializer["configuration"]["email_notify"])
    #     return JSONResponse(serializer, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', True)
        instance = self.get_object()
        if "configuration" in request.data:
            data = request.data["configuration"]
            if "email_notify" in data:
                list_email = get_list_email()
                for email in data["email_notify"]:
                    if email not in list_email:
                        data = {
                            "status": "error",
                            "exception": "Email: %s is not in list email user registers." % email
                        }
                        return JSONResponse(data, status=status.HTTP_400_BAD_REQUEST)

        serializer = TargetCreateSerializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        target_model = serializer.save()
        return JSONResponse(TargetDetailsInfoSerializer(target_model).data, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.status < 3 and instance.status >= 0:
            data = {
                "status": "error",
                "exception": _('Stop job first.')
            }
            return JSONResponse(data, status=status.HTTP_400_BAD_REQUEST)
        self.perform_destroy(instance)
        # Update System Statistic
        update_system_statistics()
        return JSONResponse({'status': 'success'}, status=status.HTTP_204_NO_CONTENT)


# /unit/id/office/id/targets/id/statistics/
class ListStatisticsView(generics.RetrieveUpdateAPIView):
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    serializer_class = StatisticsSerializers

    def get_object(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)
        target = TargetsModel.objects.select_related('statistics', 'statistics__task',
                                                     'statistics__task__statistics').get(
            pk=pk2, office=office)
        obj = target.statistics.task.statistics
        return obj


########################################################################################################################
###                                           TASKS API                                                              ###
########################################################################################################################
# GET LIST TASK OF TARGET
# /units/uid/offices/oid/targets/tid/tasks
class TasksListOfTarget(generics.ListAPIView):
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('name', 'status', 'severity', 'finish_time', 'start_time')
    search_fields = ('name',)
    serializer_class = TaskShortSerializers

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)

        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.get(pk=pk2, office=office)
        else:
            target = TargetsModel.objects.get(pk=pk2, office=office, owner=self.request.user)
        queryset = TasksModel.objects.select_related('statistics').filter(target=target.id).order_by('-id')
        return queryset


# /unit/id/office/id/targets/status/
class GetTargetsStatus(generics.ListAPIView):
    serializer_class = TargetDetailsInfoSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)

    def list(self, request, *args, **kwargs):
        status_scans = {"total": 0,
                        "init": TargetsModel.objects.filter(status=0).count(),
                        "running": TargetsModel.objects.filter(status=2).count(),
                        "waitting": TargetsModel.objects.filter(status=1).count(),
                        "stopped": TargetsModel.objects.filter(status=3).count(),
                        "error": TargetsModel.objects.filter(status=4).count(),
                        "finish": TargetsModel.objects.filter(status=5).count()}
        status_scans["total"] = status_scans["init"] + status_scans["waitting"] + status_scans["running"] + \
                                status_scans["stopped"] + status_scans["error"] + status_scans["finish"]
        return JSONResponse(status_scans, status=status.HTTP_200_OK)


# # /unit/id/office/id/targets/tid/compare
# class TasksCompareViews(generics.CreateAPIView):
#     serializer_class = TaskCompare2Serializer
#     authentication_classes = (OneTokenAuthentication,)
#     permission_classes = (IsOneUserAuthenticated,)
#     renderer_classes = (JSONRenderer,)
#
#     def get_queryset(self):
#         task1 = self.request.data.get("taskid_one", None)
#         task2 = self.request.data.get("taskid_two", None)
#         queryset = TasksModel.objects.filter(pk__in=[task1, task2]).order_by('id')
#         if len(queryset) != 2:
#             raise TasksModel.DoesNotExist("Task is not found.")
#         elif queryset[0].target != queryset[1].target:
#             raise ValueError("The tasks is not in a same target.")
#         queryset = queryset.select_related('statistics')
#         queryset = queryset.prefetch_related('hosts')
#         return queryset

    #     queryset = queryset.select_related('target', 'statistics')
    #     queryset = queryset.prefetch_related('hosts', 'hosts__services', 'hosts__vulns')
    #     # queryset = queryset.prefetch_related(Prefetch('hosts__services', queryset=HostServicesModel.objects.all().only('id', 'port')))
    #     # queryset = queryset.prefetch_related(Prefetch('hosts__vulns', queryset=HostServicesModel.objects.all().only('id', 'name')))
    #     return queryset

    def create(self, request, *args, **kwargs):
        # check params
        data = request.data
        if "taskid_one" not in data or "taskid_two" not in data:
            response = {
                "status": "error",
                "exception": "taskid_one and taskid_two is requirements."
            }
            return JSONResponse(response, status=status.HTTP_400_BAD_REQUEST)

        self.serializer_class = TaskCompareListHostSerializer
        tasks_serializer = self.get_serializer(self.get_queryset(), many=True)
        task_one = tasks_serializer.data[0]
        task_two = tasks_serializer.data[1]

        data_compares = {
            "statistics": {
                task_one["id"]: task_one["statistics"],
                task_two["id"]: task_two["statistics"]
            },
            "alert": {
                "host_new": 0,
                "host_delete": 0,
                "host_changed": 0,
                "services_new": 0,
                "services_closed": 0,
                "vulns_new": 0,
                "vuln_fixed": 0,
                "sessions_news": 0,
                "sessions_fixed": 0,
                "severity": 0
            },
            "host_details": []
        }

        # compare list hosts
        list_host1 = np.array(task_one["hosts"])
        list_host2 = np.array(task_two["hosts"])
        hosts_new = np.setdiff1d(list_host2, list_host1)
        hosts_delete = np.setdiff1d(list_host1, list_host2)
        total_host = np.append(list_host1, hosts_new)

        total_model = HostsModel.objects.select_related('task', 'statistics').prefetch_related('services', 'vulns',
                                                                                                'sessions',
                                                                                                'vulns__vulnerability').filter(
                    ip_addr__in=total_host, task_id=task_one["id"])
        total_model_data = HostShortInfoSerializer(total_model, many=True).data

        # Update statistic
        data_compares["alert"]["host_new"] = len(hosts_new)
        data_compares["alert"]["host_delete"] = len(hosts_delete)

        # host new
        hosts_new_models = HostsModel.objects.select_related('task', 'statistics').prefetch_related('services', 'vulns',
                                                                                                'sessions',
                                                                                                'vulns__vulnerability').filter(
                    ip_addr__in=hosts_new, task_id=task_two["id"])
        hosts_new_data = HostShortInfoSerializer(hosts_new_models, many=True).data
        for host in hosts_new_data:
            host["changed"] = "new"
            data_compares["host_details"].append(host)
            data_compares["alert"]["services_new"] += host["statistics"]["services_count"]
            data_compares["alert"]["vulns_new"] += host["statistics"]["vulns_count"]

        # host delelte
        hosts_delete_models = HostsModel.objects.select_related('task', 'statistics').prefetch_related('services', 'vulns',
                                                                                                'sessions',
                                                                                                'vulns__vulnerability').filter(
                    ip_addr__in=hosts_delete, task_id=task_one["id"])
        hosts_delete_data = HostShortInfoSerializer(hosts_delete_models, many=True).data

        for host in hosts_delete_data:
            host["changed"] = "delete"
            data_compares["host_details"].append(host)
            data_compares["alert"]["services_closed"] += host["statistics"]["services_count"]
            data_compares["alert"]["vuln_fixed"] += host["statistics"]["vulns_count"]

        # host changed
        hosts_changed = np.setdiff1d(list_host2, hosts_new)
        hosts_one_changed_models = HostsModel.objects.select_related('task', 'statistics').prefetch_related('services', 'vulns',
                                                                                                'sessions',
                                                                                                'vulns__vulnerability').filter(
                    ip_addr__in=hosts_changed, task_id=task_one["id"]).order_by('id')
        hosts_one_changed_data = HostShortInfoSerializer(hosts_one_changed_models, many=True).data
        hosts_two_changed_models = HostsModel.objects.select_related('task', 'statistics').prefetch_related('services', 'vulns',
                                                                                                'sessions',
                                                                                                'vulns__vulnerability').filter(
                    ip_addr__in=hosts_changed, task_id=task_two["id"]).order_by('id')
        hosts_two_changed_data = HostShortInfoSerializer(hosts_two_changed_models, many=True).data

        for count in range(0, len(hosts_two_changed_data)):
            host1_data = hosts_one_changed_data[count]
            print host1_data["ip_addr"]
            host2_data = hosts_two_changed_data[count]
            print host2_data["ip_addr"]

            # Compare services
            host1_services = np.array(host1_data["services"])
            host2_services = np.array(host2_data["services"])
            new_services = np.setdiff1d(host2_services, host1_services)
            deleted_services = np.setdiff1d(host1_services, host2_services)

            compare_services = {
                "new": np.array([]),
                "deleted": np.array([])
            }
            if len(new_services) > 0:
                compare_services["new"] = new_services
                data_compares["alert"]["services_new"] += len(new_services)

            if len(deleted_services) > 0:
                compare_services["deleted"] = deleted_services
                data_compares["alert"]["services_closed"] += len(deleted_services)

            host2_data["services"] = compare_services
            if len(new_services) > 0 or len(deleted_services) > 0:
                host2_data["changed"] = "changed"

            # Compare vulns
            host1_vulns = np.array(host1_data["vulns"])
            host2_vulns = np.array(host2_data["vulns"])
            new_vulns = np.setdiff1d(host2_vulns, host1_vulns)
            deleted_vulns = np.setdiff1d(host1_vulns, host2_vulns)

            compare_vulns = {
                "new": np.array([]),
                "deleted": np.array([])
            }
            if len(new_vulns) > 0:
                compare_vulns["new"] = new_vulns
                data_compares["alert"]["vulns_new"] += len(new_vulns)
                for vuln in new_vulns:
                    if vuln["severity"] >= 3:
                        if data_compares["alert"]["severity"] < 2:
                            data_compares["alert"]["severity"] = 2
                            break
                    elif vuln["severity"] == 2:
                        if data_compares["alert"]["severity"] < 1:
                            data_compares["alert"]["severity"] = 1

            if len(deleted_vulns) > 0:
                compare_vulns["deleted"] = deleted_vulns
                data_compares["alert"]["vuln_fixed"] += len(deleted_vulns)

            host2_data["vulns"] = compare_vulns
            if len(new_vulns) > 0 or len(deleted_vulns) > 0:
                host2_data["changed"] = "changed"

            # Compare sessions
            host1_sessions = np.array(host1_data["sessions"])
            host2_sessions = np.array(host2_data["sessions"])
            new_sessions = np.setdiff1d(host2_sessions, host1_sessions)
            deleted_sessions = np.setdiff1d(host1_sessions, host2_sessions)

            compare_sessions = {
                "new": np.array([]),
                "deleted": np.array([])
            }
            if len(new_sessions) > 0:
                compare_sessions["new"] = new_sessions
                data_compares["alert"]["sessions_news"] += len(new_sessions)

            if len(deleted_sessions) > 0:
                compare_sessions["deleted"] = deleted_services
                data_compares["alert"]["sessions_fixed"] += len(deleted_sessions)

            host2_data["sessions"] = compare_sessions
            if len(new_sessions) > 0 or len(deleted_sessions) > 0:
                host2_data["changed"] = "changed"

            if "changed" in host2_data and host2_data["changed"] == "changed":
                data_compares["host_details"].append(host2_data)

        if data_compares["alert"]["host_new"] > 0 or data_compares["alert"]["sessions_news"] > 0:
            if data_compares["alert"]["severity"] < 1:
                data_compares["alert"]["severity"] = 1
        elif data_compares["alert"]["sessions_news"] > 0:
            if data_compares["alert"]["severity"] < 2:
                data_compares["alert"]["severity"] = 2

        data_alert = {
            "content": {
                "statistics": task_two["statistics"],
                "alerts": data_compares["alert"]
            },
            "task": task_two["id"],
            "target": task_two["target"],
            "type": data_compares["alert"]["severity"]
        }

        try:
            system_alert_serializer = LoggingAlertSerializers(data=data_alert)
            system_alert_serializer.is_valid(raise_exception=True)
            system_alert_serializer.save()
        except Exception, ex:
            print "Cannot create system alerts"
        return JSONResponse(data_compares, status=status.HTTP_200_OK)

# /unit/id/office/id/targets/tid/compare
# class TasksCompare2Views(generics.CreateAPIView):
#     serializer_class = TaskCompare2Serializer
#     authentication_classes = (OneTokenAuthentication,)
#     permission_classes = (IsOneUserAuthenticated,)
#     renderer_classes = (JSONRenderer,)
#
#     def get_queryset(self):
#         task1 = self.request.data.get("taskid_one", None)
#         task2 = self.request.data.get("taskid_two", None)
#         queryset = TasksModel.objects.filter(pk__in=[task1, task2]).order_by('id')
#         if len(queryset) != 2:
#             raise TasksModel.DoesNotExist("Task is not found.")
#         elif queryset[0].target != queryset[1].target:
#             raise ValueError("The tasks is not in a same target.")
#         queryset = queryset.select_related('statistics')
#         queryset = queryset.prefetch_related('hosts')
#         return queryset
#
#     def create(self, request, *args, **kwargs):
#         # check data
#         task1 = self.request.data.get("taskid_one", None)
#         task2 = self.request.data.get("taskid_two", None)
#         if int(task1) > int(task2):
#             temp = task1
#             task1 = task2
#             task2 = temp
#
#         recompare = self.request.data.get("recompare", None)
#         data = {
#                 "task_one": task1,
#                 "task_two": task2,
#                 }
#         try:
#             task_compare = TaskCompareModels.objects.get(task_one_id=task1, task_two_id=task2)
#             if recompare:
#                 compare_serializer = TaskCompare2Serializer(task_compare, data=data, partial=True)
#                 compare_serializer.is_valid(raise_exception=True)
#                 task_compare = compare_serializer.save()
#         except TaskCompareModels.DoesNotExist:
#
#             compare_serializer = TaskCompare2Serializer(data=data)
#             compare_serializer.is_valid(raise_exception=True)
#             task_compare = compare_serializer.save()
#
#         return JSONResponse(TaskCompare2Serializer(task_compare).data, status=status.HTTP_200_OK)



# /unit/id/office/id/targets/id/tasks/id/
class TasksDetails(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = TasksSerializerInfoScans
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        # unit = UnitsModel.objects.get(pk=pk)
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.get(office=office, pk=pk2)
        else:
            target = TargetsModel.objects.get(office=office, pk=pk2, owner=self.request.user)
        queryset = TasksModel.objects.filter(target=target).order_by('-id')
        return queryset

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())
        obj = get_object_or_404(queryset, pk=self.kwargs['pk3'])

        # May raise a permission denied
        self.check_object_permissions(self.request, obj)

        return obj

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.status < 3:
            data = {
                "status": "error",
                "exception": "Stop job firse."
            }
            return JSONResponse(data, status=status.HTTP_400_BAD_REQUEST)
        if instance.target.last_task_id == instance.pk:
            data = {
                "status": "error",
                "exception": "not delete task last."
            }
            return JSONResponse(data, status=status.HTTP_400_BAD_REQUEST)
        self.perform_destroy(instance)
        return JSONResponse({}, status=status.HTTP_200_OK)


# /unit/id/office/id/targets/id/tasks/id/prev-curent-next/
class PrevCurentNext(generics.ListAPIView):
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        unit = UnitsModel.objects.get(pk=pk)
        office = OfficesModel.objects.get(pk=pk1, unit=unit)
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.get(office=office, pk=pk2)
        else:
            target = TargetsModel.objects.get(office=office, pk=pk2, owner=self.request.user)
        queryset = TasksModel.objects.filter(target=target).order_by('-id')
        return queryset

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())
        obj = get_object_or_404(queryset, pk=self.kwargs['pk3'])
        self.check_object_permissions(self.request, obj)
        return obj

    def get(self, request, *args, **kwargs):
        prev_crent_next = {"prev": None, "curent": None, "next": None, "first": None, "last": None}
        queryset = self.get_queryset()
        first = queryset.first()
        last = queryset.last()
        curent = self.get_object()
        prev = prev_in_order(curent, qs=queryset, loop=False)
        next = next_in_order(curent, qs=queryset, loop=False)

        prev_crent_next["curent"] = {"tasks": curent.id, "targets": curent.target.pk, "office": curent.target.office.id,
                                     "unit": curent.target.office.unit.id}
        if first != curent:
            prev_crent_next["first"] = {"tasks": first.id, "targets": first.target.pk,
                                        "office": first.target.office.id, "unit": first.target.office.unit.id}
        if last != curent:
            prev_crent_next["last"] = {"tasks": last.id, "targets": last.target.pk,
                                       "office": last.target.office.id, "unit": last.target.office.unit.id}
        if prev:
            prev_crent_next["prev"] = {"tasks": prev.id, "targets": prev.target.pk, "office": prev.target.office.id,
                                       "unit": prev.target.office.unit.id}
        if next:
            prev_crent_next["next"] = {"tasks": next.id, "targets": next.target.pk, "office": next.target.office.id,
                                       "unit": next.target.office.unit.id}
        return JSONResponse(prev_crent_next, status=status.HTTP_200_OK)


# /unit/id/office/id/targets/id/tasks/id/scans/
class ListScanOfTask(generics.ListAPIView):
    serializer_class = ScansSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        unit = UnitsModel.objects.get(pk=pk)
        office = OfficesModel.objects.get(pk=pk1, unit=unit)
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.get(office=office, pk=pk2)
        else:
            target = TargetsModel.objects.get(office=office, pk=pk2, owner=self.request.user)
        task = TasksModel.objects.get(target=target, pk=pk3)
        queryset = ScansModel.objects.filter(task=task).order_by('id')
        return queryset


# /unit/id/office/id/targets/id/tasks/id/scans/id/
class ScanTaskDetails(generics.RetrieveAPIView):
    serializer_class = ScansSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        unit = UnitsModel.objects.get(pk=pk)
        office = OfficesModel.objects.get(pk=pk1, unit=unit)
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.get(office=office, pk=pk2)
        else:
            target = TargetsModel.objects.get(office=office, pk=pk2, owner=self.request.user)
        task = TasksModel.objects.get(target=target, pk=pk3)
        queryset = ScansModel.objects.filter(task=task).order_by('id')
        return queryset

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())
        obj = get_object_or_404(queryset, pk=self.kwargs['pk4'])

        # May raise a permission denied
        self.check_object_permissions(self.request, obj)
        return obj

# /units/{{unit-id}}/offices/{{office-id}}/targets/{{target-id}}/tasks/compares
# Get vuln alerts
class TopVulnsAlertOfTask(generics.ListAPIView):
    serializer_class = VulneratbilitySerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('name',)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        pk2 = self.kwargs['pk2']
        pk3 = self.kwargs['pk3']
        unit = UnitsModel.objects.get(pk=pk)
        office = OfficesModel.objects.get(pk=pk1, unit=unit)
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.get(office=office, pk=pk2)
        else:
            target = TargetsModel.objects.get(office=office, pk=pk2, owner=self.request.user)
        task = TasksModel.objects.get(target=target, pk=pk3)

        queryset = VulnerabilityModel.objects.prefetch_related('hosts', 'hosts__host', 'hosts__task').filter(Q(alert=True) & Q(hosts__task=task)).distinct()
        # queryset = queryset.filter(hosts__task=task)
        # queryset = queryset.prefetch_related('sessions')
        # queryset = queryset.annotate(host_counts=Count('hosts')).order_by('-host_counts')[:10]
        return queryset

    def list(self, request, *args, **kwargs):
        task_id = self.kwargs['pk3']
        queryset = self.filter_queryset(self.get_queryset())

        vulns_alerts = []
        for vulnerability in queryset:
            list_host_vulns = vulnerability.hosts.filter(task_id=task_id)
            vulnerability_info = VulneratbilitySerializer(vulnerability).data
            vulnerability_info["list_devices"] = []
            for host_vulns in list_host_vulns:
                  vulnerability_info["list_devices"].append({"id": host_vulns.host_id, "ip_addr": host_vulns.host.ip_addr})
            vulns_alerts.append(vulnerability_info)
        return JSONResponse(vulns_alerts, status=status.HTTP_200_OK)


