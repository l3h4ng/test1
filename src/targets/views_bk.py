from time import sleep

from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from rest_framework import generics
from rest_framework import status
from rest_framework.generics import get_object_or_404
from rest_framework.renderers import JSONRenderer

from one_auth.authentication import OneTokenAuthentication
from one_users.permissions import IsOneUserAuthenticated
from plugins.models import PluginsModel
from sbox4web.views import JSONResponse
from targets.controller import create_tasks, setTimeSchedulerAfterScan, get_list_email, checkTasksAfterScans, \
    get_list_email_notify, prev_in_order, next_in_order
from targets.controller import setTimeScheduler
from targets.models import ScansModel, TasksModel, TargetsModel, SchedulerModel
from targets.serializers import TargetSerializer, SchedulerSerializers, \
    TargetConfigurationsSerializers, TasksSerializer, ScansSerializer, TasksSerializerInfoScans, StatisticsSerializers
from units.models import UnitsModel, OfficesModel
from units.serializers import UnitsShortInfoSerializer, OfficesShortInfoSerializer


# /unit/id/office/id/targets/
class TargetsOfUnitView(generics.ListCreateAPIView):
    # queryset = TargetsModel.objects.order_by('-id')
    serializer_class = TargetSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('name', 'status', 'office', 'address', 'severity')
    search_fields = ('name', 'address')

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        unit = UnitsModel.objects.get(pk=pk)
        office = OfficesModel.objects.get(pk=pk1, unit=unit)
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            queryset = TargetsModel.objects.filter(office=office).order_by('-id')
        else:
            queryset = TargetsModel.objects.filter(owner=self.request.user, office=office).order_by('-id')
        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            for target_serializer in serializer.data:
                office = OfficesModel.objects.get(pk=target_serializer["office"])
                try:
                    last_task = TasksModel.objects.get(pk=target_serializer["last_task_id"])
                    last_task_data = TasksSerializer(last_task).data
                except:
                    last_task_data = None
                target_serializer.update({"last_task": last_task_data,
                                          "unit": UnitsShortInfoSerializer(office.unit).data,
                                          "office": OfficesShortInfoSerializer(office).data})
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)
        for target_serializer in serializer.data:
            try:
                last_task = TasksModel.objects.get(pk=target_serializer["last_task_id"])
                last_task_data = TasksSerializer(last_task).data
            except:
                last_task_data = None
            office = OfficesModel.objects.get(pk=target_serializer["office"])
            target_serializer.update({"last_task": last_task_data,
                                      "unit": UnitsShortInfoSerializer(office.unit).data,
                                      "office": OfficesShortInfoSerializer(office).data, })
            target_serializer["configuration"]["email_notify"] = get_list_email_notify(
                target_serializer["configuration"]["email_notify"])
        return JSONResponse(serializer.data, status=status.HTTP_200_OK)

    def post(self, request, *args, **kwargs):
        pk1 = self.kwargs['pk1']
        office = OfficesModel.objects.get(pk=pk1)

        # target configurations valid data
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
            target_configuration_serializer = TargetConfigurationsSerializers(data=data)
            target_configuration_serializer.is_valid(raise_exception=True)

            # Target scheduler valid
            if "scheduler" in data:
                scheduler_serializer = SchedulerSerializers(data=data["scheduler"])
                scheduler_serializer.is_valid(raise_exception=True)
            else:
                data = {
                    "status": "error",
                    "exception": "Scheduler not null"
                }
                return JSONResponse(data, status=status.HTTP_400_BAD_REQUEST)
        else:
            data = {
                "status": "error",
                "exception": "configuration not null"
            }
            return JSONResponse(data, status=status.HTTP_400_BAD_REQUEST)
        # target object
        target_serializer = self.get_serializer(data=request.data)
        target_serializer.is_valid(raise_exception=True)
        target_serializer.save(owner=request.user, office=office)
        target_model = TargetsModel.objects.get(pk=target_serializer.data['id'])

        target_configuration_serializer.save(target=target_model)
        scheduler_serializer.save(configurations=target_model.configuration)
        setTimeScheduler(scheduler=target_model.configuration.scheduler)
        create_tasks(target=target_model)
        return JSONResponse(TargetSerializer(target_model).data, status=status.HTTP_201_CREATED)


# /unit/id/office/id/targets/id/
class TargetDetails(generics.RetrieveUpdateDestroyAPIView):
    # queryset = TargetsModel.objects.all()
    serializer_class = TargetSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        unit = UnitsModel.objects.get(pk=pk)
        office = OfficesModel.objects.get(pk=pk1, unit=unit)
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            queryset = TargetsModel.objects.filter(office=office).order_by('-id')
        else:
            queryset = TargetsModel.objects.filter(owner=self.request.user, office=office).order_by('-id')
        return queryset

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())

        # Perform the lookup filtering.
        lookup_url_kwarg = self.lookup_url_kwarg or self.lookup_field

        assert lookup_url_kwarg in self.kwargs, (
            'Expected view %s to be called with a URL keyword argument '
            'named "%s". Fix your URL conf, or set the `.lookup_field` '
            'attribute on the view correctly.' %
            (self.__class__.__name__, lookup_url_kwarg)
        )

        obj = get_object_or_404(queryset, pk=self.kwargs['pk2'])

        # May raise a permission denied
        self.check_object_permissions(self.request, obj)

        return obj

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance).data
        try:
            last_task = TasksModel.objects.get(pk=serializer["last_task_id"])
            last_task_data = TasksSerializer(last_task).data
        except:
            last_task_data = None
        office = OfficesModel.objects.get(pk=serializer["office"])
        serializer.update({"last_task": last_task_data,
                           "unit": UnitsShortInfoSerializer(office.unit).data,
                           "office": OfficesShortInfoSerializer(office).data})
        serializer["configuration"]["email_notify"] = get_list_email_notify(serializer["configuration"]["email_notify"])
        return JSONResponse(serializer, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        sleep(1)
        partial = kwargs.pop('partial', True)
        instance = self.get_object()

        if "status" in request.data:
            old_status = instance.status
            new_status = int(request.data["status"])
            if new_status != old_status:
                if new_status != 0 and new_status != 3 and new_status != 1:
                    data = {
                        "status": "error",
                        "exception": "Status is 0 or 1 or 3"
                    }
                    return JSONResponse(data, status=status.HTTP_400_BAD_REQUEST)

                if new_status == 0 and old_status <= 2:
                    data = {
                        "status": "error",
                        "exception": "Stop job firse."
                    }
                    return JSONResponse(data, status=status.HTTP_400_BAD_REQUEST)

                if new_status == 0 and old_status >= 3:
                    create_tasks(target=instance)
                if new_status == 3 and old_status < 3:
                    import datetime
                    instance.status = 3
                    instance.last_scan = datetime.datetime.now()
                    instance.save()
                    setTimeSchedulerAfterScan(instance)
                    # setTimeScheduler(scheduler=instance.configuration.scheduler)
                    task = TasksModel.objects.filter(target=instance).order_by('id')
                    task_obj = task.last()
                    if task_obj.status < 3:
                        task_obj.status = 3
                        task_obj.stop_time = instance.last_scan
                        task_obj.save()
                        list_scans = ScansModel.objects.filter(task=task_obj)
                        for scan in list_scans:
                            if scan.status < 3:  # not increase with scan is error and finish
                                scan.status = 3
                                scan.save()

                if new_status == 1 and old_status < 1:
                    import datetime

                    instance.status = 1
                    # instance.last_scan = datetime.datetime.now()
                    instance.save()
                    setTimeSchedulerAfterScan(instance)
                    # setTimeScheduler(scheduler=instance.configuration.scheduler)
                    task = TasksModel.objects.filter(target=instance).order_by('id')
                    task_obj = task.last()
                    if task_obj.status < 1:
                        task_obj.status = 1
                        # task_obj.stop_time = instance.last_scan
                        task_obj.save()
                        list_scans = ScansModel.objects.filter(task=task_obj)
                        for scan in list_scans:
                            if scan.status < 1:  # not increase with scan is error and finish
                                # scan.start_id += 1
                                scan.status = 1
                                scan.save()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        if "configuration" in request.data:
            data_configuration = request.data["configuration"]
            if "email_notify" in data_configuration:
                list_email = get_list_email()
                for email in data_configuration["email_notify"]:
                    if email not in list_email:
                        data = {
                            "status": "error",
                            "exception": "email: %s not exist." % email
                        }
                        return JSONResponse(data, status=status.HTTP_400_BAD_REQUEST)
            serializer_configuration = TargetConfigurationsSerializers(instance.configuration, data=data_configuration,
                                                                       partial=partial)
            serializer_configuration.is_valid(raise_exception=True)
            serializer_configuration.save()
            if "scheduler" in data_configuration:
                data_scheduler = data_configuration["scheduler"]
                instance_scheduler = instance.configuration.scheduler
                time_interval_old = instance_scheduler.time_interval
                start_at_old = instance_scheduler.started_at
                scheduler_serializer = SchedulerSerializers(instance_scheduler, data=data_scheduler,
                                                            partial=partial)
                scheduler_serializer.is_valid(raise_exception=True)
                scheduler_serializer.save()
                scheduler_new = SchedulerModel.objects.get(pk=scheduler_serializer.data["configurations"])
                if scheduler_serializer.data["status"]:
                    if "time_interval" in scheduler_serializer.data and "started_at" in scheduler_serializer.data:
                        time_interval_new = scheduler_new.time_interval
                        start_at_new = scheduler_new.started_at
                        if start_at_new != start_at_old or time_interval_new != time_interval_old or scheduler_new.next_time is None:
                            setTimeScheduler(scheduler=scheduler_new)

        if "office" in request.data:
            office = OfficesModel.objects.get(pk=request.data["office"])
            instance.office = office
            instance.save()
        target_model = self.get_object()

        serializer = self.get_serializer(target_model)
        serializer_data = serializer.data
        serializer_data["configuration"]["email_notify"] = get_list_email_notify(
            serializer_data["configuration"]["email_notify"])
        office = OfficesModel.objects.get(pk=serializer.data["office"])
        office_serializer = OfficesShortInfoSerializer(office)
        unit = UnitsModel.objects.get(offices=office)
        unit_serializer = UnitsShortInfoSerializer(unit)
        serializer_data.update({"unit": unit_serializer.data, "office_info": office_serializer.data})

        return JSONResponse(serializer_data, status=status.HTTP_200_OK)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        if instance.status < 3:
            data = {
                "status": "error",
                "exception": "Stop job firse."
            }
            return JSONResponse(data, status=status.HTTP_400_BAD_REQUEST)
        self.perform_destroy(instance)
        return JSONResponse({}, status=status.HTTP_204_NO_CONTENT)


# /unit/id/office/id/targets/status/
class GetTargetsStatus(generics.ListAPIView):
    serializer_class = TargetSerializer
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


# /unit/id/office/id/targets/id/tasks/
class TasksListOfTarget(generics.ListAPIView):
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('name', 'status', 'severity')
    search_fields = ('name',)
    serializer_class = TasksSerializerInfoScans

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


# /unit/id/office/id/targets/id/tasks/id/
class TasksDetails(generics.RetrieveDestroyAPIView):
    serializer_class = TasksSerializerInfoScans
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

        # Perform the lookup filtering.
        lookup_url_kwarg = self.lookup_url_kwarg or self.lookup_field

        assert lookup_url_kwarg in self.kwargs, (
            'Expected view %s to be called with a URL keyword argument '
            'named "%s". Fix your URL conf, or set the `.lookup_field` '
            'attribute on the view correctly.' %
            (self.__class__.__name__, lookup_url_kwarg)
        )

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


# /unit/id/office/id/targets/id/statistics/
class ListStatisticsView(generics.ListAPIView):
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    serializer_class = StatisticsSerializers
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('task', 'time_scan', 'vulns_count')
    search_fields = ('task', 'time_scan')

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
        queryset = [task.task_statistics for task in TasksModel.objects.filter(target=target).order_by('-id')]
        return queryset


class GetTargetStatus(generics.ListAPIView):
    serializer_class = TasksSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)

    def list(self, request, *args, **kwargs):
        pk = self.kwargs['pk']
        target = TargetsModel.objects.get(pk=pk)
        status_scans = {"total": TasksModel.objects.filter(target=target).count(),
                        "waitting": TasksModel.objects.filter(status=0,
                                                              target=target).count() + TasksModel.objects.filter(
                            status=1).count(), "stopped": TasksModel.objects.filter(status=3, target=target).count(),
                        "running": TasksModel.objects.filter(status=2, target=target).count(),
                        "error": TasksModel.objects.filter(status=4, target=target).count(),
                        "finish": TasksModel.objects.filter(status=5, target=target).count()}
        return JSONResponse(status_scans, status=status.HTTP_200_OK)


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

        # Perform the lookup filtering.
        lookup_url_kwarg = self.lookup_url_kwarg or self.lookup_field

        assert lookup_url_kwarg in self.kwargs, (
            'Expected view %s to be called with a URL keyword argument '
            'named "%s". Fix your URL conf, or set the `.lookup_field` '
            'attribute on the view correctly.' %
            (self.__class__.__name__, lookup_url_kwarg)
        )

        obj = get_object_or_404(queryset, pk=self.kwargs['pk3'])

        # May raise a permission denied
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


# -------------------------------------------------------------------------------

class TasksList(generics.ListCreateAPIView):
    queryset = TasksModel.objects.order_by('-id')
    serializer_class = TasksSerializerInfoScans
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('name', 'status', 'target_addr', 'severity')
    search_fields = ('name', 'target_addr')


class TaskDetails(generics.RetrieveUpdateAPIView):
    queryset = TasksModel.objects.all()
    serializer_class = TasksSerializerInfoScans
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)


## Scan
class ScansList(generics.ListAPIView):
    queryset = ScansModel.objects.all().order_by('-priority')
    serializer_class = ScansSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('task', 'status', 'tool')


class ScanDetails(generics.RetrieveUpdateDestroyAPIView):
    queryset = ScansModel.objects.all()
    serializer_class = ScansSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)

        # get url
        task_model = TasksModel.objects.get(pk=serializer.data['task'])
        scan_info = serializer.data
        scan_info["target"] = task_model.url
        return JSONResponse(scan_info, status=status.HTTP_200_OK)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return JSONResponse(serializer.data)

    def perform_update(self, serializer):
        serializer.save()
        scan_model = self.get_object()
        # check Task
        checkTasksAfterScans(scan_model=scan_model)
        # print "put scans"


class TaskScan(generics.RetrieveAPIView):
    # queryset = ScansModel.objects.all().order_by('-priority')
    serializer_class = ScansSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (DjangoFilterBackend,)
    filter_fields = ('task', 'status', 'tool')

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        target = TargetsModel.objects.get(pk=pk)
        queryset = ScansModel.objects.filter(task=TasksModel.objects.get(pk=pk1, target=target)).order_by('-priority')
        return queryset

        # def perform_create(self, serializer):
        #     serializer.save()
        #     task_model = TasksModel.objects.get(pk=serializer.data['task'])
        #     if task_model.status == 0:
        #         task_model.status = 1
        #         task_model.save()


class ScanTaskDetails(generics.RetrieveUpdateAPIView):
    # queryset = ScansModel.objects.all()
    serializer_class = ScansSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)

    def get_object(self):
        pk = int(self.kwargs['pk'])
        pk1 = int(self.kwargs['pk1'])
        pk2 = int(self.kwargs['pk2'])
        instance = ScansModel.objects.get(task=TasksModel.objects.get(pk=pk1, target=TargetsModel.objects.get(pk=pk)),
                                          tool=PluginsModel.objects.get(pk=pk2))
        return instance

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        task_model = TasksModel.objects.get(pk=serializer.data['task'])
        scan_info = serializer.data
        scan_info["target"] = task_model.report_file
        return JSONResponse(scan_info, status=status.HTTP_200_OK)

    def perform_update(self, serializer):
        serializer.save()
        scan_model = ScansModel.objects.get(pk=serializer.data['id'])
        # check Task
        checkTasksAfterScans(scan_model=scan_model)


class ScansInfos(generics.RetrieveAPIView):
    queryset = TasksModel.objects.all()
    serializer_class = TasksSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)

    def get(self, request, *args, **kwargs):
        pk = int(self.kwargs['pk'])
        pk1 = int(self.kwargs['pk1'])
        task = TasksModel.objects.get(target=TargetsModel.objects.get(pk=pk), pk=pk1)
        # task_info = NetworkGeneralReport().get_task_quick_info(task)
        task_info = {}
        return JSONResponse(task_info, status=status.HTTP_200_OK)
