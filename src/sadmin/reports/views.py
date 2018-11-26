# -*- coding: utf-8 -*-
import os
from django.conf import settings

__author__ = 'TOANTV'

from sbox4web.libs import *
from django.db.models import Q

from rest_framework import generics
from rest_framework import status
from rest_framework import filters
from rest_framework.renderers import JSONRenderer
from rest_framework.exceptions import ValidationError

from django_filters.rest_framework import DjangoFilterBackend

from sbox4web.views import JSONResponse
from units.models import OfficesModel
from targets.models import TargetsModel, TasksModel
from sadmin.reports.models import ReportsTemplatesModel, ReportsModel
from sadmin.reports.serializers import ReportTemplateSerializer, ReportSerializer, ReportDetailsSerializer, \
    ReportOfTargetDetailsSerializer, ReportTemplateDetailsSerializer
from one_auth.authentication import OneTokenAuthentication
from one_users.permissions import IsOneUserAuthenticated, IsOneUserScanner, IsOneUserReadOnlyOrSuperAdmin


class ReportsTemplateListView(generics.ListCreateAPIView):
    queryset = ReportsTemplatesModel.objects.all()
    serializer_class = ReportTemplateSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserReadOnlyOrSuperAdmin,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('type',)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = ReportTemplateDetailsSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = ReportTemplateDetailsSerializer(queryset, many=True)
        return JSONResponse(serializer.data, status=status.HTTP_200_OK)


class ReportTemplateDetails(generics.RetrieveUpdateDestroyAPIView):
    queryset = ReportsTemplatesModel.objects.all()
    serializer_class = ReportTemplateSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserReadOnlyOrSuperAdmin,)
    renderer_classes = (JSONRenderer,)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = ReportTemplateDetailsSerializer(instance)
        return JSONResponse(serializer.data)

########################################################################################################################
#####                                              REPORT API                                                     ######
########################################################################################################################
# /reports
class ReportsListView(generics.CreateAPIView):
    serializer_class = ReportDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('template', 'status',)

    def get_queryset(self):
        queryset = ReportsModel.objects.all().order_by('-id')
        # if self.request.user.is_smod == 1 or self.request.user.is_superuser:
        #     queryset = ReportsModel.objects.all().order_by('-id')
        # else:
        #     queryset = ReportsModel.objects.select_related('task__target__owner').filter(
        #         task__target__owner=self.request.user).order_by('-id')
        # queryset = queryset.select_related('task', 'template', 'task__target', 'task__target__office',
        #                                    'task__target__office__unit')
        # search_query = self.request.GET.get('search', None)
        # if search_query is not None:
        #     queryset = queryset.filter(
        #         Q(task__target_addr__contains=search_query) | Q(task__target__name__contains=search_query))
        return queryset

    def post(self, request, *args, **kwargs):
        data = request.data
        report_models = None
        if isinstance(data, dict) and data["template"] in [5,6]  and "target" in data :
            report_models = ReportsModel.objects.filter(template_id=data["template"], target=data["target"])
        elif isinstance(data, dict) and data["template"] in [7,8]  and "task" in data :
            report_models =  ReportsModel.objects.filter(template_id=data["template"], task=data["task"])

        if report_models is not None and report_models.count() > 0:
            report_model = report_models[0]

            if report_model.template_id == 5 or report_model.template_id == 6:
                target = TargetsModel.objects.filter(pk=report_model.target)
                if target.count() == 1:
                    last_task_finish = get_last_task_finish(target[0])
                    report_model.task = last_task_finish.id
                    report_model.save()
        else:
            serializer = ReportSerializer(data=data)
            serializer.is_valid(raise_exception=True)
            report_model = serializer.save()

            if report_model.template_id == 5 or report_model.template_id == 6:
                target = TargetsModel.objects.filter(pk=report_model.target)
                if target.count() == 1:
                    last_task_finish = get_last_task_finish(target[0])
                    report_model.task = last_task_finish.id
                    report_model.save()

        # Add report job to rabbitmq
        if report_model.download_link is None or report_model.download_link == "" or not os.path.isfile(os.path.join(settings.GUI_PATH, report_model.download_link)):
            add_report_job(report_model)
        return JSONResponse(ReportDetailsSerializer(report_model).data, status=status.HTTP_201_CREATED)


# /reports/rid
class ReportDetailsView(generics.RetrieveUpdateDestroyAPIView):
    queryset = ReportsModel.objects.all().order_by('-id')
    serializer_class = ReportDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserReadOnlyOrSuperAdmin,)
    renderer_classes = (JSONRenderer,)
    filter_fields = ('template', 'status',)

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()

        # Delete report  file
        # if instance.download_link is not None and instance.download_link != "":
        #     if os.path.isfile(os.path.join(settings.GUI_PATH, instance.download_link)):
        #         os.remove(os.path.join(settings.GUI_PATH, instance.download_link))

        self.perform_destroy(instance)
        return JSONResponse({}, status=status.HTTP_204_NO_CONTENT)


# /agents/reports
class ReportsAgentsListView(generics.ListAPIView):
    serializer_class = ReportDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('template', 'status',)

    def get_queryset(self):
        queryset = ReportsModel.objects.all().order_by('-id')
        queryset = queryset.select_related('template')
        return queryset


# /agents/reports/id
class ReportAgentDetailsView(generics.RetrieveUpdateAPIView):
    queryset = ReportsModel.objects.all()
    serializer_class = ReportDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        queryset = ReportsModel.objects.all().order_by('-id')
        queryset = queryset.select_related('template')
        return queryset


# /unit/id/office/id/targets/id/tasks/id/reports
class ReportsOfTaskListView(generics.ListCreateAPIView):
    serializer_class = ReportOfTargetDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        uid = self.kwargs['pk']
        oid = self.kwargs['pk1']
        tarid = self.kwargs['pk2']
        tasid = self.kwargs['pk3']

        # unit = UnitsModel.objects.get(pk=pk)
        office = OfficesModel.objects.select_related('unit').get(pk=oid, unit_id=uid)
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.get(office=office, pk=tarid)
        else:
            target = TargetsModel.objects.get(office=office, pk=tarid, owner=self.request.user)
        task = TasksModel.objects.get(target=target, pk=tasid)
        queryset = ReportsModel.objects.select_related('template').filter(task=task).order_by('-id')
        return queryset

    def post(self, request, *args, **kwargs):
        data = request.data
        data["task"] = self.kwargs['pk3']
        try:
            serializer = ReportSerializer(data=data)
            serializer.is_valid(raise_exception=True)
            report_model = serializer.save()
            return JSONResponse(ReportDetailsSerializer(report_model).data, status=status.HTTP_201_CREATED)
        except ValidationError:
            if "task" in request.data and "template" in request.data:
                report_model = ReportsModel.objects.get(task_id=data["task"],
                                                        template_id=data["template"])
                return JSONResponse(ReportDetailsSerializer(report_model).data, status=status.HTTP_201_CREATED)
            else:
                error = {"status": "error",
                         "exception": "task and template is the required fields"
                         }
                return JSONResponse(error, status=status.HTTP_400_BAD_REQUEST)


# /unit/id/office/id/targets/id/reports
class ReportsOfTargetListView(generics.ListCreateAPIView):
    serializer_class = ReportOfTargetDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        uid = self.kwargs['pk']
        oid = self.kwargs['pk1']
        tarid = self.kwargs['pk2']

        # unit = UnitsModel.objects.get(pk=pk)
        office = OfficesModel.objects.select_related('unit').get(pk=oid, unit_id=uid)
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            target = TargetsModel.objects.get(office=office, pk=tarid)
        else:
            target = TargetsModel.objects.select_related('statistics').get(office=office, pk=tarid,
                                                                           owner=self.request.user)
        task = target.statistics.task
        queryset = ReportsModel.objects.select_related('template').filter(task=task).order_by('-id')
        return queryset

    def post(self, request, *args, **kwargs):
        data = request.data
        target = TargetsModel.objects.get(pk=self.kwargs['pk2'])
        data["task"] = target.statistics.task_id
        try:
            serializer = ReportSerializer(data=data)
            serializer.is_valid(raise_exception=True)
            report_model = serializer.save()
            return JSONResponse(ReportDetailsSerializer(report_model).data, status=status.HTTP_201_CREATED)
        except ValidationError:
            if "task" in request.data and "template" in request.data:
                report_model = ReportsModel.objects.get(task_id=data["task"],
                                                        template_id=data["template"])
                return JSONResponse(ReportDetailsSerializer(report_model).data, status=status.HTTP_201_CREATED)
            else:
                error = {"status": "error",
                         "exception": "task and template is the required fields"
                         }
                return JSONResponse(error, status=status.HTTP_400_BAD_REQUEST)
