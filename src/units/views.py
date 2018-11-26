from django.db.models import Prefetch
from django.utils.translation import ugettext_lazy as _
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import filters
from rest_framework import generics
from rest_framework import status
from rest_framework.renderers import JSONRenderer

from one_auth.authentication import OneTokenAuthentication
from one_users.permissions import IsOneUserAuthenticated, IsAnyOneReadOnly
from sbox4web.libs import update_office_statistic
from sbox4web.views import JSONResponse
from targets.models import TargetsModel
from targets.serializers import TargetDetailsSerializer, TargetStatusSerializer
from units.models import UnitsModel, OfficesModel, OfficesStatistics
from units.serializers import UnitsSerializer, OfficesSerializer, UnitStatusSerializer, OfficeStatusSerializer, \
    UnitTreeSerializer, OfficesStatisticSerializer


class UnitsList(generics.ListCreateAPIView):
    serializer_class = UnitsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    search_fields = ('name',)
    filter_fields = ('name',)

    def get_queryset(self):
        queryset = UnitsModel.objects.all().order_by('-severity')
        queryset = queryset.prefetch_related(Prefetch('offices',
                                                      queryset=OfficesModel.objects.only('name', 'id',
                                                                                         'unit_id').all()))
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            return queryset
        else:
            return queryset.filter(owner=self.request.user)

    def create(self, request, *args, **kwargs):
        # data = request.data
        # data["owner"] = request.user.id
        serializer = UnitsSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(owner=request.user)
        return JSONResponse(serializer.data, status=status.HTTP_201_CREATED)


class UnitDetails(generics.mixins.RetrieveModelMixin,
                  generics.mixins.UpdateModelMixin,
                  generics.mixins.DestroyModelMixin,
                  generics.GenericAPIView):
    serializer_class = UnitsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        queryset = UnitsModel.objects.all()
        queryset = queryset.prefetch_related(Prefetch('offices',
                                                      queryset=OfficesModel.objects.only('name', 'id',
                                                                                         'unit_id').all()))
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            return queryset
        else:
            return queryset.filter(owner=self.request.user)

    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        return self.update(request, *args, **kwargs)

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        list_offices = OfficesModel.objects.filter(unit=instance)
        if len(list_offices) > 0:
            msg = _('You cannot delete unit if unit have one or many offices.')
            return JSONResponse({'status': 'error', 'error': msg},
                                status=status.HTTP_403_FORBIDDEN)
        self.perform_destroy(instance)
        return JSONResponse({'status': 'success'}, status=status.HTTP_204_NO_CONTENT)


class OfficesOfUnitList(generics.ListCreateAPIView):
    serializer_class = OfficesSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    search_fields = ('name',)
    filter_fields = ('name', 'unit')

    def get_queryset(self):
        pk = self.kwargs['pk']
        unit = UnitsModel.objects.get(pk=pk)
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            queryset = OfficesModel.objects.select_related('unit').select_related('owner').all()
            queryset = queryset.prefetch_related('targets').filter(unit=unit)
        else:
            queryset = OfficesModel.objects.select_related('unit').select_related('owner').all()
            queryset = queryset.prefetch_related('targets').filter(owner=self.request.user, unit=unit)
        queryset = queryset.order_by('-severity')
        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = self.get_serializer(queryset, many=True)

        return JSONResponse(serializer.data, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        pk = self.kwargs['pk']
        unit = UnitsModel.objects.get(pk=pk)
        # data=request.data
        # data["owner"] = request.user.id
        # data["unit"] = unit.id
        serializer = OfficesSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save(unit=unit, owner=request.user)
        # office = OfficesModel.objects.get(name=serializer.data['name'],unit=unit)
        # serializer = OfficesSerializer(office)
        return JSONResponse(serializer.data, status=status.HTTP_201_CREATED)  # , headers=headers)


class OfficeOfUnitDetails(generics.mixins.RetrieveModelMixin,
                          generics.mixins.UpdateModelMixin,
                          generics.mixins.DestroyModelMixin,
                          generics.GenericAPIView):
    # queryset = OfficesModel.objects.all()
    serializer_class = OfficesSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        self.kwargs['pk'] = pk1
        unit = UnitsModel.objects.get(pk=pk)
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            queryset = OfficesModel.objects.select_related('unit').select_related('owner').all()
            queryset = queryset.prefetch_related('targets').filter(unit=unit)
        else:
            queryset = OfficesModel.objects.select_related('unit').select_related('owner').all()
            queryset = queryset.prefetch_related('targets').filter(owner=self.request.user, unit=unit, pk=pk1)
        return queryset

    def get(self, request, *args, **kwargs):
        return self.retrieve(request, *args, **kwargs)

    def put(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', True)
        pk = self.kwargs['pk']
        unit = UnitsModel.objects.get(pk=pk)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        serializer.save(unit=unit)
        return JSONResponse(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        list_tasks = TargetsModel.objects.filter(office=instance)
        if len(list_tasks) > 0:
            msg = _('You cannot delete office if office have one or many tasks.')
            return JSONResponse({'status': 'error', 'error': msg},
                                status=status.HTTP_403_FORBIDDEN)
        self.perform_destroy(instance)
        return JSONResponse({'status': 'success'}, status=status.HTTP_204_NO_CONTENT)


########################################################################################################################
###                                            UNIT STATISTICS                                                       ###
########################################################################################################################
class UnitStatisticView(generics.RetrieveAPIView):
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            queryset = UnitsModel.objects.filter(pk=pk)
        else:
            queryset = UnitsModel.objects.select_related('owner').filter(pk=pk, owner=self.request.user)
        return queryset

    def get(self, request, *args, **kwargs):
        data = {
            "offices_count": 0,
            "targets_count": 0,
            "targets_high_security_count": 0,
            "targets_medium_security_count": 0,
            "targets_low_security_count": 0
        }
        instance = self.get_object()
        data["offices_count"] = OfficesModel.objects.filter(unit=instance).count()
        data["targets_count"] = TargetsModel.objects.prefetch_related("office", "office__unit").filter(
            office__unit=instance).count()
        data["targets_high_security_count"] = TargetsModel.objects.prefetch_related("office", "office__unit").filter(
            office__unit=instance, severity=3).count()
        data["targets_medium_security_count"] = TargetsModel.objects.prefetch_related("office", "office__unit").filter(
            office__unit=instance, severity=2).count()
        data["targets_low_security_count"] = TargetsModel.objects.prefetch_related("office", "office__unit").filter(
            office__unit=instance, severity=1).count()
        return JSONResponse(data, status=status.HTTP_200_OK)


class UnitTopTargetsView(generics.ListAPIView):
    serializer_class = TargetDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('name', 'status', 'office', 'address', 'severity')
    search_fields = ('name', 'address')

    def get_queryset(self):
        pk = self.kwargs['pk']
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            queryset = TargetsModel.objects.select_related('office', 'office__unit', 'owner').filter(office__unit=pk)
            queryset.order_by('-severity')
        else:
            queryset = TargetsModel.objects.select_related('office', 'office__unit', 'owner').filter(office__unit=pk,
                                                                                                     owner=self.request.user)
            queryset.order_by('-severity')
        return queryset


########################################################################################################################
###                                            OFFICES STATISTICS                                                       ###
########################################################################################################################
class OfficeStatisticView(generics.RetrieveAPIView):
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            queryset = OfficesModel.objects.filter(unit_id=pk, id=pk1)
        else:
            queryset = UnitsModel.objects.select_related('owner').filter(unit_id=pk, id=pk1, owner=self.request.user)
        self.kwargs['pk'] = self.kwargs['pk1']
        return queryset

    def get(self, request, *args, **kwargs):
        instance = self.get_object()
        try:
            office_statistics = OfficesStatistics.objects.get(office=instance)
        except OfficesStatistics.DoesNotExist:
            office_statistics = update_office_statistic(office=instance)
        return JSONResponse(OfficesStatisticSerializer(office_statistics).data, status=status.HTTP_200_OK)


class OfficeTopTargetsView(generics.ListAPIView):
    serializer_class = TargetDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticated,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('name', 'status', 'office', 'address', 'severity')
    search_fields = ('name', 'address')

    def get_queryset(self):
        pk = self.kwargs['pk']
        pk1 = self.kwargs['pk1']
        office = OfficesModel.objects.select_related('unit').get(pk=pk1, unit_id=pk)
        if self.request.user.is_smod == 1 or self.request.user.is_superuser:
            queryset = TargetsModel.objects.select_related('office', 'office__unit', 'owner').filter(office=office)
            queryset.order_by('-severity')
        else:
            queryset = TargetsModel.objects.select_related('office', 'office__unit', 'owner').filter(office=office,
                                                                                                     owner=self.request.user)
            queryset.order_by('-severity')
        return queryset


########################################################################################################################
###                                         TARGET TREE                                                              ###
########################################################################################################################

class TargetTreeView(generics.ListAPIView):
    serializer_class = UnitTreeSerializer
    authentication_classes = []
    permission_classes = (IsAnyOneReadOnly,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    search_fields = ('name',)
    filter_fields = ('name',)

    def get_queryset(self):
        queryset = UnitsModel.objects.all()
        queryset = queryset.prefetch_related('offices').all()
        return queryset


class SystemScanStatusView(generics.ListAPIView):
    # serializer_class = UnitTreeSerializer
    authentication_classes = []
    permission_classes = (IsAnyOneReadOnly,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)

    def get_queryset(self):
        # if TargetsModel.objects.all().count() <= 10:
        queryset = TargetsModel.objects.all().order_by('-severity')
        self.serializer_class = TargetStatusSerializer

        # elif OfficesModel.objects.all().count() <= 10:
        #     queryset = OfficesModel.objects.all()
        #     self.serializer_class = OfficeStatusSerializer
        #
        # else:
        #     queryset = UnitsModel.objects.all()
        #     self.serializer_class = UnitStatusSerializer
        return queryset
