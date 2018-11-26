from __future__ import unicode_literals
# -*- coding: utf-8 -*-
from targets.models import TargetsModel

__author__ = 'TOANTV'
from one_users.serializers import OneUserSerializerEmail
from targets.serializers import TargetShortSerializer
from rest_framework import serializers
from units.models import UnitsModel, OfficesModel, OfficesStatistics, UnitsStatistics

class OfficesShortInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = OfficesModel
        fields = ('id', 'name', 'severity')

class UnitsShortInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = UnitsModel
        fields = ('id', 'name')


class UnitsSerializer(serializers.ModelSerializer):
    offices = OfficesShortInfoSerializer(many=True, read_only=True)

    class Meta:
        model = UnitsModel
        # fields = ('id', 'name', 'address', 'description', 'offices', 'owner')
        read_only_fields = ('owner',)
        fields = '__all__'


class OfficesSerializer(serializers.ModelSerializer):
    targets = TargetShortSerializer(many=True, read_only=True)
    unit = UnitsShortInfoSerializer(read_only=True)
    owner = OneUserSerializerEmail(read_only=True)

    class Meta:
        model = OfficesModel
        read_only_fields = ('unit', 'owner',)
        fields = '__all__'


class OfficesDetailsSerializer(serializers.ModelSerializer):
    targets = serializers.PrimaryKeyRelatedField(many=True, read_only=True)
    unit = UnitsShortInfoSerializer(read_only=True)
    owner = OneUserSerializerEmail(read_only=True)

    class Meta:
        model = OfficesModel
        read_only_fields = ('unit', 'owner',)
        fields = '__all__'


class UnitsStatisticSerializer(serializers.ModelSerializer):
    class Meta:
        model = UnitsStatistics
        read_only_fields = ('unit',)
        fields = '__all__'


class OfficesStatisticSerializer(serializers.ModelSerializer):
    class Meta:
        model = OfficesStatistics
        read_only_fields = ('office',)
        fields = '__all__'


class OfficeTreeSerializer(serializers.ModelSerializer):
    targets = TargetShortSerializer(many=True, read_only=True)

    class Meta:
        model = OfficesModel
        fields = ('id', 'name', 'severity', 'targets')


class UnitTreeSerializer(serializers.ModelSerializer):
    offices = OfficeTreeSerializer(many=True, read_only=True)

    class Meta:
        model = UnitsModel
        fields = ('id', 'name', 'offices')


class OfficeStatusSerializer(serializers.ModelSerializer):
    is_scanning = serializers.SerializerMethodField(source='is_scanning')
    unit = UnitsShortInfoSerializer(read_only=True)

    class Meta:
        model = OfficesModel
        fields = ('id', 'name', 'unit', 'severity', 'is_scanning')

    def get_is_scanning(self, obj):
        if TargetsModel.objects.filter(status=2, office=obj).count() > 0:
            return True
        else:
            return False


class UnitStatusSerializer(serializers.ModelSerializer):
    is_scanning = serializers.SerializerMethodField(source='is_scanning')

    class Meta:
        model = UnitsModel
        fields = ('id', 'name', 'severity', 'is_scanning')

    def get_is_scanning(self, obj):
        if TargetsModel.objects.select_related('office', 'office__unit').filter(status=2, office__unit=obj).count() > 0:
            return True
        else:
            return False