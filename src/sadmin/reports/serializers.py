# -*- coding: utf-8 -*-

__author__ = 'TOANTV'
from rest_framework import serializers
from sadmin.reports.models import ReportsModel, ReportsTemplatesModel
from django.utils.translation import ugettext_lazy as _

########################################################################################################################
#####                                            REPORT SERIALIZER                                                 #####
########################################################################################################################
class ReportTemplateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportsTemplatesModel
        fields = '__all__'


class ReportTemplateDetailsSerializer(serializers.ModelSerializer):
    filter = serializers.SerializerMethodField(source='filter', read_only=True)

    class Meta:
        model = ReportsTemplatesModel
        fields = '__all__'

    def get_filter(self, obj):
        data = obj.filter
        for key, value in data.iteritems():
            data[key] = _(value)
        return data


class ReportTemplateInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportsTemplatesModel
        fields = ('id', 'type', 'name')


class ReportSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReportsModel
        fields = '__all__'


class ReportOfTargetDetailsSerializer(serializers.ModelSerializer):
    template = ReportTemplateInfoSerializer(read_only=True)

    class Meta:
        model = ReportsModel
        fields = '__all__'


class ReportDetailsSerializer(serializers.ModelSerializer):
    template = ReportTemplateDetailsSerializer(read_only=True)
    # unit = serializers.SerializerMethodField(source='unit', read_only=True)
    # office = serializers.SerializerMethodField(source='office', read_only=True)
    # task = serializers.SerializerMethodField(source='task', read_only=True)
    # target = serializers.SerializerMethodField(source='target', read_only=True)

    class Meta:
        model = ReportsModel
        fields = '__all__'

        # def get_task(self, obj):
        #     task = obj.task
        #     return {"id": task.id,
        #             "target_addr": task.target_addr,
        #             "start_time": task.start_time,
        #             "finish_time": task.finish_time,
        #             "severity": task.severity,
        #             "statistics": StatisticsSerializers(task.statistics).data
        #             }
        #
        # def get_target(self, obj):
        #     return {"id": obj.task.target.id, "name": obj.task.target.name}
        #
        # def get_office(self, obj):
        #     office = obj.task.target.office
        #     return {"id": office.id, "name": office.name}
        #
        # def get_unit(self, obj):
        #     unit = obj.task.target.office.unit
        #     return {"id": unit.id, "name": unit.name}
