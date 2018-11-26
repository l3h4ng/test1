# -*- coding: utf-8 -*-
import time

__author__ = 'TOANTV'
from rest_framework import serializers

from targets.models import SchedulerModel, TargetsModel, TasksModel, TargetStatisticsModel
from targets.serializers import TargetConfigurationsDetailsSerializers, TasksCreateSerializer


class TargetSchedulerSerializers(serializers.ModelSerializer):
    target = serializers.SerializerMethodField(source='target', read_only=True)

    class Meta:
        model = SchedulerModel
        read_only_fields = ('configurations', 'status', 'time_interval', 'started_at',)
        fields = '__all__'

    def get_target(self, obj):
        target_id = obj.configurations.target_id
        return target_id


# /units/uid/offices/oid/targets/tid
class TargetTimeDetailsInfoSerializer(serializers.ModelSerializer):
    configuration = TargetConfigurationsDetailsSerializers(read_only=True)
    office = serializers.SerializerMethodField(source='office', read_only=True)
    unit = serializers.SerializerMethodField(source='unit', read_only=True)
    last_task = serializers.SerializerMethodField(source='last_task', read_only=True)

    class Meta:
        model = TargetsModel
        read_only_fields = (
            'owner', 'created_at', 'tasks_count', 'report_file', 'last_task_id', 'severity', 'name', 'address')
        fields = '__all__'

    def get_office(self, obj):
        return {"id": obj.office.id, "name": obj.office.name}

    def get_unit(self, obj):
        unit = obj.office.unit
        return {"id": unit.id, "name": unit.name}

    def get_last_task(self, obj):
        if obj.tasks.count() > 0:
            last_task = obj.tasks.get(pk=obj.last_task_id)
            return {"id": last_task.id, "start_time": last_task.start_time}
        else:
            return []

    def update(self, instance, validated_data):
        status = validated_data.get('status', instance.status)
        if instance.status != status:
            if status == 0:
                if instance.status >= 0 and instance.status <= 2:
                    raise ValueError(_("Stop job first."))
                else:
                    # create task
                    task_data = {"name": "%s_%s" % (instance.name, str(int(time.time()))),
                                 "target": instance.id,
                                 "target_addr": instance.address}
                    task_serializer = TasksCreateSerializer(data=task_data)
                    task_serializer.is_valid(raise_exception=True)
                    task = task_serializer.save()

                    instance.tasks_count += 1

                    if not TargetStatisticsModel.objects.filter(target=instance).exists():
                        target_statistic = TargetStatisticsModel(target=instance, task=task)
                        target_statistic.save()
                    # else:
                    #     if instance.last_task_id > 0:
                    #         # Update last task
                    #         last_task = TasksModel.objects.get(pk=instance.last_task_id)
                    #         last_task.is_lasted = False
                    #         last_task.save()

                    instance.last_task_id = task.id
                    instance.status = 0
                    instance.save()

            if status == 1:
                if instance.status != 0:
                    raise ValueError(_("Cannot change target status from {0} to 1".format(str(instance.id))))

                # Update task
                print "Update task 0 --> 1"
                task = TasksModel.objects.get(pk=instance.last_task_id)
                task_serializer = TasksCreateSerializer(task, {"status": 1}, partial=True)
                task_serializer.is_valid(raise_exception=True)
                task_serializer.save()
                print "Finish update task 0 --> 1"

                # Update target
                instance.status = 1
        instance.save()
        return instance