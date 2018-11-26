# -*- coding: utf-8 -*-
__author__ = 'TOANTV'

from agents.hosts.models import HostsModel
from agents.hosts.serializers import InfoSerializer, HostSerializer
from agents.services.models import HostServicesModel
from rest_framework import serializers
from django.utils.translation import ugettext_lazy as _


########################################################################################################################
#####                                            HOST SERVICES                                                     #####
########################################################################################################################
class ServiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = HostServicesModel
        # read_only_fields = ('ip_addr',)
        fields = '__all__'

    def create(self, validated_data):
        ip_addr = validated_data.get("ip_addr", validated_data["host"].ip_addr)
        validated_data["ip_addr"] = ip_addr
        service = HostServicesModel.objects.create(**validated_data)

        # Update host statistics
        host_statistic = service.host.statistics
        host_statistic.services_count += 1
        host_statistic.save()

        # Update task statistics
        task_statistic = service.host.task.statistics
        task_statistic.services_count += 1
        task_statistic.save()
        return service

    def update(self, instance, validated_data):
        instance.name = validated_data.get('name', instance.name)
        instance.protocol = validated_data.get('protocol', instance.protocol)
        instance.state = validated_data.get('state', instance.state)
        instance.version = validated_data.get('version', instance.version)
        instance.save()
        return instance

class HostServicesSerializer(serializers.ModelSerializer):
    details = InfoSerializer(read_only=True)
    services = ServiceSerializer(read_only=True, many=True)

    class Meta:
        model = HostsModel
        fields = '__all__'
