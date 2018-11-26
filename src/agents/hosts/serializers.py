# -*- coding: utf-8 -*-
from agents.monitor.models import WebsiteMonitorStatusModel
from rest_framework import serializers

from agents.hosts.models import HostStatisticsModel, HostsModel, HostDetailsModel
from sbox4web.rabbitmq import Rabbitmq

__author__ = 'TOANTV'


########################################################################################################################
#####                                            HOST STATISTIC                                                    #####
########################################################################################################################
class StatisticSerializer(serializers.ModelSerializer):
    status = serializers.SerializerMethodField(source='get_status', read_only=True)

    class Meta:
        model = HostStatisticsModel
        read_only_fields = ('host',)
        fields = '__all__'

    def get_status(self, obj):
        if WebsiteMonitorStatusModel.objects.filter(website=obj.host).count() > 0:
            mstatus = WebsiteMonitorStatusModel.objects.filter(website=obj.host).latest('id')
            return {
                "monitor_time": mstatus.monitor_time,
                "ping_status": mstatus.ping_status,
                "ping_response": mstatus.ping_response,
                "web_status": mstatus.web_status,
                "web_load_response": mstatus.web_load_response,
            }
        else:
            return {}


class InfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = HostDetailsModel
        read_only_fields = ('host',)
        fields = '__all__'

    def update(self, instance, validated_data):
        instance.hostname = validated_data.get('hostname', instance.hostname)
        instance.last_boot = validated_data.get('last_boot', instance.last_boot)
        instance.mac_addr = validated_data.get('mac_addr', instance.mac_addr)
        instance.ipv4 = validated_data.get('ipv4', instance.ipv4)
        if instance.ipv4 != "":
            instance.host.statistics.ip_addr = instance.ipv4
            instance.host.statistics.save()
        instance.ipv6 = validated_data.get('ipv6', instance.ipv6)
        instance.vendor = validated_data.get('vendor', instance.vendor)
        instance.status = validated_data.get('status', instance.status)
        instance.state = validated_data.get('state', instance.state)
        if 'os' in validated_data:
            os_diff = validated_data.get('os')
            os_old = instance.os
            for os_items in os_diff:
                if os_items not in os_old:
                    os_old.append(os_items)
            instance.os = os_old
        instance.save()
        return instance


# Host Create or Update Basic
class HostCreateUpdateSerializer(serializers.ModelSerializer):
    details = InfoSerializer(read_only=True)

    class Meta:
        model = HostsModel
        fields = '__all__'

    def create(self, validated_data):
        # Create host
        host = HostsModel.objects.create(**validated_data)

        # Create Host Details
        host_detail = HostDetailsModel(host=host)
        host_detail.save()

        # Create host Statistics
        host_statistic = HostStatisticsModel(host=host)
        host_statistic.save()

        # Update task statistic
        host.task.statistics.hosts_count += 1
        host.task.statistics.save()
        return host


# Create or Update with host detail
class HostCreateDetailsSerializer(serializers.ModelSerializer):
    details = InfoSerializer()

    class Meta:
        model = HostsModel
        fields = '__all__'

    def create(self, validated_data):
        host_detail_data = validated_data.pop("details")
        host_detail_serializer = InfoSerializer(data=host_detail_data)
        host_detail_serializer.is_valid(raise_exception=True)

        # Create host
        host = HostsModel.objects.create(**validated_data)

        # Create Host Details
        host_detail = host_detail_serializer.save(host=host)
        # host_detail.ipv4 = host.ip_addr
        host_detail.save()

        # Create host Statistics
        if "ipv4" in host_detail_data:
            host_statistic = HostStatisticsModel(host=host, ip_addr=host_detail_data["ipv4"])
        else:
            host_statistic = HostStatisticsModel(host=host)
        host_statistic.save()

        # Update task statistic
        host.task.statistics.hosts_count += 1
        host.task.statistics.save()
        return host

    def update(self, instance, validated_data):
        host_detail_data = validated_data.pop("details")
        host_detail = instance.details
        host_detail_serializer = InfoSerializer(host_detail, data=host_detail_data, partial=True)
        host_detail_serializer.is_valid(raise_exception=True)
        host_detail_serializer.save()

        instance.severity = validated_data.get('severity', instance.severity)
        instance.device_type = validated_data.get('device_type', instance.device_type)
        instance.status = validated_data.get('status', instance.status)
        instance.save()
        return instance


class HostSerializer(serializers.ModelSerializer):
    class Meta:
        model = HostsModel
        fields = '__all__'


class HostShortSerializer(serializers.ModelSerializer):
    class Meta:
        model = HostsModel
        fields = ('id', 'ip_addr')


class HostStatisticSerializer(serializers.ModelSerializer):
    statistics = StatisticSerializer(read_only=True)

    class Meta:
        model = HostsModel
        fields = '__all__'


# Host info
# /tasks/tid/hosts/info
class HostInfoSerializer(serializers.ModelSerializer):
    statistics = StatisticSerializer(read_only=True)
    details = InfoSerializer(read_only=True)

    class Meta:
        model = HostsModel
        fields = '__all__'
