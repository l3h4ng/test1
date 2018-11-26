# -*- coding: utf-8 -*-
from targets.models import TasksModel

__author__ = 'TOANTV'
import time

from rest_framework import serializers
from agents.vulns.models import HostVulnerabilityModel
from sadmin.vulnerabilities.serializers import VulneratbilitySerializer


class HostVulneratbilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = HostVulnerabilityModel
        read_only_fields = ('detection_time',)
        fields = '__all__'

    def create(self, validated_data):
        validated_data["name"] = validated_data["vulnerability"].name
        host_vulns = HostVulnerabilityModel.objects.create(**validated_data)
        host_vulns.detection_time = int(time.time())
        host_vulns.save()

        # Update host statistics and task statistics
        host = host_vulns.host
        host_statistic = host.statistics
        host_statistic.vulns_count += 1

        task_statistic = host.task.statistics
        task_statistic.vulns_count += 1

        if host_vulns.vulnerability.severity == 0:
            host_statistic.info_count += 1
            task_statistic.info_count += 1
        if host_vulns.vulnerability.severity == 1:
            host_statistic.low_count += 1
            task_statistic.low_count += 1
            if host.severity < 1:
                host.severity = 1
            if task_statistic.severity < 1:
                task_statistic.severity = 1
        if host_vulns.vulnerability.severity == 2:
            host_statistic.medium_count += 1
            task_statistic.medium_count += 1
            if host.severity < 2:
                host.severity = 2
            if task_statistic.severity < 2:
                task_statistic.severity = 2
        if host_vulns.vulnerability.severity == 3:
            host_statistic.high_count += 1
            task_statistic.high_count += 1
            if host.severity < 3:
                host.severity = 3
            if task_statistic.severity < 3:
                task_statistic.severity = 3
        if host_vulns.vulnerability.severity == 4:
            host_statistic.critical_count += 1
            task_statistic.critical_count += 1
            if host.severity < 3:
                host.severity = 3
            if task_statistic.severity < 3:
                task_statistic.severity = 3
        host.task.severity = task_statistic.severity
        host.task.save()
        host_statistic.save()
        task_statistic.save()
        host.save()
        return host_vulns


class HostVulnerabilityDetailSerializer(serializers.ModelSerializer):
    vulnerability = VulneratbilitySerializer(read_only=True)

    class Meta:
        model = HostVulnerabilityModel
        fields = '__all__'


class HostVulnerabilityListDetailsSerializer(serializers.ModelSerializer):
    unit = serializers.SerializerMethodField(source='unit', read_only=True)
    office = serializers.SerializerMethodField(source='office', read_only=True)
    host = serializers.SerializerMethodField(source='unit', read_only=True)
    task = serializers.SerializerMethodField(source='task', read_only=True)
    target = serializers.SerializerMethodField(source='target', read_only=True)
    vulnerability = VulneratbilitySerializer(read_only=True)

    class Meta:
        model = HostVulnerabilityModel
        fields = '__all__'

    def get_task(self, obj):
        return {"id": obj.task.id, "target_addr": obj.task.target_addr}

    def get_target(self, obj):
        return {"id": obj.target.id, "name": obj.target.name}

    def get_office(self, obj):
        office = obj.target.office
        return {"id": office.id, "name": office.name}

    def get_unit(self, obj):
        unit = obj.target.office.unit
        return {"id": unit.id, "name": unit.name}

    def get_host(self, obj):
        host = obj.host
        return {"id": host.id, "ip_addr": host.ip_addr}


class HostVulnrabilitiesCreateSerializer(serializers.ModelSerializer):
    vulnerability = VulneratbilitySerializer()

    class Meta:
        model = HostVulnerabilityModel
        fields = '__all__'

    def create(self, validated_data):
        vulns_data = validated_data.pop("vulnerability")
        vulns_data["created_at"] = int(time.time())
        vulns_serializer = VulneratbilitySerializer(data=vulns_data)
        vulns_serializer.is_valid(raise_exception=True)
        vuln = vulns_serializer.save()

        # Create host
        validated_data["vulnerability"] = vuln
        validated_data["name"] = vuln.name
        host_vulns = HostVulnerabilityModel.objects.create(**validated_data)
        host_vulns.detection_time = int(time.time())
        host_vulns.save()

        # Update host statistics and task statistics
        host = host_vulns.host
        host_statistic = host.statistics
        host_statistic.vulns_count += 1

        task_statistic = host.task.statistics
        task_statistic.vulns_count += 1

        if host_vulns.vulnerability.severity == 0:
            host_statistic.info_count += 1
            task_statistic.info_count += 1
        if host_vulns.vulnerability.severity == 1:
            host_statistic.low_count += 1
            task_statistic.low_count += 1
            if host.severity < 1:
                host.severity = 1
            if task_statistic.severity < 1:
                task_statistic.severity = 1
        if host_vulns.vulnerability.severity == 2:
            host_statistic.medium_count += 1
            task_statistic.medium_count += 1
            if host.severity < 2:
                host.severity = 2
            if task_statistic.severity < 2:
                task_statistic.severity = 2
        if host_vulns.vulnerability.severity == 3:
            host_statistic.high_count += 1
            task_statistic.high_count += 1
            if host.severity < 3:
                host.severity = 3
            if task_statistic.severity < 3:
                task_statistic.severity = 3
        if host_vulns.vulnerability.severity == 4:
            host_statistic.critical_count += 1
            task_statistic.critical_count += 1
            if host.severity < 3:
                host.severity = 3
            if task_statistic.severity < 3:
                task_statistic.severity = 3
        host.task.severity = task_statistic.severity
        if TasksModel.objects.filter(target=host.task.target).count() == 1:
            host.task.target.severity = host.task.severity
            host.task.target.save()
        host.task.save()
        host_statistic.save()
        task_statistic.save()
        host.save()
        return host_vulns

    def update(self, instance, validated_data):
        # vulns_data = validated_data.pop("vulnerability")
        # vuln_info = instance.vulnerability
        # vulns_serializer = VulneratbilitySerializer(vuln_info, data=vulns_data, partial=True)
        # vulns_serializer.is_valid(raise_exception=True)
        # vulns_serializer.save()

        instance.name = validated_data.get('name', instance.name)
        instance.port = validated_data.get('port', instance.port)
        instance.type = validated_data.get('type', instance.type)
        instance.time_attack = validated_data.get('time_attack', instance.time_attack)
        instance.attack_module = validated_data.get('attack_module', instance.attack_module)
        instance.payload = validated_data.get('payload', instance.payload)
        instance.scanner_scan_id = validated_data.get('scanner_scan_id', instance.scanner_scan_id)
        instance.scanner_vuln_id = validated_data.get('scanner_vuln_id', instance.scanner_vuln_id)
        instance.save()
        return instance

# class HostVulnsDetailsSerializer(serializers.ModelSerializer):
#     statistic = StatisticSerializer(read_only=True)
#     vulnerability = VulneratbilitySerializer(read_only=True)
#
#     class Meta:
#         model = HostDetailsModel
#         fields = '__all__'
