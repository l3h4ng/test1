# -*- coding: utf-8 -*-
from agents.crawldata.serializers import CrawlDataSerializer
from agents.crawldata.views import CrawlDataDetails
from agents.technologies.serializers import WebsiteTechnologiesSerializer
from agents.vulns.serializers import HostVulnerabilityDetailSerializer

__author__ = 'TOANTV'
from agents.hosts.models import HostsModel
from agents.hosts.serializers import InfoSerializer, StatisticSerializer
from agents.services.serializers import ServiceSerializer

from rest_framework import serializers

# /units/uid/offices/oid/targets/tid/tasks/tid/hosts/details
class HostOfTaskOverviewsSerializer(serializers.ModelSerializer):
    statistics = StatisticSerializer(read_only=True)

    class Meta:
        model = HostsModel
        fields = '__all__'


# /units/uid/offices/oid/targets/tid/tasks/tid/hosts/details
class GatheringInformationSerializer(serializers.ModelSerializer):
    details = InfoSerializer(read_only=True)
    # services = ServiceSerializer(read_only=True, many=True)
    services = serializers.SerializerMethodField(source='services', read_only=True)
    technologies = WebsiteTechnologiesSerializer(many=True, read_only=True)

    class Meta:
        model = HostsModel
        fields = '__all__'

    def get_services(self, obj):
        # list_services = HostServicesModel.objects.filter(host=obj).order_by("port")
        list_services = obj.services.all().order_by("port")
        return ServiceSerializer(list_services, many=True).data


# /units/uid/offices/oid/targets/tid/tasks/tid/hosts/details
class VunerabilitiesScanSerializer(serializers.ModelSerializer):
    statistics = StatisticSerializer(read_only=True)
    vulns = HostVulnerabilityDetailSerializer(read_only=True, many=True)

    class Meta:
        model = HostsModel
        fields = '__all__'


# /units/uid/offices/oid/targets/tid/tasks/tid/hosts/details
class WebsiteCrawlerDataSerializer(serializers.ModelSerializer):
    statistics = StatisticSerializer(read_only=True)
    crawls = CrawlDataSerializer(read_only=True, many=True)

    class Meta:
        model = HostsModel
        fields = '__all__'


# /units/uid/offices/oid/targets/tid/tasks/tid/hosts/details
class PentestrationTestingSerializer(serializers.ModelSerializer):
    statistics = StatisticSerializer(read_only=True)

    class Meta:
        model = HostsModel
        fields = '__all__'
