# -*- coding: utf-8 -*-
__author__ = 'TOANTV'
from rest_framework import serializers
from agents.hosts.models import HostDetailsModel
from agents.hosts.serializers import StatisticSerializer
from agents.vulns.models import VulnerabilityModel, HostVulnerabilityModel


class VulneratbilitySerializer(serializers.ModelSerializer):
    class Meta:
        model = VulnerabilityModel
        fields = '__all__'
