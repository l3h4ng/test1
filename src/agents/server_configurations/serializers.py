# -*- coding: utf-8 -*-
from agents.server_configurations.models import ServerConfigurationsModel

__author__ = 'TOANTV'

from rest_framework import serializers
from agents.crawldata.models import CrawlDataModel



########################################################################################################################
#####                                            WEBSITE CRAWLDATA                                                 #####
########################################################################################################################
class ServerConfigurationsSerializer(serializers.ModelSerializer):
    # children = serializers.SerializerMethodField(source='children', read_only=True)
    class Meta:
        model = ServerConfigurationsModel
        # read_only_fields = ('website',)
        fields = '__all__'

    # def get_children(self, obj):
    #     childrens = CrawlDataModel.objects.filter(pk=obj.parent_id)
    #     return CrawlDataSerializer(childrens).data


    def create(self, validated_data):
        server_config_vulns = ServerConfigurationsModel.objects.create(**validated_data)

        # Update host statistics
        host_statistic = server_config_vulns.website.statistics
        host_statistic.server_configs_count += 1
        host_statistic.save()

        # Update task statistics
        task_statistic = server_config_vulns.website.task.statistics
        task_statistic.server_configs_count += 1
        task_statistic.save()
        return server_config_vulns
