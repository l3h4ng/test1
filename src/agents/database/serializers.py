# -*- coding: utf-8 -*-
__author__ = 'TOANTV'
from rest_framework import serializers
from agents.database.models import WebsiteDatabasesModel


########################################################################################################################
#####                                            HOST SERVICES                                                     #####
########################################################################################################################
class WebsiteDatabaseSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebsiteDatabasesModel
        fields = '__all__'

    # def create(self, validated_data):
    #     web_database = WebsiteDatabasesModel.objects.create(**validated_data)
    #
    #     # Update host statistics
    #     host_statistic = web_database.website.statistics
    #     host_statistic.db_attack_count += 1
    #     host_statistic.save()
    #
    #     # Update task statistics
    #     task_statistic = web_database.website.task.statistics
    #     task_statistic.db_attack_count += 1
    #     task_statistic.severity = 3
    #     task_statistic.save()
    #     return web_database
