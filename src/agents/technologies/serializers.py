# -*- coding: utf-8 -*-
__author__ = 'TOANTV'
from agents.technologies.models import WebsiteTechnologiesModel
from rest_framework import serializers

########################################################################################################################
#####                                            HOST TECHNOLOGY                                                   #####
########################################################################################################################
class WebsiteTechnologiesSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebsiteTechnologiesModel
        fields = '__all__'
