# -*- coding: utf-8 -*-

__author__ = 'TOANTV'
from rest_framework import serializers
from nodes.models import SboxNodes



########################################################################################################################
#####                                            HOST SERVICES                                                     #####
########################################################################################################################
class SboxNodesSerializer(serializers.ModelSerializer):
    class Meta:
        model = SboxNodes
        fields = '__all__'
