# -*- coding: utf-8 -*-
__author__ = 'TOANTV'

from rest_framework import serializers
from agents.crawldata.models import CrawlDataModel



########################################################################################################################
#####                                            WEBSITE CRAWLDATA                                                 #####
########################################################################################################################
class CrawlDataSerializer(serializers.ModelSerializer):
    # children = serializers.SerializerMethodField(source='children', read_only=True)
    class Meta:
        model = CrawlDataModel
        # read_only_fields = ('website',)
        fields = '__all__'
