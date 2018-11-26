# -*- coding: utf-8 -*-
from rest_framework import serializers

from sadmin.plugins.models import PluginsModel, PluginsLicenseModel


class PluginSerializers(serializers.ModelSerializer):
    class Meta:
        model = PluginsModel
        fields = '__all__'


# class PluginsGroupSerializerInfo(serializers.ModelSerializer):
#     class Meta:
#         model = PluginsGroupModel
#         fields = '__all__'


class PluginsLicenseSerializerInfo(serializers.ModelSerializer):
    class Meta:
        model = PluginsLicenseModel
        fields = '__all__'
