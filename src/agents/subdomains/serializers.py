# -*- coding: utf-8 -*-
__author__ = 'TOANTV'

from rest_framework import serializers
from agents.subdomains.models import WebsiteSubdomainsModel
import requests
from urlparse import urlparse

########################################################################################################################
#####                                            WEBSITE SUBDOMAINS                                                #####
########################################################################################################################
class WebsiteSubdomainsSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebsiteSubdomainsModel
        # read_only_fields = ('website',)
        fields = '__all__'

    def create(self, validated_data):
        subdomain = WebsiteSubdomainsModel.objects.create(**validated_data)

        # Update host statistics
        host_statistic = subdomain.website.statistics
        host_statistic.subdomains_count += 1
        host_statistic.save()

        # Update task statistics
        task_statistic = subdomain.website.task.statistics
        task_statistic.subdomains_count += 1
        task_statistic.save()
        return subdomain

    def update(self, instance, validated_data):
        instance.is_monitor = validated_data.get('is_monitor', instance.is_monitor)
        url_subdomain = "http://{}".format(instance.subdomain)
        try:
            r = requests.get(url_subdomain)
            parsed_uri = urlparse(r.url)
            url_subdomain = '{uri.scheme}://{uri.netloc}'.format(uri=parsed_uri)
        except Exception, ex:
            pass

        if instance.is_monitor:
            current_target = instance.website.task.target.address
            list_website = current_target.split(',')
            is_monitored = False
            for website in list_website:
                if url_subdomain in website:
                    is_monitored = True
                    break
            if not is_monitored:
                list_website.append(url_subdomain)
                instance.website.task.target.address = ','.join(list_website)
            instance.website.task.target.save()
        else:
            current_target = instance.website.task.target.address
            list_website = current_target.split(',')
            is_monitored = False
            for website in list_website:
                if url_subdomain in website:
                    is_monitored = True
                    url_subdomain = website
                    break
            if is_monitored:
                list_website.remove(url_subdomain)
                instance.website.task.target.address = ','.join(list_website)
            instance.website.task.target.save()
        instance.save()
        return instance
