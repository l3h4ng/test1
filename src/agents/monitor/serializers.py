# -*- coding: utf-8 -*-
import datetime
from agents.hosts.serializers import HostShortSerializer
from django.utils.translation import ugettext_lazy as _

__author__ = 'TOANTV'
from rest_framework import serializers
from agents.monitor.models import GoogleHackingKeywordModels, WebsiteSecurityAlertModel, WebsiteMonitorStatusModel, \
    WebsiteMonitorUrl, WebsiteMonitorContentStatusModel, WebsiteBlacklistCheckingModel, \
    WebsiteGoogleHackingDetectModel, WebsitePhishingDomainDetectModel, SecurityEventsModels, \
    TargetTechnologyVersionModel, SoftwareLastVersionModel, WebsiteContentModel, WebsiteMonitorContentChangeModel

########################################################################################################################
#####                                            SECURITY EVENT                                                    #####
########################################################################################################################

class SecurityEventsSerializer(serializers.ModelSerializer):
    class Meta:
        model = SecurityEventsModels
        fields = '__all__'


class SecurityEventsDetailsSerializer(serializers.ModelSerializer):
    # severity = serializers.CharField(source='get_severity_display')

    class Meta:
        model = SecurityEventsModels
        fields = '__all__'


########################################################################################################################
#####                                            SECURITY MONITOR ALERT                                            #####
########################################################################################################################
class WebsiteSecurityAlertSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebsiteSecurityAlertModel
        fields = '__all__'


class WebsiteSecurityAlertDetailsSerializer(serializers.ModelSerializer):
    events = SecurityEventsDetailsSerializer()
    unit = serializers.SerializerMethodField(source='unit', read_only=True)
    office = serializers.SerializerMethodField(source='office', read_only=True)
    host = serializers.SerializerMethodField(source='host', read_only=True)
    task = serializers.SerializerMethodField(source='task', read_only=True)
    target = serializers.SerializerMethodField(source='target', read_only=True)
    # description = serializers.SerializerMethodField('get_description_string')
    # solution = serializers.SerializerMethodField('get_solution_string')
    name = serializers.SerializerMethodField()
    solution = serializers.SerializerMethodField()
    description = serializers.SerializerMethodField()

    class Meta:
        model = WebsiteSecurityAlertModel
        fields = '__all__'

    def get_host(self, obj):
        return {"id": obj.host.id, "address": obj.host.ip_addr}

    def get_task(self, obj):
        task = obj.host.task
        return {"id": task.id, "name": task.name}

    def get_target(self, obj):
        target = obj.host.task.target
        return {"id": target.id, "name": target.name, "address": target.address}

    def get_office(self, obj):
        office = obj.host.task.target.office
        return {"id": office.id, "name": office.name}

    def get_unit(self, obj):
        unit = obj.host.task.target.office.unit
        return {"id": unit.id, "name": unit.name}

    def get_name(self, obj):
        secirity_name = obj.events.get_alert_display()
        name = _(secirity_name)
        if obj.events.alert == "NEW_VULNERABILITY" or  obj.events.alert == "VULNERABILITY_IS_NOT_FIX":
            return obj.name
        return name

    # def get_description_string(self, obj):
    #     return _(obj.description)
    #
    # def get_solution_string(self, obj):
    #     return _(obj.solution)

    def get_description(self, obj):
        security_event = obj.description
        secirity_description = obj.get_description_display()
        description = _(secirity_description)
        if security_event == "NEW_DEVICE":
            description += "<ul style='margin-bottom: 0px;'>"
            description += "<li><b>" + unicode(_("IP address")) + "</b>: " + obj.details["ip_addr"] + "</li>"
            description += "</ul>"

        if security_event == "DEVICE_TURN_OFF":
            description += "<ul style='margin-bottom: 0px;'>"
            description += "<li><b>" + unicode(_("IP address")) + "</b> " + obj.details["ip_addr"]
            description += "</ul>"

        if security_event == "DEVICE_CHANGE_IP":
            description += "<ul style='margin-bottom: 0px;'>"
            description += "<li><b>" + unicode(_("Old IP address")) + "</b>: " + obj.details["old"]["ip_addr"] + "</li>"
            description += "<li><b>" + unicode(_("New IP address")) + "</b>: " + obj.details["new"]["ip_addr"] + "</li>"
            description += "</ul>"

        if security_event == "NEW_SERVICE":
            description = "<ul style='margin-bottom: 0px;'>"
            description += "<li><b>" + unicode(_("IP address")) + "</b>: " + obj.host.ip_addr + "</li>"
            description += "<li><b>" + unicode(_("New service port")) + "</b>: " + unicode(
                obj.details["port"]) + "</li>"
            description += "</ul>"

        if security_event == "SERVICE_CHANGED":
            description = "<ul style='margin-bottom: 0px;'>"
            description += "<li><b>" + unicode(_("IP address")) + "</b>: " + obj.host.ip_addr + "</li>"
            description += "<li><b>" + unicode(_("Service is changed")) + "</b>: " + unicode(
                obj.details["new"]["port"]) + "</li>"
            description += "</ul>"

        if security_event == "SERVICE_CLOSED":
            description = "<ul style='margin-bottom: 0px;'>"
            description += "<li><b>" + unicode(_("IP address")) + "</b>: " + obj.host.ip_addr + "</li>"
            description += "<li><b>" + unicode(_("Service is closed")) + "</b>: " + unicode(
                obj.details["port"]) + "</li>"
            description += "</ul>"

        if security_event == "SERVICE_VERSION_TOO_OLD":
            description = "<ul style='margin-bottom: 0px;'>"
            description += "<li><b>" + unicode(_("Website")) + "</b>: " + obj.host.ip_addr + "</li>"
            description += "<li><b>" + unicode(_("Service is detected")) + "</b>: " + unicode(
                obj.details["port"]) + "</li>"
            description += "<li><b>" + unicode(_("Version")) + "</b>: " + unicode(obj.details["port"])
            description += "</ul>"

        if security_event == "NEW_VULNERABILITY":
            description = "<ul style='margin-bottom: 0px;'>"
            description += "<li><b>" + unicode(_("Website")) + "</b>: " + obj.host.ip_addr + "</li>"
            description += "<li><b>" + unicode(_("Vulnerability")) + "</b>: " + obj.details["vulnerability"][
                "name"] + "</li>"
            description += "<li><b>" + unicode(_("Affects")) + "</b>: " + obj.details["affects"] + "</li>"
            description += "</ul>"

        if security_event == "VULNERABILITY_IS_NOT_FIX":
            description = "<ul style='margin-bottom: 0px;'>"
            description += "<li><b>" + unicode(_("Website")) + "</b>: " + obj.host.ip_addr + "</li>"
            description += "<li><b>" + unicode(_("Vulnerability")) + "</b>: " + obj.details["vulnerability"][
                "name"] + "</li>"
            description += "<li><b>" + unicode(_("Affects")) + "</b>: " + obj.details["affects"] + "</li>"
            description += "</ul>"

        if security_event == "BKACLIST_DETECTED":
            description += "<ul style='margin-bottom: 0px;'>"
            description += "<li><b>" + unicode(_("Website")) + "</b>: " + obj.host.ip_addr + "</li>"
            description += "<li><b>" + unicode(_("Blacklist by")) + "</b>: " + unicode(obj.details["vendor"]) + "</li>"
            description += "</ul>"

        if security_event == "MALWARE_DETECTED":
            description += "<ul style='margin-bottom: 0px;'>"
            description += "<li><b>" + unicode(_("Website")) + ": </b>: " + obj.host.ip_addr + "</li>"
            description += "<li><b>" + unicode(_("Malware path")) + ": </b>: " + unicode(obj.details["path"]) + "</li>"
            description += "</ul>"

        if security_event == "WEBSITE_CONTENT_DETECTED":
            description += "<ul style='margin-bottom: 0px;'>"
            description += "<li><b>" + unicode(_("Url")) + "</b>: " + obj.host.ip_addr + "</li>"
            if "pages" in obj.details and len(obj.details["pages"]) > 0:
                description += "<li><b>" + unicode(_("List pages content changed")) + ":</b>"
                for page in obj.details["pages"]:
                    description += "<li>" + unicode(page["url"]) + "</li>"
                description += "</li>"
            description += "<li><b>" + unicode(_("Time detected")) + "</b>: " + datetime.datetime.fromtimestamp(int(obj.details["monitor_time"])).strftime('%Y-%m-%d %H:%M:%S') + "</li>"
            description += "</ul>"

        if security_event == "SERVER_STATUS":
            description += "<ul style='margin-bottom: 0px;'>"
            description += "<li><b>" + unicode(_("Website")) + "</b>: " + obj.host.ip_addr + "</li>"
            description += "<li><b>" + unicode(_("HTTP status code")) + ": </b>: " + unicode(obj.details["web_status"]) + "</li>"
            description += "<li><b>" + unicode(_("Time detected")) + ": </b>: " + datetime.datetime.fromtimestamp(int(obj.details["monitor_time"])).strftime('%Y-%m-%d %H:%M:%S') + "</li>"
            description += "</ul>"

        return description

    def get_solution(self, obj):
        security_event = obj.solution
        secirity_solution = obj.get_solution_display()
        solution = _(secirity_solution)
        if security_event == "NEW_DEVICE":
            pass

        if security_event == "DEVICE_TURN_OFF":
            pass

        if security_event == "DEVICE_CHANGE_IP":
            pass

        if security_event == "NEW_SERVICE":
            pass

        if security_event == "SERVICE_CHANGED":
            pass

        if security_event == "SERVICE_CLOSED":
            pass

        if security_event == "SERVICE_VERSION_TOO_OLD":
            solution += "</br><b>" + unicode(_("Service is detected")) + "</b>: " + unicode(obj.details["port"])
            solution += "</br><b>" + unicode(_("Last Version")) + "</b>: " + unicode(obj.details["port"])

        if security_event == "NEW_VULNERABILITY":
            solution = obj.details["vulnerability"]["solution"]

        if security_event == "VULNERABILITY_IS_NOT_FIX":
            solution = obj.details["vulnerability"]["solution"]

        if security_event == "BKACLIST_DETECTED":
            pass

        if security_event == "MALWARE_DETECTED":
            solution += "</br><b>" + unicode(_("Details")) + "</b>: " + unicode(obj.details["path"])

        if security_event == "WEBSITE_CONTENT_DETECTED":
            pass

        if security_event == "SERVER_STATUS":
            pass
        return solution


class WebsiteSecurityAlertDetailsSerializer2(serializers.ModelSerializer):
    events = SecurityEventsDetailsSerializer()
    unit = serializers.SerializerMethodField(source='unit', read_only=True)
    office = serializers.SerializerMethodField(source='office', read_only=True)
    host = serializers.SerializerMethodField(source='host', read_only=True)
    task = serializers.SerializerMethodField(source='task', read_only=True)
    target = serializers.SerializerMethodField(source='target', read_only=True)
    # description = serializers.SerializerMethodField('get_description_string')
    # solution = serializers.SerializerMethodField('get_solution_string')
    name = serializers.SerializerMethodField()
    solution = serializers.SerializerMethodField()
    description = serializers.SerializerMethodField()

    class Meta:
        model = WebsiteSecurityAlertModel
        fields = '__all__'

    def get_host(self, obj):
        return {"id": obj.host.id, "address": obj.host.ip_addr}

    def get_task(self, obj):
        task = obj.host.task
        return {"id": task.id, "name": task.name}

    def get_target(self, obj):
        target = obj.host.task.target
        return {"id": target.id, "name": target.name, "address": target.address}

    def get_office(self, obj):
        office = obj.host.task.target.office
        return {"id": office.id, "name": office.name}

    def get_unit(self, obj):
        unit = obj.host.task.target.office.unit
        return {"id": unit.id, "name": unit.name}

    def get_name(self, obj):
        secirity_name = obj.events.get_alert_display()
        name = _(secirity_name)
        if obj.events.alert == "NEW_VULNERABILITY" or  obj.events.alert == "VULNERABILITY_IS_NOT_FIX":
            return obj.name
        return name

    # def get_description_string(self, obj):
    #     return _(obj.description)
    #
    # def get_solution_string(self, obj):
    #     return _(obj.solution)

    def get_description(self, obj):
        security_event = obj.description
        secirity_description = obj.get_description_display()
        description = _(secirity_description)
        if security_event == "NEW_DEVICE":
            description += "\n" + unicode(_("IP address")) + "\n" + obj.details["ip_addr"]

        if security_event == "DEVICE_TURN_OFF":
            description += "\n" + unicode(_("IP address")) + "\n" + obj.details["ip_addr"]

        if security_event == "DEVICE_CHANGE_IP":
            description += "\n" + unicode(_("Old IP address")) + "\n" + obj.details["old"]["ip_addr"]
            description += "\n" + unicode(_("New IP address")) + "\n" + obj.details["new"]["ip_addr"]

        if security_event == "NEW_SERVICE":
            description += "\n" + unicode(_("IP address")) + "\n"+ obj.host.ip_addr
            description += "\n" + unicode(_("New service port")) + "\n" + unicode(obj.details["port"])

        if security_event == "SERVICE_CHANGED":
            description += "\n" + unicode(_("IP address")) + "\n" + obj.host.ip_addr
            description += "\n" + unicode(_("Service is changed")) + "\n" + unicode(obj.details["new"]["port"])

        if security_event == "SERVICE_CLOSED":
            description += "\n" + unicode(_("IP address")) + "\n" + obj.host.ip_addr
            description += "\n" + unicode(_("Service is closed")) + "\n" + unicode(obj.details["port"])

        if security_event == "SERVICE_VERSION_TOO_OLD":
            description += "\n" + unicode(_("IP address")) + "\n" + obj.host.ip_addr
            description += "\n" + unicode(_("Service is detected")) + "\n" + unicode(obj.details["port"])
            description += "\n" + unicode(_("Version")) + "\n" + unicode(obj.details["port"])

        if security_event == "NEW_VULNERABILITY":
            description += "\n" + unicode(_("IP address")) + "\n" + obj.host.ip_addr
            description += "\n" + unicode(_("Vulnerability")) + "\n" + obj.details["vulnerability"]["name"]

        if security_event == "VULNERABILITY_IS_NOT_FIX":
            description += "\n" + unicode(_("IP address")) + "\n" + obj.host.ip_addr
            description += "\n" + unicode(_("Vulnerability")) + "\n" + obj.details["vulnerability"]["name"]

        if security_event == "BKACLIST_DETECTED":
            description += "\n" + unicode(_("Website")) + "\n" + obj.host.ip_addr
            description += "\n" + unicode(_("Blacklist by")) + "\n" + unicode(obj.details)

        if security_event == "MALWARE_DETECTED":
            description += "\n" + unicode(_("Url")) + "\n" + obj.host.ip_addr
            description += "\n" + unicode(_("Path")) + "\n" + unicode(obj.details)

        if security_event == "WEBSITE_CONTENT_DETECTED":
            pass

        if security_event == "SERVER_STATUS":
            pass

        return description

    def get_solution(self, obj):
        security_event = obj.solution
        secirity_solution = obj.get_solution_display()
        solution = _(secirity_solution)
        if security_event == "NEW_DEVICE":
            pass

        if security_event == "DEVICE_TURN_OFF":
            pass

        if security_event == "DEVICE_CHANGE_IP":
            pass

        if security_event == "NEW_SERVICE":
            pass

        if security_event == "SERVICE_CHANGED":
            pass

        if security_event == "SERVICE_CLOSED":
            pass

        if security_event == "SERVICE_VERSION_TOO_OLD":
            solution += "</br><b>" + unicode(_("Service is detected")) + "</b>: " + unicode(obj.details["port"])
            solution += "</br><b>" + unicode(_("Last Version")) + "</b>: " + unicode(obj.details["port"])

        if security_event == "NEW_VULNERABILITY":
            solution = obj.details["vulnerability"]["solution"]

        if security_event == "VULNERABILITY_IS_NOT_FIX":
            solution = obj.details["vulnerability"]["solution"]

        if security_event == "BKACLIST_DETECTED":
            pass

        if security_event == "MALWARE_DETECTED":
            solution += "</br><b>" + unicode(_("Details")) + "</b>: " + unicode(obj.details["path"])

        if security_event == "WEBSITE_CONTENT_DETECTED":
            pass

        if security_event == "SERVER_STATUS":
            pass
        return solution


class SecurityAlertInfoSerializer(serializers.ModelSerializer):
    events = SecurityEventsDetailsSerializer()
    solution = serializers.SerializerMethodField()
    description = serializers.SerializerMethodField()

    class Meta:
        model = WebsiteSecurityAlertModel
        fields = '__all__'

    def get_description(self, obj):
        secirity_description = obj.get_description_display()
        description = _(secirity_description)
        return description

    def get_solution(self, obj):
        secirity_solution = obj.get_solution_display()
        solution = _(secirity_solution)
        return solution



########################################################################################################################
#####                                            SOFTWARE LAST VERSION                                             #####
########################################################################################################################
class SoftwareLastVersionSerializer(serializers.ModelSerializer):
    class Meta:
        model = SoftwareLastVersionModel
        fields = '__all__'


########################################################################################################################
#####                                            TARGET SOFTWARE VERSION                                            #####
########################################################################################################################
class TargetTechnologyVersionSerializer(serializers.ModelSerializer):
    class Meta:
        model = TargetTechnologyVersionModel
        fields = '__all__'


class TargetTechnologyVersionDetailsSerializer(serializers.ModelSerializer):
    target = serializers.SerializerMethodField(source='target', read_only=True)
    host = serializers.SerializerMethodField(source='get_host', read_only=True)

    class Meta:
        model = TargetTechnologyVersionModel
        fields = '__all__'

    def get_host(self, obj):
        return {"id": obj.host.id, "address": obj.host.ip_addr}

    def get_target(self, obj):
        target = obj.host.task.target
        return {"id": target.id, "name": target.name, "address": target.address}


########################################################################################################################
#####                                            MONITOR CONTENTS                                                  #####
########################################################################################################################
class WebsiteMonitorUrlSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebsiteMonitorUrl
        # read_only_fields = ('target', 'path',)
        fields = '__all__'


# class WebsiteContentSerializer(serializers.ModelSerializer):
#     class Meta:
#         model = WebsiteContentModel
#         fields = '__all__'


class WebsiteContentSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebsiteContentModel
        fields = '__all__'


class WebsiteMonitorContentSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebsiteMonitorContentStatusModel
        fields = '__all__'


class WebsiteMonitorContentDetailsSerializer(serializers.ModelSerializer):
    # old_content = WebsiteContentSerializer()
    # new_content = WebsiteContentSerializer()
    url_monitor = WebsiteMonitorUrlSerializer()

    class Meta:
        model = WebsiteMonitorContentStatusModel
        fields = '__all__'




class WebsiteMonitorContentChangeSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebsiteMonitorContentChangeModel
        fields = '__all__'


class WebsiteMonitorContentChangeDetailsSerializer(serializers.ModelSerializer):
    url_monitor = WebsiteMonitorUrlSerializer()

    class Meta:
        model = WebsiteMonitorContentChangeModel
        fields = '__all__'



class WebsiteMonitorContentHistorySerializer(serializers.ModelSerializer):
    # url_monitor = WebsiteMonitorUrlSerializer()
    # pages = WebsiteMonitorContentChangeSerializer(many=True, read_only=True)
    # pages = serializers.SerializerMethodField(source='pages', read_only=True)

    class Meta:
        model = WebsiteMonitorContentStatusModel
        fields = '__all__'


class WebsiteMonitorContentHistoryInfoSerializer(serializers.ModelSerializer):
    url_monitor = WebsiteMonitorUrlSerializer()
    # pages = WebsiteMonitorContentChangeSerializer(many=True, read_only=True)
    pages = serializers.SerializerMethodField(source='pages', read_only=True)

    class Meta:
        model = WebsiteMonitorContentStatusModel
        fields = '__all__'

    def get_pages(self, obj):
        pages = []
        list_pages_change = obj.pages.all()
        for page in list_pages_change:
            pages.append({"id": page.id, "url": page.url_monitor.path})
        return pages

class WebsiteMonitorContentHistoryDetailsSerializer(serializers.ModelSerializer):
    url_monitor = WebsiteMonitorUrlSerializer()
    # pages = WebsiteMonitorContentChangeSerializer(many=True, read_only=True)
    pages = serializers.SerializerMethodField(source='pages', read_only=True)

    class Meta:
        model = WebsiteMonitorContentStatusModel
        fields = '__all__'

    def get_pages(self, obj):
        pages = []
        list_pages_change = obj.pages.all()
        for page in list_pages_change:
            pages.append(WebsiteMonitorContentChangeDetailsSerializer(page).data)
            # pages.append({"id": page.id, "url": page.url_monitor.path})
        return pages


# class WebsiteMonitorContentHistoryDetailsSerializer(serializers.ModelSerializer):
#     url_monitor = WebsiteMonitorUrlSerializer()
#     pages = WebsiteMonitorContentChangeSerializer(many=True, read_only=True)
#
#     class Meta:
#         model = WebsiteMonitorContentStatusModel
#         fields = '__all__'


########################################################################################################################
#####                                            MONITOR STATUS                                                    #####
########################################################################################################################

class WebsiteMonitorStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebsiteMonitorStatusModel
        fields = '__all__'


class WebsiteMonitorStatusDetailsSerializer(serializers.ModelSerializer):
    website = HostShortSerializer()

    class Meta:
        model = WebsiteMonitorStatusModel
        fields = '__all__'


########################################################################################################################
#####                                            GOOGLE HACKING DB                                                 #####
########################################################################################################################
class GoogleHackingKeywordSerializer(serializers.ModelSerializer):
    class Meta:
        model = GoogleHackingKeywordModels
        fields = '__all__'


class WebsiteGoogleHackingDetectSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebsiteGoogleHackingDetectModel
        fields = '__all__'


class WebsiteGoogleHackingDetectDetailsSerializer(serializers.ModelSerializer):
    keyword = GoogleHackingKeywordSerializer()

    class Meta:
        model = WebsiteGoogleHackingDetectModel
        fields = '__all__'


class WebsiteGoogleHackingDetectWebsiteDetailsSerializer(serializers.ModelSerializer):
    keyword = GoogleHackingKeywordSerializer()
    website = HostShortSerializer()

    class Meta:
        model = WebsiteGoogleHackingDetectModel
        fields = '__all__'


########################################################################################################################
#####                                            BLACKLIST WARNING                                                 #####
########################################################################################################################
class WebsiteBlacklistCheckingSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebsiteBlacklistCheckingModel
        fields = '__all__'


class WebsiteBlacklistCheckingDetailsSerializer(serializers.ModelSerializer):
    website = HostShortSerializer()

    class Meta:
        model = WebsiteBlacklistCheckingModel
        fields = '__all__'


class WebsiteBlacklistChecking2DetailsSerializer(serializers.ModelSerializer):
    website = HostShortSerializer()
    vendor = serializers.SerializerMethodField(source='get_vendor', read_only=True)

    class Meta:
        model = WebsiteBlacklistCheckingModel
        fields = '__all__'

    def get_vendor(self, obj):
        return obj.get_type_display()


########################################################################################################################
#####                                            PHISHING DOMAIN WARNING                                            #####
########################################################################################################################
class WebsitePhishingDomainDetectSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebsitePhishingDomainDetectModel
        fields = '__all__'


class WebsitePhishingDomainDetectDetailsSerializer(serializers.ModelSerializer):
    website = HostShortSerializer()

    class Meta:
        model = WebsitePhishingDomainDetectModel
        fields = '__all__'
