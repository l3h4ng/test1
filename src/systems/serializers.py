from agents.monitor.models import WebsiteMonitorStatusModel, WebsiteBlacklistCheckingModel
from agents.monitor.serializers import WebsiteSecurityAlertDetailsSerializer
from rest_framework import serializers

from agents.hosts.models import HostsModel
from agents.hosts.serializers import HostStatisticSerializer, InfoSerializer, StatisticSerializer
from agents.vulns.models import VulnerabilityModel
from agents.vulns.serializers import HostVulneratbilitySerializer
from systems.models import SystemsNetworkConfig, SystemsEmailNotify, SystemsProxy, SystemStatistics, SystemsLicense, \
    SystemsAlert, SystemLog, SystemVPNModel
from targets.models import TargetsModel, TasksModel


class NetworkConfigSerializer(serializers.ModelSerializer):
    # ip_addr = serializers.IPAddressField()
    # netmask = serializers.IPAddressField()
    # gateway = serializers.IPAddressField()

    class Meta:
        model = SystemsNetworkConfig
        fields = '__all__'


class SystemsEmailSerializers(serializers.ModelSerializer):
    port = serializers.IntegerField(min_value=1, max_value=65535)
    security = serializers.ChoiceField(choices=("TLS", "SSL", "Auto"))
    username = serializers.EmailField()

    class Meta:
        model = SystemsEmailNotify
        read_only_fields = ('test_connection',)
        fields = '__all__'


class SystemsProxySerializers(serializers.ModelSerializer):
    port = serializers.IntegerField(min_value=1, max_value=65535)
    address = serializers.IPAddressField()
    protocol = serializers.ChoiceField(choices=("http", "https"))

    class Meta:
        model = SystemsProxy
        read_only_fields = ('test_connection',)
        fields = '__all__'


class SystemsLicenseSerializers(serializers.ModelSerializer):
    class Meta:
        model = SystemsLicense
        fields = '__all__'


class LoggingAlertSerializers(serializers.ModelSerializer):
    class Meta:
        model = SystemsAlert
        fields = '__all__'

class LoggingAlertDetailsSerializers(serializers.ModelSerializer):
    contents = WebsiteSecurityAlertDetailsSerializer()

    class Meta:
        model = SystemsAlert
        fields = '__all__'


class TaskShortSerializer(serializers.ModelSerializer):
    class Meta:
        model = TasksModel
        fields = ('id', 'target_addr',)


class TargetShortSerializer(serializers.ModelSerializer):
    class Meta:
        model = TargetsModel
        fields = ('id', 'name', 'address',)


# class LoggingAlertDetailsSerializers(serializers.ModelSerializer):
#     unit = serializers.SerializerMethodField(source='unit', read_only=True)
#     office = serializers.SerializerMethodField(source='office', read_only=True)
#     # task = TaskShortSerializer()
#     # target = TargetShortSerializer()
#     task = serializers.SerializerMethodField(source='task', read_only=True)
#     target = serializers.SerializerMethodField(source='target', read_only=True)
#
#     class Meta:
#         model = SystemsAlert
#         fields = '__all__'
#
#     def get_task(self, obj):
#         return {"id": obj.task.id, "name": obj.task.name}
#
#     def get_target(self, obj):
#         return {"id": obj.target.id, "name": obj.target.name, "address": obj.target.address}
#
#     def get_office(self, obj):
#         office = obj.target.office
#         return {"id": office.id, "name": office.name}
#
#     def get_unit(self, obj):
#         unit = obj.target.office.unit
#         return {"id": unit.id, "name": unit.name}


class LoggingSystemSerializers(serializers.ModelSerializer):
    class Meta:
        model = SystemLog
        fields = '__all__'


class LoggingSystemDetailsSerializers(serializers.ModelSerializer):
    unit = serializers.SerializerMethodField(source='unit', read_only=True)
    office = serializers.SerializerMethodField(source='office', read_only=True)
    # task = TaskShortSerializer()
    # target = TargetShortSerializer()
    task = serializers.SerializerMethodField(source='task', read_only=True)
    target = serializers.SerializerMethodField(source='target', read_only=True)

    class Meta:
        model = SystemLog
        fields = '__all__'

    def get_task(self, obj):
        return {"id": obj.task.id, "name": obj.task.name}

    def get_target(self, obj):
        return {"id": obj.target.id, "name": obj.target.name, "address": obj.target.address}

    def get_office(self, obj):
        office = obj.target.office
        return {"id": office.id, "name": office.name}

    def get_unit(self, obj):
        unit = obj.target.office.unit
        return {"id": unit.id, "name": unit.name}


### Statistic API
class SystemStatisticsSerializers(serializers.ModelSerializer):
    # status = serializers.SerializerMethodField(source='get_status', read_only=True)
    # blacklist_detect = serializers.SerializerMethodField(source='get_blacklist_detect', read_only=True)

    class Meta:
        model = SystemStatistics
        fields = '__all__'

    # def get_status(self, obj):
    #     list_status = []
    #     list_task = TargetsModel.objects.values_list('last_task_id', flat=True)
    #     list_last_hosts = HostsModel.objects.prefetch_related('task').filter(task_id__in=list(list_task))
    #     for host in list_last_hosts:
    #         try:
    #             mstatus = WebsiteMonitorStatusModel.objects.filter(website=host).latest('id')
    #             list_status.append({
    #                 "url": mstatus.website.ip_addr,
    #                 "monitor_time": mstatus.monitor_time,
    #                 "ping_status": mstatus.ping_status,
    #                 "ping_response": mstatus.ping_response,
    #                 "web_status": mstatus.web_status,
    #                 "web_load_response": mstatus.web_load_response,
    #             })
    #         except WebsiteMonitorStatusModel.DoesNotExist:
    #             pass
    #     return list_status
    #
    # def get_blacklist_detect(self, obj):
    #     list_status = []
    #     list_task = TargetsModel.objects.values_list('last_task_id', flat=True)
    #     list_last_hosts = HostsModel.objects.prefetch_related('task').filter(task_id__in=list(list_task))
    #     for host in list_last_hosts:
    #         checking = WebsiteBlacklistCheckingModel.objects.filter(website=host, result=1).count()
    #         if checking > 0:
    #             list_status.append({
    #                 "website": host.id,
    #                 "url": host.ip_addr
    #             })
    #     return list_status


class SystemStatisticTopVulnSerializers(serializers.ModelSerializer):
    # hosts = serializers.PrimaryKeyRelatedField(many=True, read_only=True)
    list_hosts = serializers.SerializerMethodField(source='list_hosts', read_only=True)
    hosts_count = serializers.SerializerMethodField()

    class Meta:
        model = VulnerabilityModel
        fields = '__all__'

    def get_hosts_count(self, obj):
        return obj.hosts.count()

    def get_list_hosts(self, obj):
        list_host_vulns = obj.hosts.all()
        data = []
        list_host = []
        for host_vuln in list_host_vulns:
            host = host_vuln.host
            if host not in list_host:
                list_host.append(host)
                data.append({"id": host.id, "ip_addr": host.ip_addr, "count": 1})
            else:
                index = list_host.index(host)
                data[index]["count"] += 1
        return data


class SystemStatisticTopHostsDangerousSerializers(serializers.ModelSerializer):
    statistics = StatisticSerializer(read_only=True)
    # details = InfoSerializer(read_only=True)
    # vulns = HostVulneratbilitySerializer(many=True)
    task = serializers.SerializerMethodField(source='task', read_only=True)
    target = serializers.SerializerMethodField(source='target', read_only=True)
    unit = serializers.SerializerMethodField(source='unit', read_only=True)
    office = serializers.SerializerMethodField(source='office', read_only=True)

    class Meta:
        model = HostsModel
        fields = '__all__'

    def get_task(self, obj):
        return {"id": obj.task.id, "name": obj.task.name}

    def get_target(self, obj):
        return {"id": obj.task.target.id, "name": obj.task.target.name, "address": obj.task.target.address}

    def get_office(self, obj):
        office = obj.task.target.office
        return {"id": office.id, "name": office.name}

    def get_unit(self, obj):
        unit = obj.task.target.office.unit
        return {"id": unit.id, "name": unit.name}


class SystemVPNSerializers(serializers.ModelSerializer):
    class Meta:
        model = SystemVPNModel
        fields = '__all__'
