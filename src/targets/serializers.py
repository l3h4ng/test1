# -*- coding: utf-8 -*-
# -*- coding: utf-8 -*-
import time
import datetime

from agents.hosts.models import HostsModel
from agents.hosts.serializers import StatisticSerializer
from agents.monitor.models import WebsiteMonitorStatusModel, WebsiteBlacklistCheckingModel
from agents.scans.models import ScansModel
from agents.scans.serializers import ScansSerializer
from agents.services.models import HostServicesModel
from agents.services.serializers import ServiceSerializer
from agents.vulns.models import HostVulnerabilityModel
from agents.vulns.serializers import HostVulneratbilitySerializer
from one_users.models import OneUsers
from rest_framework import serializers
from rest_framework.relations import PrimaryKeyRelatedField
from django.conf import settings
from one_users.serializers import OneUserSerializerEmail
from rest_framework.utils import json
from sadmin.plugins.models import PluginsModel
from sbox4web.libs import get_last_task_finish
from sbox4web.rabbitmq import Rabbitmq
import six
from targets.models import SchedulerModel, TargetConfigurationsModel, TargetsModel, TasksModel, \
    TaskStatisticsModel, TargetStatisticsModel
from django.utils.translation import ugettext_lazy as _

# import validators

class StatisticsSerializers(serializers.ModelSerializer):
    # status = serializers.SerializerMethodField(source='get_status', read_only=True)
    # blacklist_detect = serializers.SerializerMethodField(source='get_blacklist_detect', read_only=True)

    class Meta:
        model = TaskStatisticsModel
        fields = '__all__'

    # def get_status(self, obj):
    #     list_status = []
    #     list_hosts_of_task = obj.task.hosts.all()
    #     for host in list_hosts_of_task:
    #         if WebsiteMonitorStatusModel.objects.filter(website=host).count() > 0:
    #             mstatus = WebsiteMonitorStatusModel.objects.filter(website=host).latest('id')
    #             list_status.append({
    #                 "url": mstatus.website.ip_addr,
    #                 "monitor_time": mstatus.monitor_time,
    #                 "ping_status": mstatus.ping_status,
    #                 "ping_response": mstatus.ping_response,
    #                 "web_status": mstatus.web_status,
    #                 "web_load_response": mstatus.web_load_response,
    #             })
    #     return list_status
    #
    # def get_blacklist_detect(self, obj):
    #     list_status = []
    #     list_hosts_of_task = obj.task.hosts.all()
    #     for host in list_hosts_of_task:
    #         checking = WebsiteBlacklistCheckingModel.objects.filter(website=host, result=1).count()
    #         if checking > 0:
    #             list_status.append({
    #                 "website": host.id,
    #                 "url": host.ip_addr
    #             })
    #     return list_status


class SchedulerSerializers(serializers.ModelSerializer):
    class Meta:
        model = SchedulerModel
        read_only_fields = ('last_time', 'configurations',)
        fields = '__all__'

    def create(self, validated_data):
        scheduler = SchedulerModel.objects.create(**validated_data)
        if scheduler.status:
            self.caculator_next_time(scheduler)
        scheduler.save()
        return scheduler

    def update(self, instance, validated_data):
        instance.status = validated_data.get('status', instance.status)
        instance.time_interval = validated_data.get('time_interval', instance.time_interval)
        instance.last_time = validated_data.get('last_time', instance.last_time)

        started_at = instance.started_at
        next_time = instance.next_time
        instance.started_at = validated_data.get('started_at', instance.started_at)
        instance.next_time = validated_data.get('next_time', instance.next_time)

        if instance.status and instance.next_time == next_time and instance.started_at != started_at:
            self.caculator_next_time(instance)

        instance.save()
        return instance

    def caculator_next_time(self, instance):
        today_date = datetime.datetime.now().date()
        time_today = datetime.datetime.combine(today_date,
                                               datetime.datetime.strptime(instance.started_at, "%H:%M").time())
        time_current = int(time.time())
        next_time = int(time.mktime(time_today.timetuple()))
        if next_time > time_current:
            instance.next_time = next_time
        else:
            next_date = today_date + datetime.timedelta(days=instance.time_interval)
            next_time = datetime.datetime.combine(next_date,
                                                  datetime.datetime.strptime(instance.started_at, "%H:%M").time())
            instance.next_time = int(time.mktime(next_time.timetuple()))


class SchedulerSerializerInfo(serializers.ModelSerializer):
    class Meta:
        model = SchedulerModel
        # fields = ('id', 'status', 'time_interval', 'next_time', 'last_time', 'configurations', 'started_at')
        fields = '__all__'


class TargetShortSerializer(serializers.ModelSerializer):
    class Meta:
        model = TargetsModel
        fields = ('id', 'name', 'severity')


class TaskShortSerializers(serializers.ModelSerializer):
    statistics = StatisticsSerializers(read_only=True)

    class Meta:
        model = TasksModel
        # fields = ('id', 'name', 'statistics', 'status', 'start_time', 'finish_time', 'is_lasted')
        fields = '__all__'


class CheckCookie(serializers.JSONField):
    default_error_messages = {
        'invalid': 'Value must be valid JSON.',
        'invalid1': 'Url or value not in cookie.',
        'invalid2': 'Enter a valid URL.'
    }

    def to_internal_value(self, data):
        try:
            if self.binary:
                if isinstance(data, six.binary_type):
                    data = data.decode('utf-8')
                return json.loads(data)
            else:
                json.dumps(data)
            if type(data) == type([]) and data is not None:
                for cookie in data:
                    if "url" not in cookie or "value" not in cookie:
                        self.fail('invalid1')
                        # elif not validators.url(str(cookie["url"])):
                        #     self.fail('invalid2')

        except (TypeError, ValueError):
            self.fail('invalid')
        return data

    def to_representation(self, value):
        list_cookies = []
        if isinstance(value, list):
            if len(value) > 0:
                for cookie in value:
                    if isinstance(cookie, str) or isinstance(cookie, unicode):
                        list_cookies.append(json.loads(cookie))
                    else:
                        list_cookies.append(cookie)
                return list_cookies
            else:
                return []


class ArrayOfJsonFieldSerializerField(serializers.Field):
    """ Serializer for JSONField -- required to make field writable"""

    def to_representation(self, value):
        # print type(value)
        list_hosts = []
        if isinstance(value, list):
            if len(value) > 0:
                for host in value:
                    if isinstance(host, str) or isinstance(host, unicode):
                        list_hosts.append(json.loads(host))
                    else:
                        list_hosts.append(host)
                return list_hosts
            else:
                return []


class CheckHeader(serializers.JSONField):
    default_error_messages = {
        'invalid': 'Value must be valid JSON.',
        'invalid1': 'Url or value not in cookie.',
        'invalid2': 'Enter a valid URL.'
    }

    def to_internal_value(self, data):
        try:
            if self.binary:
                if isinstance(data, six.binary_type):
                    data = data.decode('utf-8')
                return json.loads(data)
            else:
                json.dumps(data)
            if type(data) == type([]) and data is not None:
                for cookie in data:
                    if "url" not in cookie or "e" not in cookie:
                        self.fail('invalid1')
                        # elif not validators.url(str(cookie["url"])):
                        #     self.fail('invalid2')

        except (TypeError, ValueError):
            self.fail('invalid')
        return data


class TargetConfigurationsSerializers(serializers.ModelSerializer):
    scheduler = SchedulerSerializers()
    # custom_cookies = CheckCookie(default=None)

    class Meta:
        model = TargetConfigurationsModel
        # fields = ('scheduler', 'email_notify', 'speed')
        read_only_fields = ('target',)
        fields = '__all__'

    def create(self, validated_data):
        # Valid configuration
        scheduler_data = validated_data.pop("scheduler")
        scheduler_serializer = SchedulerSerializers(data=scheduler_data)
        scheduler_serializer.is_valid(raise_exception=True)

        # save target
        configuration = TargetConfigurationsModel.objects.create(**validated_data)
        scheduler_serializer.save(configurations=configuration)

        # # create time scheduler
        # current_date = datetime.datetime.now().date()
        # next_date = current_date + datetime.timedelta(days=scheduler.time_interval)
        # next_datetime = datetime.datetime.combine(next_date,
        #                                           datetime.datetime.strptime(scheduler.started_at, "%H:%M").time())
        # next_time = int(time.mktime(next_datetime.timetuple()))
        # scheduler.next_time = next_time
        # scheduler.save()
        return configuration

    def update(self, instance, validated_data):
        scheduler_data = validated_data.pop("scheduler")
        scheduler = instance.scheduler
        scheduler_serializer = SchedulerSerializers(scheduler, data=scheduler_data, partial=True)
        scheduler_serializer.is_valid(raise_exception=True)
        scheduler_serializer.save()

        instance.speed = validated_data.get('speed', instance.speed)
        instance.email_notify = validated_data.get('email_notify', instance.email_notify)
        instance.custom_cookies = validated_data.get('custom_cookies', instance.custom_cookies)
        instance.custom_headers = validated_data.get('custom_headers', instance.custom_headers)
        instance.save()
        return instance


class TargetConfigurationsDetailsSerializers(serializers.ModelSerializer):
    scheduler = SchedulerSerializers()
    email_notify = serializers.SerializerMethodField(source='email_notify')
    custom_cookies = serializers.SerializerMethodField(source='custom_cookies')
    # custom_cookies = CheckCookie(read_only=True)

    class Meta:
        model = TargetConfigurationsModel
        # fields = ('scheduler', 'email_notify', 'speed')
        read_only_fields = ('target',)
        fields = '__all__'

    def get_email_notify(self, obj):
        list_email = obj.email_notify
        email_notify = []
        for email in list_email:
            email_info = OneUserSerializerEmail(OneUsers.objects.get(email=email)).data
            email_notify.append(email_info)
        return email_notify

    def get_custom_cookies(self, obj):
        custom_cookies = obj.custom_cookies
        return custom_cookies


class TargetConfigurationsSerializerInfo(serializers.ModelSerializer):
    scheduler = SchedulerSerializers(read_only=True)
    targets = PrimaryKeyRelatedField(read_only=True, many=True)

    class Meta:
        model = TargetConfigurationsModel
        fields = ('scheduler', 'email_notify', 'targets')


#######################  TARGETS  ####################################
# Target Serializer
class TargetSerializer(serializers.ModelSerializer):
    class Meta:
        model = TargetsModel
        read_only_fields = (
            'owner', 'created_at', 'tasks_count', 'report_file', 'last_task_id', 'severity')
        fields = '__all__'


# # /units/uid/offices/oid/targets
# # /targets
# class TargetDetailsInfoSerializer(serializers.ModelSerializer):
#     owner = OneUserSerializerEmail(read_only=True)
#     configuration = TargetConfigurationsDetailsSerializers(read_only=True)
#     office = OfficesShortInfoSerializer(read_only=True)
#     unit = serializers.SerializerMethodField(source='unit')
#     statictis = serializers.SerializerMethodField(source='statictis')
#
#     # tasks = PrimaryKeyRelatedField(read_only=True, many=True)
#
#     class Meta:
#         model = TargetsModel
#         read_only_fields = (
#             'owner', 'created_at', 'tasks_count', 'report_file', 'last_task_id', 'severity')
#         fields = '__all__'
#
#     def get_unit(self, obj):
#         unit = obj.office.unit
#         return UnitsShortInfoSerializer(unit).data
#
#     def get_statictis(self, obj):
#         try:
#             task_statictis = obj.statictis.task.statistics
#             return StatisticsSerializers(task_statictis).data
#         except Exception, ex:
#             return {
#                 "task": 0,
#                 "time_scan": 0,
#                 "hosts_count": 0,
#                 "services_count": 0,
#                 "vulns_count": 0,
#                 "high_count": 0,
#                 "critical_count": 0,
#                 "medium_count": 0,
#                 "low_count": 0,
#                 "info_count": 0,
#                 "severity": 0}


# /units/uid/offices/oid/targets
class TargetCreateSerializer(serializers.ModelSerializer):
    owner = OneUserSerializerEmail(read_only=True)
    configuration = TargetConfigurationsSerializers()

    class Meta:
        model = TargetsModel
        read_only_fields = (
            'owner', 'created_at', 'tasks_count', 'report_file', 'last_task_id', 'severity')
        fields = '__all__'

    def create(self, validated_data):
        # Valid configuration
        configuration_data = validated_data.pop("configuration")
        configuration_serializer = TargetConfigurationsSerializers(data=configuration_data)
        configuration_serializer.is_valid(raise_exception=True)

        # save target
        target = TargetsModel.objects.create(**validated_data)
        configuration_serializer.save(target=target)

        # create task
        if not target.configuration.scheduler.status:
            task_data = {"name": "%s_%s" % (target.name, str(int(time.time()))),
                         "target": target.id,
                         "target_addr": target.address}
            task_serializer = TasksCreateSerializer(data=task_data)
            task_serializer.is_valid(raise_exception=True)
            task = task_serializer.save()

            # Update target
            target.status = 0
            target.tasks_count = 1
            target.last_task_id = task.id

            # create target statistics
            target_statistics = TargetStatisticsModel(target=target, task=task)
            target_statistics.save()
        else:
            target.status = -1
            target.tasks_count = 0
            target.last_task_id = 0
            # target statistics create when start target

        target.save()

        return target

    def update(self, instance, validated_data):
        configuration_data = validated_data.pop("configuration")
        configuration = instance.configuration
        configuration_serializer = TargetConfigurationsSerializers(configuration, data=configuration_data, partial=True)
        configuration_serializer.is_valid(raise_exception=True)
        configuration_serializer.save()

        instance.name = validated_data.get('name', instance.name)
        old_address = instance.address
        instance.address = validated_data.get('address', old_address)
        instance.description = validated_data.get('description', instance.description)
        status = validated_data.get('status', instance.status)
        if instance.status != status:
            if status == 0:
                if instance.status >= 0 and instance.status <= 2:
                    raise ValueError(_("Stop job first."))
                else:
                    # create task
                    task_data = {"name": "%s_%s" % (instance.name, str(int(time.time()))),
                                 "target": instance.id,
                                 "target_addr": instance.address}
                    task_serializer = TasksCreateSerializer(data=task_data)
                    task_serializer.is_valid(raise_exception=True)
                    task = task_serializer.save()

                    # Update target
                    instance.tasks_count += 1
                    # instance.address = old_address

                    if not TargetStatisticsModel.objects.filter(target=instance, task=task).exists():
                        target_statistic = TargetStatisticsModel(target=instance, task=task)
                        target_statistic.save()

                    # else:
                    #     if instance.last_task_id > 0:
                    #         # Update last task
                    #         last_task = TasksModel.objects.get(pk=instance.last_task_id)
                    #         last_task.is_lasted = False
                    #         last_task.save()

                    instance.last_task_id = task.id
                    instance.status = 0
                    instance.save()
            elif status == 1:
                if instance.status != 0:
                    raise ValueError(_("Cannot change target status from {0} to 1".format(str(instance.id))))

                # Update task
                task = TasksModel.objects.get(pk=instance.last_task_id)
                task_serializer = TasksCreateSerializer(task, {"status": 1}, partial=True)
                task_serializer.is_valid(raise_exception=True)
                task_serializer.save()

                # Update target
                instance.address = old_address
                instance.status = 1
            elif status == 3:
                if instance.status > 3:
                    # raise ValueError(_("Job is finished, you can't stop it."))
                    print "Target {} is finished, you can't stop it.".format(str(instance.id))
                elif instance.status == -1:
                    instance.address = old_address
                    instance.status = 3
                else:  # Stop job
                    task = TasksModel.objects.get(pk=instance.last_task_id)
                    # Update task
                    task = TasksModel.objects.get(pk=instance.last_task_id)
                    task_serializer = TasksCreateSerializer(task, {"status": 3}, partial=True)
                    task_serializer.is_valid(raise_exception=True)
                    task_serializer.save()

                    instance.statistics.task = task
                    instance.statistics.save()
                    instance.address = old_address
                    instance.status = 3
        instance.save()
        return instance


# /units/uid/offices/oid/targets/tid
class TargetDetailsInfoSerializer(serializers.ModelSerializer):
    owner = serializers.SerializerMethodField(source='owner', read_only=True)
    configuration = TargetConfigurationsDetailsSerializers(read_only=True)
    office = serializers.SerializerMethodField(source='office', read_only=True)
    unit = serializers.SerializerMethodField(source='unit', read_only=True)
    # tasks = TaskShortSerializers(read_only=True, many=True)
    statistic = serializers.SerializerMethodField(source='statictis')

    class Meta:
        model = TargetsModel
        read_only_fields = (
            'owner', 'created_at', 'tasks_count', 'report_file', 'last_task_id', 'severity')
        fields = '__all__'

    def get_owner(self, obj):
        return {"id": obj.owner.id, "email": obj.owner.email, "fullname": obj.owner.fullname}

    def get_office(self, obj):
        return {"id": obj.office.id, "name": obj.office.name}

    def get_unit(self, obj):
        unit = obj.office.unit
        return {"id": unit.id, "name": unit.name}

    def get_statistic(self, obj):
        try:
            last_task_finish = get_last_task_finish(obj)
            return StatisticsSerializers(last_task_finish.statistics).data
        except Exception, ex:
            return {
                "hosts_count": 0,
                "db_attack_count": 0,
                "medium_count": 0,
                "services_count": 0,
                "info_count": 0,
                "security_alert_count": 0,
                "low_count": 0,
                "severity": 0,
                "domain_blacklist_alert_count": 0,
                "website_content_alert_count": 0,
                "status": [],
                "vulns_count": 0,
                "server_configs_count": 0,
                "paths_count": 0,
                "critical_count": 0,
                "blacklist_detect": [],
                "task": 0,
                "subdomains_count": 0,
                "high_count": 0,
                "phishing_domain_count": 0,
                "malware_path_count": 0
            }


# /units/uid/offices/oid/targets/tid
class TargetDetailsSerializer(serializers.ModelSerializer):
    owner = serializers.SerializerMethodField(source='owner', read_only=True)
    office = serializers.SerializerMethodField(source='office', read_only=True)
    unit = serializers.SerializerMethodField(source='unit', read_only=True)
    statistic = serializers.SerializerMethodField(source='statictis')

    class Meta:
        model = TargetsModel
        read_only_fields = (
            'owner', 'created_at', 'tasks_count', 'report_file', 'last_task_id', 'severity')
        fields = '__all__'

    def get_owner(self, obj):
        return {"id": obj.owner.id, "email": obj.owner.email, "fullname": obj.owner.fullname}

    def get_office(self, obj):
        return {"id": obj.office.id, "name": obj.office.name}

    def get_unit(self, obj):
        unit = obj.office.unit
        return {"id": unit.id, "name": unit.name}

    def get_statistic(self, obj):
        try:
            last_task_finish = get_last_task_finish(obj)
            return StatisticsSerializers(last_task_finish.statistics).data
        except Exception, ex:
            return {
                "hosts_count": 0,
                "db_attack_count": 0,
                "medium_count": 0,
                "services_count": 0,
                "info_count": 0,
                "security_alert_count": 0,
                "low_count": 0,
                "severity": 0,
                "domain_blacklist_alert_count": 0,
                "website_content_alert_count": 0,
                "status": [],
                "vulns_count": 0,
                "server_configs_count": 0,
                "paths_count": 0,
                "critical_count": 0,
                "blacklist_detect": [],
                "task": 0,
                "subdomains_count": 0,
                "high_count": 0,
                "phishing_domain_count": 0,
                "malware_path_count": 0
            }


#######################  TASKS  ####################################
# /units/uid/offices/oid/targets/tid/tasks
class TargetSerializerinfo(serializers.ModelSerializer):
    class Meta:
        model = TargetsModel
        fields = ('id', 'name', 'address', 'description', 'status')


class TasksSerializerCreate(serializers.ModelSerializer):
    target = TargetSerializerinfo()
    name = serializers.CharField(read_only=True)

    class Meta:
        model = TasksModel
        fields = '__all__'


class TasksSerializer(serializers.ModelSerializer):
    # scans = ScansSerializer(many=True, read_only=True)
    # target = TargetSerializerinfo(read_only=True)
    # statistics = StatisticsSerializers(read_only=True)

    class Meta:
        model = TasksModel
        fields = '__all__'


class TasksCreateSerializer(serializers.ModelSerializer):
    # scans = ScansSerializer(many=True, read_only=True)
    # target = TargetSerializerinfo(read_only=True)
    # statistics = StatisticsSerializers(read_only=True)

    class Meta:
        model = TasksModel
        # fields = ('id', 'name', 'target')
        read_only_fields = ('is_lasted',)
        fields = '__all__'

    def create(self, validated_data):
        task = TasksModel.objects.create(**validated_data)
        task.save()
        # Create Task statistics
        statistics = TaskStatisticsModel(task=task, time_scan=int(time.time()))
        statistics.save()

        # create scans
        plugin_models = PluginsModel.objects.all().order_by('id')
        for plugin in plugin_models:
            if plugin.enabled:
                new_scan = ScansModel.objects.create(plugin=plugin, task=task)
                new_scan.save()
        return task

    def update(self, instance, validated_data):
        print "Update task {}".format(str(instance.id))
        instance.name = validated_data.get('name', instance.name)
        instance.target_addr = validated_data.get('target_addr', instance.target_addr)
        instance.severity = validated_data.get('severity', instance.severity)
        instance.report_file = validated_data.get('report_file', instance.report_file)
        status = validated_data.get('status', instance.status)
        print "Update task {} status {}".format(str(instance.id), str(status))
        if status != instance.status:
            if status == 1:
                if instance.status == 0:
                    scans = ScansModel.objects.filter(task=instance).order_by('id')
                    print "Task {}, total {}".format(str(instance.id), str(len(scans)))
                    server_node_name = instance.target.server_node.name
                    if settings.IS_PARALLEL_MODE:
                        for scan in scans:
                            if scan.status < 1:
                                scan.status = 1
                                scan.save()

                                print "Send scan id {} to queue.".format(str(scan.id))
                                plugin_name = scan.plugin.name
                                queue_name = "{}_{}".format(server_node_name, plugin_name)
                                rabbitmq = Rabbitmq(queue_name)
                                rabbitmq.add(str(scan.id))
                                print "Finish send scan id {} to queue {}".format(str(scan.id), str(queue_name))
                    else:
                        for scan in scans:
                            scan.status = 1
                            scan.save()

                            print "Send scan id {} to queue.".format(str(scan.id))
                            plugin_name = scan.plugin.name
                            queue_name = "{}_{}".format(server_node_name, plugin_name)
                            rabbitmq = Rabbitmq(queue_name)
                            rabbitmq.add(str(scan.id))
                            print "Finish send scan id {} to queue {}".format(str(scan.id), str(queue_name))
                            break
                    instance.status = 1
                else:
                    raise ValueError(_("Cannot change task status from {0} to 1".format(str(instance.id))))
            elif status == 3:
                if instance.status < 3:
                    # Update Scan
                    scans = ScansModel.objects.filter(task=instance)
                    for scan in scans:
                        if scan.status < 3:
                            scan.status = 3
                            scan.save()
                    instance.status = 3
        instance.finish_time = int(time.time())
        instance.save()
        return instance


class TasksSerializerLastScan(serializers.ModelSerializer):
    class Meta:
        model = TasksModel
        fields = ('id', 'finish_time', 'status')


class TasksSerializerInfoScans(serializers.ModelSerializer):
    # scans = ScansSerializer(many=True, read_only=True)
    statistics = StatisticsSerializers(read_only=True)
    target = TargetShortSerializer(read_only=True)

    class Meta:
        model = TasksModel
        fields = '__all__'


class ServiceInfoSerializer(serializers.ModelSerializer):
    class Meta:
        model = HostServicesModel
        fields = ('port', 'name',)


class HostVulneratbilityInfoSerializer(serializers.ModelSerializer):
    severity = serializers.SerializerMethodField(source='severity', read_only=True)

    class Meta:
        model = HostVulnerabilityModel
        fields = ('name', 'severity',)

    def get_severity(self, obj):
        severity = obj.vulnerability.severity
        return severity


class HostShortInfoSerializer(serializers.ModelSerializer):
    statistics = StatisticSerializer(read_only=True)
    services = ServiceInfoSerializer(read_only=True, many=True)
    vulns = HostVulneratbilityInfoSerializer(read_only=True, many=True)
    paths = serializers.SerializerMethodField(source='paths', read_only=True)
    subdomains = serializers.SerializerMethodField(source='subdomains', read_only=True)
    config_vulns = serializers.SerializerMethodField(source='config_vulns', read_only=True)
    # services = serializers.SlugRelatedField(
    #     many=True,
    #     read_only=True,
    #     slug_field='port'
    # )
    # vulns = serializers.SlugRelatedField(
    #     many=True,
    #     read_only=True,
    #     slug_field='name'
    # )
    # sessions = serializers.SlugRelatedField(
    #     many=True,
    #     read_only=True,
    #     slug_field='name'
    # )

    class Meta:
        model = HostsModel
        fields = '__all__'

    def get_paths(self, obj):
        list_url = []
        urls = obj.crawls.all()
        for url in urls:
            list_url.append(url.path)
        return list_url

    def get_subdomains(self, obj):
        subdomains_info = []
        subdomains = obj.subdomains.all()
        for domain in subdomains:
            subdomains_info.append({"ip_addr": domain.ip_addr, "subdomain": domain.subdomain})
        return subdomains_info

    def get_config_vulns(self, obj):
        configs_vulns_info = []
        configs_vulns = obj.config_vulns.all()
        for vuln in configs_vulns:
            configs_vulns_info.append({"url": vuln.url})
        return configs_vulns_info


class TaskCompareSerializer(serializers.ModelSerializer):
    statistics = StatisticsSerializers(read_only=True)
    hosts = HostShortInfoSerializer(read_only=True, many=True)

    class Meta:
        model = TasksModel
        fields = '__all__'


class TaskCompareListHostSerializer(serializers.ModelSerializer):
    statistics = StatisticsSerializers(read_only=True)
    hosts = serializers.SlugRelatedField(
        many=True,
        read_only=True,
        slug_field='ip_addr'
    )

    class Meta:
        model = TasksModel
        fields = '__all__'


# Full information
class HostInformationsSerializer(serializers.ModelSerializer):
    statistics = StatisticSerializer(read_only=True)
    services = ServiceSerializer(read_only=True, many=True)
    vulns = HostVulneratbilitySerializer(read_only=True, many=True)

    class Meta:
        model = HostsModel
        fields = '__all__'


class TaskCompareDetailsSerializer(serializers.ModelSerializer):
    statistics = StatisticsSerializers(read_only=True)
    hosts = HostInformationsSerializer(read_only=True, many=True)

    class Meta:
        model = TasksModel
        fields = '__all__'

# class TaskCompare2Serializer(serializers.ModelSerializer):
#     # host_details = ArrayOfJsonFieldSerializerField(read_only=True)
#
#     class Meta:
#         model = TaskCompareModels
#         fields = '__all__'
#
#     # def get_host_details(self):
#     #     for host_details in compare_results["host_details"]:
#     #         instance.host_details.append(json.dumps(dict(host_details)))
#
#     def create(self, validated_data):
#         task_compare = TaskCompareModels.objects.create(**validated_data)
#
#         # compare data
#         compare_results = self.compare(task_compare.task_one, task_compare.task_two)
#
#         data_alert = {
#             "content": {
#                 "statistics": compare_results["statistics"][task_compare.task_two.id],
#                 "alerts": compare_results["alert"]
#             },
#             "task": task_compare.task_two.id,
#             "target": task_compare.task_two.target.id,
#             "type": compare_results["alert"]["severity"]
#         }
#
#         try:
#             system_alert_serializer = LoggingAlertSerializers(data=data_alert)
#             system_alert_serializer.is_valid(raise_exception=True)
#             system_alert_serializer.save()
#         except Exception, ex:
#             print "Cannot create system alerts"
#
#         # update task compare
#         task_compare.host_details = []
#         for host_details in compare_results["host_details"]:
#             task_compare.host_details.append(dict(host_details))
#
#         task_compare.alert = compare_results["alert"]
#         task_compare.statistics = compare_results["statistics"]
#         task_compare.save()
#         return task_compare
#
#     def update(self, instance, validated_data):
#         compare_results = self.compare(instance.task_one, instance.task_two)
#         instance.host_details = []
#         for host_details in compare_results["host_details"]:
#             instance.host_details.append(dict(host_details))
#         instance.alert = compare_results["alert"]
#         instance.statistics = compare_results["statistics"]
#         instance.save()
#         return instance
#
#     def compare(self, task1, task2):
#         task_one = TaskCompareListHostSerializer(task1).data
#         task_two = TaskCompareListHostSerializer(task2).data
#
#         data_compares = {
#             "statistics": {
#                 task_one["id"]: task_one["statistics"],
#                 task_two["id"]: task_two["statistics"]
#             },
#             "alert": {
#                 "host_new": 0,
#                 "host_delete": 0,
#                 "host_changed": 0,
#                 "services_new": 0,
#                 "services_closed": 0,
#                 "vulns_new": 0,
#                 "vuln_fixed": 0,
#                 "subdomain_new": 0,
#                 "subdomain_deleted": 0,
#                 "path_new": 0,
#                 "path_deleted": 0,
#                 "config_vulns_new": 0,
#                 "config_vulns_fixed": 0,
#                 "severity": 0
#             },
#             "host_details": []
#         }
#
#         # compare list hosts
#         list_host1 = np.array(task_one["hosts"])
#         list_host2 = np.array(task_two["hosts"])
#         hosts_new = np.setdiff1d(list_host2, list_host1)
#         hosts_delete = np.setdiff1d(list_host1, list_host2)
#         total_host = np.append(list_host1, hosts_new)
#
#         total_model = HostsModel.objects.select_related('task', 'statistics').prefetch_related('services', 'vulns',
#                                                                                                'subdomains',
#                                                                                                'config_vulns', 'crawls',
#                                                                                                'vulns__vulnerability').filter(
#             ip_addr__in=total_host, task_id=task_one["id"])
#         total_model_data = HostShortInfoSerializer(total_model, many=True).data
#
#
#         # Update statistic
#         data_compares["alert"]["host_new"] = len(hosts_new)
#         data_compares["alert"]["host_delete"] = len(hosts_delete)
#
#
#         # host new
#         hosts_new_models = HostsModel.objects.select_related('task', 'statistics').prefetch_related('services', 'vulns',
#                                                                                                     'subdomains',
#                                                                                                     'config_vulns',
#                                                                                                     'crawls',
#                                                                                                     'vulns__vulnerability').filter(
#             ip_addr__in=hosts_new, task_id=task_two["id"])
#         hosts_new_data = HostShortInfoSerializer(hosts_new_models, many=True).data
#         for host in hosts_new_data:
#             host["changed"] = "new"
#             data_compares["host_details"].append(host)
#             data_compares["alert"]["services_new"] += host["statistics"]["services_count"]
#             data_compares["alert"]["vulns_new"] += host["statistics"]["vulns_count"]
#             data_compares["alert"]["subdomain_new"] += host["statistics"]["subdomains_count"]
#             data_compares["alert"]["path_new"] += host["statistics"]["paths_count"]
#             data_compares["alert"]["config_vulns_new"] += host["statistics"]["server_configs_count"]
#
#         # host delelte
#         hosts_delete_models = HostsModel.objects.select_related('task', 'statistics').prefetch_related('services',
#                                                                                                        'vulns',
#                                                                                                        'subdomains',
#                                                                                                        'config_vulns',
#                                                                                                        'crawls',
#                                                                                                        'vulns__vulnerability').filter(
#             ip_addr__in=hosts_delete, task_id=task_one["id"])
#         hosts_delete_data = HostShortInfoSerializer(hosts_delete_models, many=True).data
#
#         for host in hosts_delete_data:
#             host["changed"] = "delete"
#             data_compares["host_details"].append(host)
#             data_compares["alert"]["services_closed"] += host["statistics"]["services_count"]
#             data_compares["alert"]["vuln_fixed"] += host["statistics"]["vulns_count"]
#             data_compares["alert"]["subdomain_deleted"] += host["statistics"]["subdomains_count"]
#             data_compares["alert"]["path_deleted"] += host["statistics"]["paths_count"]
#             data_compares["alert"]["config_vulns_fixed"] += host["statistics"]["server_configs_count"]
#
#         # host changed
#         hosts_changed = np.setdiff1d(list_host2, hosts_new)
#         hosts_one_changed_models = HostsModel.objects.select_related('task', 'statistics').prefetch_related('services',
#                                                                                                             'vulns',
#                                                                                                             'subdomains',
#                                                                                                             'config_vulns',
#                                                                                                             'crawls',
#                                                                                                             'vulns__vulnerability').filter(
#             ip_addr__in=hosts_changed, task_id=task_one["id"]).order_by('id')
#         hosts_one_changed_data = HostShortInfoSerializer(hosts_one_changed_models, many=True).data
#         hosts_two_changed_models = HostsModel.objects.select_related('task', 'statistics').prefetch_related('services',
#                                                                                                             'vulns',
#                                                                                                             'subdomains',
#                                                                                                             'config_vulns',
#                                                                                                             'crawls',
#                                                                                                             'vulns__vulnerability').filter(
#             ip_addr__in=hosts_changed, task_id=task_two["id"]).order_by('id')
#         hosts_two_changed_data = HostShortInfoSerializer(hosts_two_changed_models, many=True).data
#
#         for count in range(0, len(hosts_two_changed_data)):
#             host1_data = hosts_one_changed_data[count]
#             print host1_data["ip_addr"]
#             host2_data = hosts_two_changed_data[count]
#             print host2_data["ip_addr"]
#
#             # Compare services
#             host1_services = np.array(host1_data["services"])
#             host2_services = np.array(host2_data["services"])
#             new_services = np.setdiff1d(host2_services, host1_services).tolist()
#             deleted_services = np.setdiff1d(host1_services, host2_services).tolist()
#
#             compare_services = {
#                 "new": [],
#                 "deleted": []
#             }
#             if len(new_services) > 0:
#                 compare_services["new"] = new_services
#                 data_compares["alert"]["services_new"] += len(new_services)
#
#             if len(deleted_services) > 0:
#                 compare_services["deleted"] = deleted_services
#                 data_compares["alert"]["services_closed"] += len(deleted_services)
#
#             host2_data["services"] = compare_services
#             if len(new_services) > 0 or len(deleted_services) > 0:
#                 host2_data["changed"] = "changed"
#
#             # Compare vulns
#             host1_vulns = np.array(host1_data["vulns"])
#             host2_vulns = np.array(host2_data["vulns"])
#             new_vulns = np.setdiff1d(host2_vulns, host1_vulns).tolist()
#             deleted_vulns = np.setdiff1d(host1_vulns, host2_vulns).tolist()
#
#             compare_vulns = {
#                 "new": [],
#                 "deleted": []
#             }
#             if len(new_vulns) > 0:
#                 compare_vulns["new"] = new_vulns
#                 data_compares["alert"]["vulns_new"] += len(new_vulns)
#                 for vuln in new_vulns:
#                     if vuln["severity"] >= 3:
#                         if data_compares["alert"]["severity"] < 2:
#                             data_compares["alert"]["severity"] = 2
#                             break
#                     elif vuln["severity"] == 2:
#                         if data_compares["alert"]["severity"] < 1:
#                             data_compares["alert"]["severity"] = 1
#
#             if len(deleted_vulns) > 0:
#                 compare_vulns["deleted"] = deleted_vulns
#                 data_compares["alert"]["vuln_fixed"] += len(deleted_vulns)
#
#             host2_data["vulns"] = compare_vulns
#             if len(new_vulns) > 0 or len(deleted_vulns) > 0:
#                 host2_data["changed"] = "changed"
#
#             # Compare sudmomains
#             host1_subdomains = np.array(host1_data["subdomains"])
#             host2_subdomains = np.array(host2_data["subdomains"])
#             new_subdomains = np.setdiff1d(host2_subdomains, host1_subdomains).tolist()
#             deleted_subdomains = np.setdiff1d(host1_subdomains, host2_subdomains).tolist()
#
#             compare_subdomains = {
#                 "new": [],
#                 "deleted": []
#             }
#             if len(new_subdomains) > 0:
#                 compare_subdomains["new"] = new_subdomains
#                 data_compares["alert"]["subdomain_new"] += len(new_subdomains)
#
#             if len(deleted_subdomains) > 0:
#                 compare_subdomains["deleted"] = deleted_subdomains
#                 data_compares["alert"]["subdomain_deleted"] += len(deleted_subdomains)
#
#             host2_data["subdomains"] = compare_subdomains
#             if len(new_subdomains) > 0 or len(deleted_subdomains) > 0:
#                 host2_data["changed"] = "changed"
#
#             # Compare path
#             host1_urls = np.array(host1_data["paths"])
#             host2_urls = np.array(host2_data["paths"])
#             new_urls = np.setdiff1d(host2_urls, host1_urls).tolist()
#             deleted_urls = np.setdiff1d(host1_urls, host2_urls).tolist()
#
#             compare_paths = {
#                 "new": [],
#                 "deleted": []
#             }
#             if len(new_urls) > 0:
#                 compare_paths["new"] = new_urls
#                 data_compares["alert"]["path_new"] += len(new_urls)
#
#             if len(deleted_urls) > 0:
#                 compare_paths["deleted"] = deleted_urls
#                 data_compares["alert"]["path_deleted"] += len(deleted_urls)
#
#             host2_data["paths"] = compare_paths
#             if len(new_urls) > 0 or len(deleted_urls) > 0:
#                 host2_data["changed"] = "changed"
#
#             # Compare config vulns
#             host1_config_vulns = np.array(host1_data["config_vulns"])
#             host2_config_vulns = np.array(host2_data["config_vulns"])
#             new_config_vulns = np.setdiff1d(host2_config_vulns, host1_config_vulns).tolist()
#             deleted_config_vulns = np.setdiff1d(host1_config_vulns, host2_config_vulns).tolist()
#
#             compare_config_vulns = {
#                 "new": [],
#                 "deleted": []
#             }
#             if len(new_config_vulns) > 0:
#                 compare_config_vulns["new"] = new_config_vulns
#                 data_compares["alert"]["config_vulns_new"] += len(new_config_vulns)
#
#             if len(deleted_config_vulns) > 0:
#                 compare_config_vulns["deleted"] = deleted_config_vulns
#                 data_compares["alert"]["config_vulns_fixed"] += len(deleted_config_vulns)
#
#             host2_data["config_vulns"] = compare_config_vulns
#             if len(new_config_vulns) > 0 or len(deleted_config_vulns) > 0:
#                 host2_data["changed"] = "changed"
#
#             if "changed" in host2_data and host2_data["changed"] == "changed":
#                 data_compares["host_details"].append(host2_data)
#
#         data_alert = {
#             "content": {
#                 "statistics": task_two["statistics"],
#                 "alerts": data_compares["alert"]
#             },
#             "task": task_two["id"],
#             "target": task_two["target"],
#             "type": data_compares["alert"]["severity"]
#         }
#         try:
#             system_alert_serializer = LoggingAlertSerializers(data=data_alert)
#             system_alert_serializer.is_valid(raise_exception=True)
#             system_alert_serializer.save()
#         except Exception, ex:
#             print "Cannot create system alerts"
#         return data_compares

class TargetStatusSerializer(serializers.ModelSerializer):
    is_scanning = serializers.SerializerMethodField(source='is_scanning')
    office = serializers.SerializerMethodField(source='office', read_only=True)
    unit = serializers.SerializerMethodField(source='unit', read_only=True)

    class Meta:
        model = TargetsModel
        fields = ('id', 'name', 'severity', 'is_scanning', 'office', 'unit')

    def get_is_scanning(self, obj):
        if obj.status == 2:
            return True
        else:
            return False

    def get_office(self, obj):
        return {"id": obj.office.id, "name": obj.office.name}

    def get_unit(self, obj):
        unit = obj.office.unit
        return {"id": unit.id, "name": unit.name}
