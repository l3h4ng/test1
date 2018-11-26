# -*- coding: utf-8 -*-
import time
import datetime
from agents.email.email_template import EmailTemplate
from agents.monitor.sbox_monitor import SboxSecurityMonitor
from django.conf import settings
from rest_framework import serializers
from agents.scans.models import ScansModel
from sadmin.plugins.models import PluginsModel
from sadmin.reports.models import ReportsTemplatesModel, ReportsModel
from sbox4web.libs import update_system_statistics, add_report_job, update_task_statistic, update_target_statistic, \
    update_office_statistic, update_unit_statistic, update_system_statisticsv2
from sbox4web.rabbitmq import Rabbitmq
from targets.models import TasksModel, TargetsModel, TargetConfigurationsModel

__author__ = 'TOANTV'


class TaskShortSerializer(serializers.ModelSerializer):
    class Meta:
        model = TasksModel
        fields = ('id', 'target_addr',)


class TargetShortSerializer(serializers.ModelSerializer):
    class Meta:
        model = TargetsModel
        fields = ('id', 'name', 'address',)


class TargetConfigurationsShortSerializerInfo(serializers.ModelSerializer):
    class Meta:
        model = TargetConfigurationsModel
        fields = '__all__'


class ScansSerializer(serializers.ModelSerializer):
    task = TaskShortSerializer(read_only=True)
    target = serializers.SerializerMethodField(source='target', read_only=True)
    configuration = serializers.SerializerMethodField(source='configuration', read_only=True)

    class Meta:
        model = ScansModel
        read_only_fields = ('task', 'plugin',)
        fields = '__all__'

    def get_target(self, obj):
        target = obj.task.target
        return TargetShortSerializer(target).data

    def get_configuration(self, obj):
        configuration = obj.task.target.configuration
        return TargetConfigurationsShortSerializerInfo(configuration).data

    def update(self, instance, validated_data):
        # total_plugin_required = PluginsModel.objects.filter(plugin=instance.plguins_group, enabled=True,
        #                                                     required=True).count()
        # if total_plugin_required == 0:
        #     plugin_percent = 100
        # else:
        #     plugin_percent = int(100 / total_plugin_required)
        # instance.percent = validated_data.get('percent', instance.percent)
        if 'scripted_scan' in validated_data:
            scripts_diff = validated_data.get('scripted_scan')
            scripts_old = instance.scripted_scan
            for script in scripts_diff:
                if script not in scripts_old:
                    scripts_old.append(script)
        #
        #             plugin_object = PluginsModel.objects.filter(pk=plugin, enabled=True, required=True)
        #             if len(plugin_object) > 0:
        #                 instance.percent += plugin_percent
        #     if instance.percent >= 100:
        #         instance.percent = 100
        #     instance.os = plugins_old
        status = validated_data.get('status', instance.status)

        if status != instance.status:
            task_model = instance.task
            if status == 2 and instance.status < 2:
                instance.status = 2
                instance.start_time = int(time.time())

                if task_model.status < 2:
                    # Update task
                    task_model.start_time = int(time.time())
                    if task_model.target.configuration.scheduler.last_time is None:
                        task_model.target.configuration.scheduler.last_time = task_model.start_time
                        task_model.target.configuration.scheduler.save()
                    task_model.status = 2
                    task_model.save()

                    # Update target
                    task_model.target.status = 2
                    task_model.target.save()

            elif status == 3 and (instance.status < 3 or instance.status == 6):
                instance.status = 3
                instance.finish_time = int(time.time())
                instance.save()
                scans_models = ScansModel.objects.select_related('task').filter(task=task_model).order_by('id')
                self.update_task_finish(task_model, scans_models)

            elif (status == 4 or status == 5 or status == 6) and (instance.status < 3 or instance.status == 6):
                if status == 6:
                    instance.percent = 99
                elif status == 4:
                    status = 2

                    # Add retry scan
                    try:
                        server_node_name = task_model.target.server_node.name
                        plugin_name = instance.plugin.name
                        queue_name = "{}_{}".format(server_node_name, plugin_name)
                        rabbitmq = Rabbitmq(queue_name)
                        rabbitmq.add(str(instance.id))
                    except Exception, ex:
                        print "Cannot add scan to rabbitmq queue, error {}".format(str(ex))

                    try:
                        # send email for tech
                        email_template = EmailTemplate(email_subject="Securitybox4Website alert",
                                      email_recv=["tongtoan.85@gmail.com"],
                                      email_cc=[],
                                      email_bcc=[])
                        email_template.get_config(email="sboxteam.2015@gmail.com",
                                                  passwd="jhirvjtnwdyctplo",
                                                  mail_server="smtp.gmail.com",
                                                  port="587",
                                                  security="Auto")
                        email_template.send_email_scan_error(args=[instance.task.target.office.unit.name,
                                                             str(instance.task.target.office.unit.id),
                                                             instance.task.target.office.name.encode('utf-8'),
                                                             str(instance.task.target.office.id),
                                                             instance.task.target.name,
                                                             str(instance.task.target.id),
                                                             str(instance.task.id),
                                                             str(instance.id), instance.plugin.name,
                                                             str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))])
                    except Exception, ex:
                        print "Cannot send email scan error notify, error {}".format(str(ex))

                else:
                    instance.percent = 100
                instance.finish_time = int(time.time())
                instance.status = status
                instance.save()

                scans_models = ScansModel.objects.select_related('task').filter(task=task_model).order_by('id')

                # update task percent
                scans_finish_count = ScansModel.objects.filter(task=task_model).count()
                task_model.percent = int(scans_finish_count * 100 / scans_models.count())
                task_model.save()

                is_check_finish = True
                if not settings.IS_PARALLEL_MODE:
                    for scan in scans_models:
                        if scan.status > 3:
                            continue
                        if scan.status == 0 and scan.plugin.enabled:
                            scan.status = 1
                            scan.save()

                            # add queue
                            server_node_name = task_model.target.server_node.name
                            plugin_name = scan.plugin.name
                            queue_name = "{}_{}".format(server_node_name, plugin_name)
                            rabbitmq = Rabbitmq(queue_name)
                            rabbitmq.add(str(scan.id))

                            is_check_finish = False
                            break
                if is_check_finish:
                    self.update_task_finish(task_model, scans_models)

        instance.save()
        return instance

    def update_task_finish(self, task_model, scans_models):
        is_finish = True
        is_error = False
        is_paused = False
        for scan in scans_models:
            if scan.status < 3:
                is_finish = False
                is_error = False
                is_paused = False
                break
            elif scan.status == 3:
                is_paused = True
                break
            elif scan.status == 4:
                is_error = True

        if is_finish or is_error or is_paused:
            # Update task lasted
            # task_model.target.statistics.task.is_lasted = False
            # task_model.target.statistics.task.save()
            # task_model.is_lasted = True
            task_model.percent = 100
            # task_model.save()

            # Update target scheduler
            scheduler = task_model.target.configuration.scheduler
            if scheduler is not None:
                scheduler.last_time = task_model.finish_time
                scheduler.save()

            if is_paused:
                # Update task
                task_model.status = 3
                task_model.finish_time = int(time.time())
                task_model.save()

                # Update target
                task_model.target.status = 3
                task_model.target.save()

                # detect monitor alert
                SboxSecurityMonitor("TASK").monitor(task_model)

                # send email finish
                self.send_email_finish(task_model)

            elif is_error:
                # Update task
                task_model.status = 4
                task_model.finish_time = int(time.time())
                task_model.save()

                # Update target
                task_model.target.status = 4
                task_model.target.save()

                # detect monitor alert
                SboxSecurityMonitor("TASK").monitor(task_model)

            elif is_finish:
                # Update task
                task_model.status = 5
                task_model.finish_time = int(time.time())
                task_model.save()

                # Update target
                task_model.target.status = 5
                task_model.target.save()

                # detect monitor alert
                SboxSecurityMonitor("TASK").monitor(task_model)

                # send email finish
                self.send_email_finish(task_model)

            # Update System Statistic
            update_task_statistic(task_model)
            update_target_statistic(task_model.target)
            update_office_statistic(task_model.target.office)
            update_unit_statistic(task_model.target.office.unit)
            update_system_statisticsv2()

    def update_target_statistic(self, target):
        last_task_finish = TasksModel.objects.filter(target=target, status=5).order_by('-id').first()
        if last_task_finish is None:
            last_task_finish = TasksModel.objects.filter(target=target).order_by('-id').first()
        target.severity = last_task_finish.severity
        target.save()

        target.statistics.task = last_task_finish
        target.statistics.save()

    def create_report(self, task):
        report_templates = ReportsTemplatesModel.objects.all()
        for template in report_templates:
            pass
            # report = ReportsModel.objects.create(task=task, template=template, status=0)
            # report.save()
            #
            # # Add report job to rabbitmq
            # add_report_job(report)

    def send_email_finish(self, task):
        # send for admin
        if isinstance(task.target.configuration.email_notify, list) and len(task.target.configuration.email_notify) > 0:
            try:
                # send email for tech
                email_template = EmailTemplate(email_subject="Securitybox4Website Report",
                              email_recv=task.target.configuration.email_notify,
                              email_cc=[],
                              email_bcc=[])
                email_template.get_config()

                color = "green"
                alert = u"Chúng tôi đánh giá website của bạn đang an toàn."
                if task.severity == 3:
                    color = "red"
                    alert = u"Chúng tôi đánh giá an ninh website của bạn đang mức nguy hiểm."

                email_template.send_email_finish(args=[u"Quản trị viên".encode('utf-8'),
                                                     str(task.target.address),
                                                     color,
                                                     alert.encode('utf-8'),
                                                     str(task.statistics.critical_count + task.statistics.high_count),
                                                     str(task.statistics.malware_path_count),
                                                     str(task.statistics.domain_blacklist_alert_count),
                                                     str(task.statistics.website_content_alert_count),
                                                     str(task.statistics.website_down_status_count),
                                                     str(task.statistics.db_attack_count),
                                                     str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))])
            except Exception, ex:
                print "Cannot send email scan error notify, error {}".format(str(ex))

        # send for tongtoan.85
        try:
            # send email for tech
            email_template = EmailTemplate(email_subject="Securitybox4Website Report",
                          email_recv=["tongtoan.85@gmail.com"],
                          email_cc=[],
                          email_bcc=[])
            email_template.get_config(email="sboxteam.2015@gmail.com",
                                      passwd="jhirvjtnwdyctplo",
                                      mail_server="smtp.gmail.com",
                                      port="587",
                                      security="Auto")

            color = "green"
            alert = u"Chúng tôi đánh giá website của bạn đang an toàn."
            if task.severity == 3:
                color = "red"
                alert = u"Chúng tôi đánh giá an ninh website của bạn đang mức nguy hiểm."

            email_template.send_email_finish(args=[u"Quản trị viên".encode('utf-8'),
                                                 str(task.target.address),
                                                 color,
                                                 alert.encode('utf-8'),
                                                 str(task.statistics.critical_count + task.statistics.high_count),
                                                 str(task.statistics.malware_path_count),
                                                 str(task.statistics.domain_blacklist_alert_count),
                                                 str(task.statistics.website_content_alert_count),
                                                 str(task.statistics.website_down_status_count),
                                                 str(task.statistics.db_attack_count),
                                                 str(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))])
        except Exception, ex:
            print "Cannot send email scan error notify, error {}".format(str(ex))
