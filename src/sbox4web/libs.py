# -*- coding: utf-8 -*-
import re
from agents.crawldata.models import CrawlDataModel
from agents.crawldata.serializers import CrawlDataSerializer
from agents.database.models import WebsiteDatabasesModel
from agents.monitor.models import WebsiteSecurityAlertModel, SecurityEventsModels, WebsitePhishingDomainDetectModel, \
    WebsiteBlacklistCheckingModel, WebsiteMonitorUrl
from agents.scans.models import ScansModel
from agents.server_configurations.models import ServerConfigurationsModel
from agents.subdomains.models import WebsiteSubdomainsModel
from agents.vulns.serializers import HostVulnerabilityDetailSerializer
from systems.serializers import SystemStatisticsSerializers

__author__ = 'TOANTV'
import subprocess
import datetime
import time
from sbox4web import settings
from sbox4web.rabbitmq import Rabbitmq
from django.db.models import Sum
from systems.models import SystemStatistics, SystemsAlert
from targets.models import TargetStatisticsModel, TargetsModel, TaskStatisticsModel, TasksModel
from agents.hosts.models import HostsModel, HostStatisticsModel
from agents.services.models import HostServicesModel
from agents.vulns.models import HostVulnerabilityModel
from units.models import OfficesStatistics, UnitsStatistics, OfficesModel, UnitsModel


def update_all_scan_target():
    list_tasks_running = TasksModel.objects.filter(status=2)
    for task_running in list_tasks_running:
        list_scans = ScansModel.objects.filter(task=task_running)
        update_task_finish(task_running, list_scans)
        print "Updated task {}".format(str(task_running.id))


def update_task_finish(task_model, scans_models):
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
        print "Change task {} status to {} - {} - {}".format(str(task_model.id), str(is_paused), str(is_error),
                                                             str(is_finish))
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

        elif is_error:
            # Update task
            task_model.status = 4
            task_model.finish_time = int(time.time())
            task_model.save()

            # Update target
            task_model.target.status = 4
            task_model.target.save()

        elif is_finish:
            # Update task
            task_model.status = 5
            task_model.finish_time = int(time.time())
            task_model.save()

            # Update target
            task_model.target.status = 5
            task_model.target.save()

            # Update System Statistic
            # update_task_statistic(task_model)
            # update_target_statistic(task_model.target)
            # update_office_statistic(task_model.target.office)
            # update_unit_statistic(task_model.target.office.unit)
            # update_system_statisticsv2()


def update_all_msecurity():
    # all_hosts = HostsModel.objects.all()
    # all_hosts = HostsModel.objects.filter(pk=1648)
    # percent_of_host = float(100.0 / all_hosts.count())
    # percent = 0.0
    all_hosts = HostsModel.objects.filter(pk=1724)
    for host in all_hosts:
        old_security_alerts = WebsiteSecurityAlertModel.objects.filter(host=host, events__type='VULNERABLITY')
        print "Deleted {} old security alert of host {}".format(str(old_security_alerts.count()), str(host.id))
        for old_alert in old_security_alerts:
            # # Update old severity
            # if old_alert.events.severity != old_alert.details["vulnerability"]["severity"]:
            #     event_security = get_security_event(severity=old_alert.details["vulnerability"]["severity"])
            #     old_alert.events = event_security
            #     old_alert.save()

            # Delete security alert
            old_alert.delete()

        if HostVulnerabilityModel.objects.filter(host=host).count() > 0:
            print "Update security alert of host {}: {}".format(str(host.id), str(host.ip_addr))
            list_host_vulns = HostVulnerabilityModel.objects.filter(host=host)

            for host_vulns in list_host_vulns:
                if host_vulns.vulnerability.severity >= 2:
                    event_security = get_security_event(severity=host_vulns.vulnerability.severity)
                    details = HostVulnerabilityDetailSerializer(host_vulns).data
                    security_alert = WebsiteSecurityAlertModel.objects.create(type="VULNERABILITY",
                                                                              events=event_security,
                                                                              host=host,
                                                                              details=details,
                                                                              description=host_vulns.vulnerability.description,
                                                                              name=host_vulns.name,
                                                                              solution=host_vulns.vulnerability.solution)
                    security_alert.save()
                    if host_vulns.vulnerability.severity >= 3:
                        SystemsAlert.objects.create(contents=security_alert)
                    print "Update security {} alert of host {}: vuln name {}".format(
                        str(host_vulns.vulnerability.severity),
                        str(host.ip_addr),
                        str(host_vulns.name))

        if CrawlDataModel.objects.select_related('website').filter(website=host, security_level__gt=0).count() > 0:
            crawler_data = CrawlDataModel.objects.select_related('website').filter(website=host, security_level__gt=0)
            for path in crawler_data:
                event_security = SecurityEventsModels.objects.get(alert="MALWARE_DETECTED", type="MALWARE", severity=4)
                details = CrawlDataSerializer(path).data
                description = _("A malware is detect in website link.")
                solution = _("Please check website content source security.")
                security_alert = WebsiteSecurityAlertModel.objects.create(type="MALWARE",
                                                                          events=event_security,
                                                                          host=host,
                                                                          details=details,
                                                                          description="MALWARE_DETECTED",
                                                                          name=event_security.get_alert_display(),
                                                                          solution="MALWARE_DETECTED")

                # add system alert
                SystemsAlert.objects.create(contents=security_alert)

                # print "Finish {}% update security alert of host {}: {}".format(str(int(percent)), str(host.id),str(host.ip_addr))
    print "FINISH UPDATE SECURITY ALERT OF HOST!!!"


def update_vulnerability_msecurity():
    vulnerability_msecurities = WebsiteSecurityAlertModel.objects.filter(events__type='VULNERABLITY')
    # all_hosts = HostsModel.objects.filter(pk=1648)
    for mscurity in vulnerability_msecurities:
        severity = mscurity.events.severity
        if severity < 4:
            event_security = get_security_event(severity=severity + 1)
            mscurity.events = event_security
            mscurity.details["vulnerability"]["severity"] = severity + 1
            mscurity.save()
    update_all_statistic()
    print "FINISH UPDATE VULNERABILITY SECURITY ALERT OF HOST!!!"


def get_security_event(severity=4):
    # Get security event
    list_event_security = SecurityEventsModels.objects.filter(alert='NEW_VULNERABILITY', type='VULNERABLITY',
                                                              severity=severity)
    if list_event_security.count() == 0:
        event_security = SecurityEventsModels.objects.create(alert='NEW_VULNERABILITY', severity=severity,
                                                             type='VULNERABLITY')
        event_security.save()
    else:
        event_security = list_event_security[0]
    return event_security

def update_all_statistic():
    all_hosts = HostsModel.objects.all()
    for host in all_hosts:
        update_host_statistic(host)

    all_tasks = TasksModel.objects.all()
    for task in all_tasks:
        update_task_statistic(task)

    all_targets = TargetsModel.objects.all()
    for target in all_targets:
        update_target_statistic(target)

    all_offices = OfficesModel.objects.all()
    for office in all_offices:
        update_office_statistic(office)

    all_units = UnitsModel.objects.all()
    for unit in all_units:
        update_unit_statistic(unit)
    update_system_statisticsv2()

def update_host_task_statistic(host):
    update_host_statistic(host)
    update_task_statistic(host.task)


def update_host_task_system_statistic(host):
    update_host_statistic(host)
    update_task_statistic(host.task)
    update_target_statistic(host.task.target)
    update_office_statistic(host.task.target.office)
    update_unit_statistic(host.task.target.office.unit)
    update_system_statisticsv2()


def update_host_statistic(host):
    try:
        host_statistics = HostStatisticsModel.objects.get(host=host)
    except HostStatisticsModel.DoesNotExist:
        host_statistics = HostStatisticsModel.objects.create(host=host)
    host_statistics.ip_addr = host.ip_addr

    host_statistics.services_count = HostServicesModel.objects.select_related('host').filter(host=host).count()
    host_statistics.subdomains_count = WebsiteSubdomainsModel.objects.select_related('website').filter(
        website=host).count()
    host_statistics.paths_count = CrawlDataModel.objects.select_related('website').filter(website=host).count()
    host_statistics.server_configs_count = ServerConfigurationsModel.objects.select_related('website').filter(
        website=host).count()

    # Vunlnerability count
    host_statistics.vulns_count = HostVulnerabilityModel.objects.filter(host=host).count()
    host_statistics.info_count = HostVulnerabilityModel.objects.select_related('vulnerability').filter(host=host,
                                                                                                       vulnerability__severity=0).count()
    host_statistics.low_count = HostVulnerabilityModel.objects.select_related('vulnerability').filter(host=host,
                                                                                                      vulnerability__severity=1).count()

    host_statistics.medium_count = HostVulnerabilityModel.objects.select_related('vulnerability').filter(host=host,
                                                                                                         vulnerability__severity=2).count()

    host_statistics.high_count = HostVulnerabilityModel.objects.select_related('vulnerability').filter(host=host,
                                                                                                       vulnerability__severity=3).count()
    host_statistics.critical_count = HostVulnerabilityModel.objects.select_related('vulnerability').filter(host=host,
                                                                                                           vulnerability__severity=4).count()

    host_statistics.db_attack_count = WebsiteDatabasesModel.objects.select_related('website').filter(
        website=host).count()

    host_statistics.malware_path_count = CrawlDataModel.objects.select_related('website').filter(
        website=host, security_level__gt=0).count()

    host_statistics.abnormal_alert_count = WebsiteSecurityAlertModel.objects.select_related('host').filter(host=host,
                                                                                                           type="ABNORMAL").count()
    host_statistics.security_alert_count = WebsiteSecurityAlertModel.objects.select_related('host').filter(
        host=host).count()
    host_statistics.phishing_domain_count = WebsitePhishingDomainDetectModel.objects.filter(website=host,
                                                                                            security_level__gt=0).count()

    if WebsiteBlacklistCheckingModel.objects.select_related('website').filter(website=host, result=1).count() > 0:
        host_statistics.is_blacklist_detected = True
    else:
        host_statistics.is_blacklist_detected = False
    # host_statistics.is_site_down = ServerConfigurationsModel.objects.select_related('host').filter(
    #     website=host).count()
    #  host_statistics.is_website_content_alert = ServerConfigurationsModel.objects.select_related('host').filter(
    #     website=host).count()
    host_statistics.save()

    if WebsiteSecurityAlertModel.objects.select_related('host', 'events').filter(host=host,
                                                                                 events__severity__gte=3).count() > 0 or host_statistics.is_blacklist_detected > 0 or host_statistics.critical_count > 0 or host_statistics.high_count > 0 or host_statistics.db_attack_count > 0 or host_statistics.malware_path_count > 0:
        host.severity = 3
        host.save()
    # elif WebsiteSecurityAlertModel.objects.select_related('host', 'event').filter(host=host,
    #                                                                               events__severity__lte=2).count() > 0:
    else:
        host.severity = 1
        host.save()
    # else:
    #     host_statistics.severity = 1
    #     host_statistics.save()
    #
    #     host_statistics.severity = 1
    #     host_statistics.save()
    print "Finish update statistics host {}: {}\t\tResult: Severity {}, critical {}, high {}, abnormal {}, , malware {}, blacklist {}, web deface {}, site down {}, penetrations {}".format(
        str(host.id), str(host.ip_addr), str(host.severity),
        str(host_statistics.critical_count), str(host_statistics.high_count),
        str(host_statistics.abnormal_alert_count), str(host_statistics.malware_path_count),
        str(host_statistics.is_blacklist_detected), str(host_statistics.is_website_content_alert),
        str(host_statistics.is_site_down), str(host_statistics.db_attack_count))
    return host_statistics


def update_task_statistic(task):
    try:
        task_statistics = TaskStatisticsModel.objects.get(task=task)
    except TaskStatisticsModel.DoesNotExist:
        task_statistics = TaskStatisticsModel.objects.create(task=task)
    task_statistics.last_update = time.time()
    task_statistics.hosts_count = HostsModel.objects.filter(task=task).count()

    task_statistics.services_count = HostServicesModel.objects.select_related('host', 'host__task').filter(
        host__task=task).count()
    task_statistics.subdomains_count = WebsiteSubdomainsModel.objects.select_related('website', 'website__task').filter(
        website__task=task).count()
    task_statistics.paths_count = CrawlDataModel.objects.select_related('website', 'website__task').filter(
        website__task=task).count()
    task_statistics.server_configs_count = ServerConfigurationsModel.objects.select_related('website',
                                                                                            'website__task').filter(
        website__task=task).count()

    task_statistics.vulns_count = HostVulnerabilityModel.objects.filter(task=task).count()
    task_statistics.info_count = HostVulnerabilityModel.objects.select_related('vulnerability').filter(task=task,
                                                                                                       vulnerability__severity=0).count()
    task_statistics.low_count = HostVulnerabilityModel.objects.select_related('vulnerability').filter(task=task,
                                                                                                      vulnerability__severity=1).count()
    task_statistics.medium_count = HostVulnerabilityModel.objects.select_related('vulnerability').filter(task=task,
                                                                                                         vulnerability__severity=2).count()
    task_statistics.high_count = HostVulnerabilityModel.objects.select_related('vulnerability').filter(task=task,
                                                                                                       vulnerability__severity=3).count()
    task_statistics.critical_count = HostVulnerabilityModel.objects.select_related('vulnerability').filter(task=task,
                                                                                                           vulnerability__severity=4).count()

    task_statistics.db_attack_count = WebsiteDatabasesModel.objects.select_related('website', 'website__task').filter(
        website__task=task).count()

    task_statistics.malware_path_count = CrawlDataModel.objects.select_related('website', 'website__task').filter(
        website__task=task, security_level__gt=0).count()

    task_statistics.abnormal_alert_count = WebsiteSecurityAlertModel.objects.select_related('host',
                                                                                            'host__task').filter(
        host__task=task, type="ABNORMAL").count()
    task_statistics.security_alert_count = WebsiteSecurityAlertModel.objects.select_related('host',
                                                                                            'host__task').filter(
        host__task=task).count()

    task_statistics.phishing_domain_count = WebsitePhishingDomainDetectModel.objects.select_related('website',
                                                                                                    'website__task').filter(
        website__task=task, security_level__gt=0).count()

    task_statistics.domain_blacklist_alert_count = WebsiteSecurityAlertModel.objects.select_related('host',
                                                                                                    'host__task').filter(
        host__task=task, type="BLACKLIST").count()

    task_statistics.website_down_status_count = HostStatisticsModel.objects.select_related('host',
                                                                                           'host__task').filter(
        host__task=task, is_site_down=True).count()

    task_statistics.website_content_alert_count = HostStatisticsModel.objects.select_related('host',
                                                                                             'host__task').filter(
        host__task=task, is_website_content_alert=True).count()

    task_statistics.save()

    if HostsModel.objects.filter(severity=3, task=task).count() > 0:
        task.severity = 3
        task.save()

        task_statistics.severity = 3
        task_statistics.save()
    elif HostsModel.objects.filter(severity=2, task=task).count() > 0:
        task.severity = 1
        task.save()

        task_statistics.severity = 1
        task_statistics.save()
    else:
        task.severity = 1
        task.save()

        task_statistics.severity = 1
        task_statistics.save()
    print "Update task {}: {} statistics finish. Severity {} !!!".format(str(task.id), str(task.target.name),
                                                                         str(task.severity))
    print "Result: critical {}, high {}, abnormal {}, , malware {}, blacklist {}, web deface {}, site down {}, penetrations {}".format(
        str(task_statistics.critical_count), str(task_statistics.high_count),
        str(task_statistics.abnormal_alert_count), str(task_statistics.malware_path_count),
        str(task_statistics.domain_blacklist_alert_count), str(task_statistics.website_content_alert_count),
        str(task_statistics.website_down_status_count), str(task_statistics.db_attack_count))
    return task_statistics


def update_target_statistic(target):
    last_task_finish = get_last_task_finish(target)

    lasted_task_list = TasksModel.objects.filter(target=target, is_lasted=True)
    for lasted_task in lasted_task_list:
        lasted_task.is_lasted = False
        lasted_task.save()

    last_task_finish.is_lasted = True
    last_task_finish.save()

    try:
        target_statistics = TargetStatisticsModel.objects.get(target=target)
    except TargetStatisticsModel.DoesNotExist:
        target_statistics = TargetStatisticsModel.objects.create(target=target)

    target_statistics.task = last_task_finish
    target_statistics.save()

    if last_task_finish.severity == 3:
        target.severity = 3
        target.save()
    elif last_task_finish.severity == 2:
        target.severity = 2
        target.save()
    else:
        target.severity = 1
        target.save()
    try:
        print "Update target {}: {} statistics finish. Severity {}!!!".format(str(target.id), str(target.name),
                                                                              str(target.severity))
        print "Result: critical {}, high {}, abnormal {}, , malware {}, blacklist {}, web deface {}, site down {}, penetrations {}".format(
            str(target_statistics.critical_count), str(target_statistics.high_count),
            str(target_statistics.abnormal_alert_count), str(target_statistics.malware_path_count),
            str(target_statistics.domain_blacklist_alert_count), str(target_statistics.website_content_alert_count),
            str(target_statistics.website_down_status_count), str(target_statistics.db_attack_count))
    except Exception, ex:
        pass
    return target_statistics


def update_office_statistic(office):
    try:
        office_statistics = OfficesStatistics.objects.get(office=office)
    except OfficesStatistics.DoesNotExist:
        office_statistics = OfficesStatistics.objects.create(office=office)
    office_statistics.last_update = time.time()

    if TargetsModel.objects.select_related('office').filter(office=office).count() > 0:
        # targets_count
        office_statistics.targets_count = TargetsModel.objects.select_related('office').filter(office=office).count()

        # hosts_count
        office_statistics.hosts_count = TargetStatisticsModel.objects.select_related('task', 'task__statistics',
                                                                                     'target', 'target__office').filter(
            target__office=office).aggregate(hosts_sum=Sum('task__statistics__hosts_count'))["hosts_sum"]

        # services_count
        office_statistics.services_count = TargetStatisticsModel.objects.select_related('task', 'task__statistics',
                                                                                        'target',
                                                                                        'target__office').filter(
            target__office=office).aggregate(services_sum=Sum('task__statistics__services_count'))["services_sum"]

        # subdomains_count
        office_statistics.subdomains_count = TargetStatisticsModel.objects.select_related('task', 'task__statistics',
                                                                                          'target',
                                                                                          'target__office').filter(
            target__office=office).aggregate(subdomains_sum=Sum('task__statistics__subdomains_count'))["subdomains_sum"]

        # paths_count
        office_statistics.paths_count = TargetStatisticsModel.objects.select_related('task', 'task__statistics',
                                                                                     'target',
                                                                                     'target__office').filter(
            target__office=office).aggregate(paths_sum=Sum('task__statistics__paths_count'))["paths_sum"]

        # server_configs_count
        office_statistics.server_configs_count = \
            TargetStatisticsModel.objects.select_related('task', 'task__statistics',
                                                         'target',
                                                         'target__office').filter(
                target__office=office).aggregate(server_configs_sum=Sum('task__statistics__server_configs_count'))[
                "server_configs_sum"]

        # vulns_count
        office_statistics.vulns_count = TargetStatisticsModel.objects.select_related('task', 'task__statistics',
                                                                                     'target',
                                                                                     'target__office').filter(
            target__office=office).aggregate(vulns_sum=Sum('task__statistics__vulns_count'))["vulns_sum"]

        # info_count
        office_statistics.info_count = TargetStatisticsModel.objects.select_related('task', 'task__statistics',
                                                                                    'target', 'target__office').filter(
            target__office=office).aggregate(info_sum=Sum('task__statistics__info_count'))["info_sum"]

        # low_count
        office_statistics.low_count = TargetStatisticsModel.objects.select_related('task', 'task__statistics',
                                                                                   'target', 'target__office').filter(
            target__office=office).aggregate(low_sum=Sum('task__statistics__low_count'))["low_sum"]

        # medium_count
        office_statistics.medium_count = TargetStatisticsModel.objects.select_related('task', 'task__statistics',
                                                                                      'target',
                                                                                      'target__office').filter(
            target__office=office).aggregate(medium_sum=Sum('task__statistics__medium_count'))["medium_sum"]

        # high_count
        office_statistics.high_count = TargetStatisticsModel.objects.select_related('task', 'task__statistics',
                                                                                    'target', 'target__office').filter(
            target__office=office).aggregate(high_sum=Sum('task__statistics__high_count'))["high_sum"]

        # critical_count
        office_statistics.critical_count = TargetStatisticsModel.objects.select_related('task', 'task__statistics',
                                                                                        'target',
                                                                                        'target__office').filter(
            target__office=office).aggregate(critical_sum=Sum('task__statistics__critical_count'))["critical_sum"]

        # db_attack_count
        office_statistics.db_attack_count = TargetStatisticsModel.objects.select_related('task', 'task__statistics',
                                                                                         'target',
                                                                                         'target__office').filter(
            target__office=office).aggregate(db_attack_sum=Sum('task__statistics__db_attack_count'))["db_attack_sum"]

        # malware_path_count
        office_statistics.malware_path_count = TargetStatisticsModel.objects.select_related('task', 'task__statistics',
                                                                                            'target',
                                                                                            'target__office').filter(
            target__office=office).aggregate(malware_path_sum=Sum('task__statistics__malware_path_count'))[
            "malware_path_sum"]

        # abnormal_alert_count
        office_statistics.abnormal_alert_count = \
            TargetStatisticsModel.objects.select_related('task', 'task__statistics',
                                                         'target', 'target__office').filter(
                target__office=office).aggregate(abnormal_alerts_sum=Sum('task__statistics__abnormal_alert_count'))[
                "abnormal_alerts_sum"]

        # security_alert_count
        office_statistics.security_alert_count = \
            TargetStatisticsModel.objects.select_related('task', 'task__statistics',
                                                         'target', 'target__office').filter(
                target__office=office).aggregate(security_alerts_sum=Sum('task__statistics__security_alert_count'))[
                "security_alerts_sum"]

        # phishing_domain_count
        office_statistics.phishing_domain_count = \
            TargetStatisticsModel.objects.select_related('task', 'task__statistics',
                                                         'target', 'target__office').filter(
                target__office=office).aggregate(phishing_domain_sum=Sum('task__statistics__phishing_domain_count'))[
                "phishing_domain_sum"]

        # domain_blacklist_alert_count
        office_statistics.domain_blacklist_alert_count = \
            TargetStatisticsModel.objects.select_related('task', 'task__statistics',
                                                         'target', 'target__office').filter(
                target__office=office).aggregate(
                domain_blacklist_alert_sum=Sum('task__statistics__domain_blacklist_alert_count'))[
                "domain_blacklist_alert_sum"]

        # website_down_status_count
        office_statistics.website_down_status_count = \
            TargetStatisticsModel.objects.select_related('task', 'task__statistics',
                                                         'target', 'target__office').filter(
                target__office=office).aggregate(
                website_down_status_sum=Sum('task__statistics__website_down_status_count'))[
                "website_down_status_sum"]

        # website_content_alert_count
        office_statistics.website_content_alert_count = \
            TargetStatisticsModel.objects.select_related('task', 'task__statistics',
                                                         'target', 'target__office').filter(
                target__office=office).aggregate(
                website_content_alert_sum=Sum('task__statistics__website_content_alert_count'))[
                "website_content_alert_sum"]
    office_statistics.save()

    if TargetsModel.objects.select_related('office').filter(severity=3, office=office).count() > 0:
        office.severity = 3
        office.save()
    elif TargetsModel.objects.select_related('office').filter(severity=2, office=office).count() > 0:
        office.severity = 2
        office.save()
    # elif TargetsModel.objects.select_related('office').filter(severity=1, office=office).count() > 0:
    else:
        office.severity = 1
        office.save()
    try:
        print "Update office {}: {} statistics finish. Severity {}!!!".format(str(office.id), str(office.name),
                                                                              str(office.severity))
        print "Result: critical {}, high {}, abnormal {}, , malware {}, blacklist {}, web deface {}, site down {}, penetrations {}".format(
            str(office_statistics.critical_count), str(office_statistics.high_count),
            str(office_statistics.abnormal_alert_count), str(office_statistics.malware_path_count),
            str(office_statistics.domain_blacklist_alert_count), str(office_statistics.website_content_alert_count),
            str(office_statistics.website_down_status_count), str(office_statistics.db_attack_count))
    except Exception, ex:
        pass
    return office_statistics


def update_unit_statistic(unit):
    try:
        unit_statistics = UnitsStatistics.objects.get(unit=unit)
    except UnitsStatistics.DoesNotExist:
        unit_statistics = UnitsStatistics.objects.create(unit=unit)
    unit_statistics.last_update = time.time()

    if OfficesStatistics.objects.select_related('office', 'office__unit').filter(office__unit=unit).count() > 0:
        # targets_count
        unit_statistics.targets_count = OfficesStatistics.objects.select_related('office',
                                                                                 'office__unit').filter(
            office__unit=unit).count()

        # hosts_count
        unit_statistics.hosts_count = OfficesStatistics.objects.select_related('office',
                                                                               'office__unit').filter(
            office__unit=unit).aggregate(
            hosts_sum=Sum('hosts_count'))["hosts_sum"]

        # services_count
        unit_statistics.services_count = OfficesStatistics.objects.select_related('office',
                                                                                  'office__unit').filter(
            office__unit=unit).aggregate(
            services_sum=Sum('services_count'))["services_sum"]

        # subdomains_count
        unit_statistics.subdomains_count = OfficesStatistics.objects.select_related('office',
                                                                                    'office__unit').filter(
            office__unit=unit).aggregate(subdomains_sum=Sum('services_count'))["subdomains_sum"]

        # paths_count
        unit_statistics.paths_count = OfficesStatistics.objects.select_related('office',
                                                                               'office__unit').filter(
            office__unit=unit).aggregate(paths_sum=Sum('paths_count'))["paths_sum"]

        # server_configs_count
        unit_statistics.server_configs_count = OfficesStatistics.objects.select_related('office',
                                                                                        'office__unit').filter(
            office__unit=unit).aggregate(server_configs_sum=Sum('server_configs_count'))[
            "server_configs_sum"]

        # vulns_count
        unit_statistics.vulns_count = OfficesStatistics.objects.select_related('office',
                                                                               'office__unit').filter(
            office__unit=unit).aggregate(vulns_sum=Sum('vulns_count'))["vulns_sum"]

        # info_count
        unit_statistics.info_count = OfficesStatistics.objects.select_related('office',
                                                                              'office__unit').filter(
            office__unit=unit).aggregate(info_sum=Sum('info_count'))["info_sum"]

        # low_count
        unit_statistics.low_count = OfficesStatistics.objects.select_related('office',
                                                                             'office__unit').filter(
            office__unit=unit).aggregate(low_sum=Sum('low_count'))["low_sum"]

        # medium_count
        unit_statistics.medium_count = OfficesStatistics.objects.select_related('office',
                                                                                'office__unit').filter(
            office__unit=unit).aggregate(medium_sum=Sum('medium_count'))["medium_sum"]

        # high_count
        unit_statistics.high_count = OfficesStatistics.objects.select_related('office',
                                                                              'office__unit').filter(
            office__unit=unit).aggregate(high_sum=Sum('high_count'))["high_sum"]

        # critical_count
        unit_statistics.critical_count = OfficesStatistics.objects.select_related('office',
                                                                                  'office__unit').filter(
            office__unit=unit).aggregate(critical_sum=Sum('critical_count'))["critical_sum"]

        # db_attack_count
        unit_statistics.db_attack_count = OfficesStatistics.objects.select_related('office',
                                                                                   'office__unit').filter(
            office__unit=unit).aggregate(db_attack_sum=Sum('db_attack_count'))["db_attack_sum"]

        # malware_path_count
        unit_statistics.malware_path_count = OfficesStatistics.objects.select_related('office',
                                                                                      'office__unit').filter(
            office__unit=unit).aggregate(malware_path_sum=Sum('malware_path_count'))[
            "malware_path_sum"]

        # abnormal_alert_count
        unit_statistics.abnormal_alert_count = OfficesStatistics.objects.select_related('office',
                                                                                        'office__unit').filter(
            office__unit=unit).aggregate(abnormal_alerts_sum=Sum('abnormal_alert_count'))[
            "abnormal_alerts_sum"]

        # security_alert_count
        unit_statistics.security_alert_count = OfficesStatistics.objects.select_related('office',
                                                                                        'office__unit').filter(
            office__unit=unit).aggregate(security_alerts_sum=Sum('security_alert_count'))[
            "security_alerts_sum"]

        # phishing_domain_count
        unit_statistics.phishing_domain_count = OfficesStatistics.objects.select_related('office',
                                                                                         'office__unit').filter(
            office__unit=unit).aggregate(phishing_domain_sum=Sum('phishing_domain_count'))[
            "phishing_domain_sum"]

        # domain_blacklist_alert_count
        unit_statistics.domain_blacklist_alert_count = OfficesStatistics.objects.select_related('office',
                                                                                                'office__unit').filter(
            office__unit=unit).aggregate(domain_blacklist_alert_sum=Sum('domain_blacklist_alert_count'))[
            "domain_blacklist_alert_sum"]

        # website_down_status_count
        unit_statistics.website_down_status_count = OfficesStatistics.objects.select_related('office',
                                                                                             'office__unit').filter(
            office__unit=unit).aggregate(website_down_status_sum=Sum('website_down_status_count'))[
            "website_down_status_sum"]

        # website_content_alert_count
        unit_statistics.website_content_alert_count = OfficesStatistics.objects.select_related('office',
                                                                                               'office__unit').filter(
            office__unit=unit).aggregate(
            website_content_alert_sum=Sum('website_content_alert_count'))["website_content_alert_sum"]
    unit_statistics.save()

    if TargetsModel.objects.select_related('office', 'office__unit').filter(severity=3, office__unit=unit).count() > 0:
        unit.severity = 3
        unit.save()
    elif TargetsModel.objects.select_related('office', 'office__unit').filter(severity=2,
                                                                              office__unit=unit).count() > 0:
        unit.severity = 2
        unit.save()
    # elif TargetsModel.objects.select_related('office', 'office__unit').filter(severity=1,
    #                                                                           office__unit=unit).count() > 0:
    else:
        unit.severity = 1
        unit.save()
    try:
        print "Update unit {}: {} statistics finish!!!. Severity {}".format(str(unit.id), str(unit.name),
                                                                            str(unit.severity))
        print "Result: critical {}, high {}, abnormal {}, , malware {}, blacklist {}, web deface {}, site down {}, penetrations {}".format(
            str(unit_statistics.critical_count), str(unit_statistics.high_count),
            str(unit_statistics.abnormal_alert_count), str(unit_statistics.malware_path_count),
            str(unit_statistics.domain_blacklist_alert_count), str(unit_statistics.website_content_alert_count),
            str(unit_statistics.website_down_status_count), str(unit_statistics.db_attack_count))

    except Exception, ex:
        pass
    return unit_statistics

def update_system_update_time():
    systems_statistics_list = SystemStatistics.objects.all().order_by('id')
    last_time = 0
    for system_statistics in systems_statistics_list:
        if system_statistics.updated_time == 0 or system_statistics.updated_time == time.mktime(system_statistics.date_statistic.timetuple()):
            system_statistics.updated_time = time.mktime(datetime.datetime.combine(system_statistics.date_statistic, datetime.datetime.strptime("23:59", "%H:%M").time()).timetuple())
            system_statistics.save()

        list_task_finish = TasksModel.objects.filter(status=5, finish_time__lte=system_statistics.updated_time).order_by('-id')
        list_targets = []
        list_tasks = []
        for task in list_task_finish:
            if task.target not in list_targets:
                list_targets.append(task.target)
                list_tasks.append(task.id)

        system_statistics.tasks = list_tasks
        system_statistics.save()

        update_system_statistics_history(system_statistics)
        print "Update finish system statistic {}!!!".format(str(system_statistics.date_statistic))
    print "Update all finish system statistic!!!"

def update_system_statistics_history(system_statistics):
    tasks = system_statistics.tasks
    if len(tasks) == 0:
        return True

    # hosts_count
    system_statistics.hosts_count = TaskStatisticsModel.objects.filter(task__pk__in=tasks).aggregate(hosts_sum=Sum('hosts_count'))["hosts_sum"]

    # services_count
    system_statistics.services_count = TaskStatisticsModel.objects.filter(pk__in=tasks).aggregate(services_sum=Sum('services_count'))[
        "services_sum"]

    # subdomains_count
    system_statistics.subdomains_count = TaskStatisticsModel.objects.filter(pk__in=tasks).aggregate(subdomains_sum=Sum('subdomains_count'))[
        "subdomains_sum"]

    # paths_count
    system_statistics.paths_count = TaskStatisticsModel.objects.filter(pk__in=tasks).aggregate(paths_sum=Sum('paths_count'))[
        "paths_sum"]

    # server_configs_count
    system_statistics.server_configs_count = \
        TaskStatisticsModel.objects.filter(pk__in=tasks).aggregate(server_configs_sum=Sum('server_configs_count'))[
            "server_configs_sum"]

    # vulns_count
    system_statistics.vulns_count = TaskStatisticsModel.objects.filter(pk__in=tasks).aggregate(vulns_sum=Sum('vulns_count'))["vulns_sum"]

    # info_count
    system_statistics.info_count = TaskStatisticsModel.objects.filter(pk__in=tasks).aggregate(infos_sum=Sum('info_count'))["infos_sum"]

    # low_count
    system_statistics.low_count = TaskStatisticsModel.objects.filter(pk__in=tasks).aggregate(lows_sum=Sum('low_count'))["lows_sum"]

    # medium_count
    system_statistics.medium_count = TaskStatisticsModel.objects.filter(pk__in=tasks).aggregate(mediums_sum=Sum('medium_count'))["mediums_sum"]

    # high_count
    system_statistics.high_count = TaskStatisticsModel.objects.filter(pk__in=tasks).aggregate(highs_sum=Sum('high_count'))["highs_sum"]

    # critical_count
    system_statistics.critical_count = TaskStatisticsModel.objects.filter(pk__in=tasks).aggregate(criticals_sum=Sum('critical_count'))[
        "criticals_sum"]

    # db_attack_count
    system_statistics.db_attack_count = TaskStatisticsModel.objects.filter(pk__in=tasks).aggregate(db_attack_sum=Sum('db_attack_count'))[
        "db_attack_sum"]

    # malware_path_count
    system_statistics.malware_path_count = \
        TaskStatisticsModel.objects.filter(pk__in=tasks).aggregate(malware_path_sum=Sum('malware_path_count'))["malware_path_sum"]

    # abnormal_alert_count
    system_statistics.abnormal_alert_count = \
        TaskStatisticsModel.objects.filter(pk__in=tasks).aggregate(abnormal_alert_sum=Sum('abnormal_alert_count'))["abnormal_alert_sum"]

    # security_alert_count
    system_statistics.security_alert_count = \
        TaskStatisticsModel.objects.filter(pk__in=tasks).aggregate(security_alerts_sum=Sum('security_alert_count'))["security_alerts_sum"]

    # phishing_domain_count
    system_statistics.phishing_domain_count = \
        TaskStatisticsModel.objects.filter(pk__in=tasks).aggregate(phishing_domain_sum=Sum('phishing_domain_count'))["phishing_domain_sum"]

    # domain_blacklist_alert_count
    system_statistics.domain_blacklist_alert_count = \
        TaskStatisticsModel.objects.filter(pk__in=tasks).aggregate(domain_blacklist_alert_sum=Sum('domain_blacklist_alert_count'))[
            "domain_blacklist_alert_sum"]

    # website_content_alert_count
    system_statistics.website_content_alert_count = \
        TaskStatisticsModel.objects.filter(pk__in=tasks).aggregate(website_content_alert_sum=Sum('website_content_alert_count'))[
            "website_content_alert_sum"]

    # website_down_status_count
    system_statistics.website_down_status_count = \
        TaskStatisticsModel.objects.filter(pk__in=tasks).aggregate(website_down_status_sum=Sum('website_down_status_count'))[
            "website_down_status_sum"]

    if TaskStatisticsModel.objects.filter(severity=3, pk__in=tasks).count() > 0:
        system_statistics.severity = 3
        system_statistics.save()
    elif TaskStatisticsModel.objects.filter(severity=2, pk__in=tasks).count() > 0:
        system_statistics.severity = 2
        system_statistics.save()
    # elif TargetsModel.objects.filter(severity=1).count() > 0:
    else:
        system_statistics.severity = 1
        system_statistics.save()
    print "Update system statistics finish!!!"
    print "Result: critical {}, high {}, abnormal {}, , malware {}, blacklist {}, web deface {}, site down {}, penetrations {}".format(
        str(system_statistics.critical_count), str(system_statistics.high_count),
        str(system_statistics.abnormal_alert_count), str(system_statistics.malware_path_count),
        str(system_statistics.domain_blacklist_alert_count), str(system_statistics.website_content_alert_count),
        str(system_statistics.website_down_status_count), str(system_statistics.db_attack_count))
    return system_statistics


def update_system_statisticsv2():
    print "Update system statistics!!!"
    date_now = datetime.datetime.today().date()
    list_task_finish = list(TasksModel.objects.filter(is_lasted=True).values_list('id', flat=True))

    # Update System Statistic
    if SystemStatistics.objects.all().count() == 0:
        system_statistics = SystemStatistics.objects.create(date_statistic=date_now, updated_time=int(time.time()))
        system_statistics.tasks = list_task_finish
    else:
        system_statistics = SystemStatistics.objects.all().order_by('-id').first()
        if not set(system_statistics.tasks) == set(list_task_finish):
            system_statistics = SystemStatistics.objects.create(date_statistic=date_now, updated_time=int(time.time()))
            system_statistics.tasks = list_task_finish
        else:
            system_statistics.date_statistic = date_now
            system_statistics.updated_time = int(time.time())

    # hosts_count
    system_statistics.hosts_count = UnitsStatistics.objects.aggregate(hosts_sum=Sum('hosts_count'))["hosts_sum"]

    # services_count
    system_statistics.services_count = UnitsStatistics.objects.aggregate(services_sum=Sum('services_count'))[
        "services_sum"]

    # subdomains_count
    system_statistics.subdomains_count = UnitsStatistics.objects.aggregate(subdomains_sum=Sum('subdomains_count'))[
        "subdomains_sum"]

    # paths_count
    system_statistics.paths_count = UnitsStatistics.objects.aggregate(paths_sum=Sum('paths_count'))[
        "paths_sum"]

    # server_configs_count
    system_statistics.server_configs_count = \
        UnitsStatistics.objects.aggregate(server_configs_sum=Sum('server_configs_count'))[
            "server_configs_sum"]

    # vulns_count
    system_statistics.vulns_count = UnitsStatistics.objects.aggregate(vulns_sum=Sum('vulns_count'))["vulns_sum"]

    # info_count
    system_statistics.info_count = UnitsStatistics.objects.aggregate(infos_sum=Sum('info_count'))["infos_sum"]

    # low_count
    system_statistics.low_count = UnitsStatistics.objects.aggregate(lows_sum=Sum('low_count'))["lows_sum"]

    # medium_count
    system_statistics.medium_count = UnitsStatistics.objects.aggregate(mediums_sum=Sum('medium_count'))["mediums_sum"]

    # high_count
    system_statistics.high_count = UnitsStatistics.objects.aggregate(highs_sum=Sum('high_count'))["highs_sum"]

    # critical_count
    system_statistics.critical_count = UnitsStatistics.objects.aggregate(criticals_sum=Sum('critical_count'))[
        "criticals_sum"]

    # db_attack_count
    system_statistics.db_attack_count = UnitsStatistics.objects.aggregate(db_attack_sum=Sum('db_attack_count'))[
        "db_attack_sum"]

    # malware_path_count
    system_statistics.malware_path_count = \
        UnitsStatistics.objects.aggregate(malware_path_sum=Sum('malware_path_count'))["malware_path_sum"]

    # abnormal_alert_count
    system_statistics.abnormal_alert_count = \
        UnitsStatistics.objects.aggregate(abnormal_alert_sum=Sum('abnormal_alert_count'))["abnormal_alert_sum"]

    # security_alert_count
    system_statistics.security_alert_count = \
        UnitsStatistics.objects.aggregate(security_alerts_sum=Sum('security_alert_count'))["security_alerts_sum"]

    # phishing_domain_count
    system_statistics.phishing_domain_count = \
        UnitsStatistics.objects.aggregate(phishing_domain_sum=Sum('phishing_domain_count'))["phishing_domain_sum"]

    # domain_blacklist_alert_count
    system_statistics.domain_blacklist_alert_count = \
        UnitsStatistics.objects.aggregate(domain_blacklist_alert_sum=Sum('domain_blacklist_alert_count'))[
            "domain_blacklist_alert_sum"]

    # website_content_alert_count
    system_statistics.website_content_alert_count = \
        UnitsStatistics.objects.aggregate(website_content_alert_sum=Sum('website_content_alert_count'))[
            "website_content_alert_sum"]

    # website_down_status_count
    system_statistics.website_down_status_count = \
        UnitsStatistics.objects.aggregate(website_down_status_sum=Sum('website_down_status_count'))[
            "website_down_status_sum"]

    if TargetsModel.objects.filter(severity=3).count() > 0:
        system_statistics.severity = 3
        system_statistics.save()
    elif TargetsModel.objects.filter(severity=2).count() > 0:
        system_statistics.severity = 2
        system_statistics.save()
    # elif TargetsModel.objects.filter(severity=1).count() > 0:
    else:
        system_statistics.severity = 1
        system_statistics.save()
    system_statistics.updated_time = int(time.time())
    system_statistics.save()
    print "Update system statistics finish!!!"
    print "Result: critical {}, high {}, abnormal {}, , malware {}, blacklist {}, web deface {}, site down {}, penetrations {}".format(
        str(system_statistics.critical_count), str(system_statistics.high_count),
        str(system_statistics.abnormal_alert_count), str(system_statistics.malware_path_count),
        str(system_statistics.domain_blacklist_alert_count), str(system_statistics.website_content_alert_count),
        str(system_statistics.website_down_status_count), str(system_statistics.db_attack_count))

    # # If SystemStatistics is None
    # total_statistics = SystemStatistics.objects.all().count()
    # if total_statistics >= 2:
    #     lasted_statistics = SystemStatistics.objects.all().order_by('-id')[1]
    #     lasted_statistic_data = SystemStatisticsSerializers(lasted_statistics).data
    #     del lasted_statistic_data["date_statistic"]
    #     del lasted_statistic_data["updated_time"]
    #     del lasted_statistic_data["id"]
    #
    #     current_statistic_data = SystemStatisticsSerializers(system_statistics).data
    #     del current_statistic_data["date_statistic"]
    #     del current_statistic_data["updated_time"]
    #     del current_statistic_data["id"]
    #
    #     if cmp(lasted_statistic_data, current_statistic_data) == 0:
    #         lasted_statistics.delete()
    return system_statistics


def update_system_statistics():
    print "Update system statistics!!!"
    # Update System Statistic
    date_now = datetime.datetime.today().date()
    try:
        system_statistics = SystemStatistics.objects.get(date_statistic=date_now)
    except SystemStatistics.DoesNotExist:
        system_statistics = SystemStatistics.objects.create(date_statistic=date_now)

    system_statistics.hosts_count = TargetStatisticsModel.objects.select_related('task',
                                                                                 'task__statistics').aggregate(
        hosts_sum=Sum('task__statistics__hosts_count'))["hosts_sum"]

    system_statistics.services_count = TargetStatisticsModel.objects.select_related('task',
                                                                                    'task__statistics').aggregate(
        services_sum=Sum('task__statistics__services_count'))["services_sum"]

    system_statistics.critical_count = TargetStatisticsModel.objects.select_related('task',
                                                                                    'task__statistics').aggregate(
        critical_sum=Sum('task__statistics__critical_count'))["critical_sum"]

    system_statistics.high_count = TargetStatisticsModel.objects.select_related('task',
                                                                                'task__statistics').aggregate(
        high_sum=Sum('task__statistics__high_count'))["high_sum"]

    system_statistics.medium_count = TargetStatisticsModel.objects.select_related('task',
                                                                                  'task__statistics').aggregate(
        medium_sum=Sum('task__statistics__medium_count'))["medium_sum"]

    system_statistics.low_count = TargetStatisticsModel.objects.select_related('task',
                                                                               'task__statistics').aggregate(

        low_sum=Sum('task__statistics__low_count'))["low_sum"]

    system_statistics.info_count = TargetStatisticsModel.objects.select_related('task',
                                                                                'task__statistics').aggregate(
        info_sum=Sum('task__statistics__info_count'))["info_sum"]

    system_statistics.vulns_count = system_statistics.critical_count + system_statistics.high_count + \
                                    system_statistics.medium_count + system_statistics.low_count + \
                                    system_statistics.info_count

    system_statistics.save()
    print "Update system statistics finish!!!"


def ping_window(address):
    pattern = "(^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$)"
    if not re.search(pattern, address, re.M | re.I):
        return {"status": "error"}

    p = subprocess.Popen('ping -n 3 -w 1000 ' + address, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    response = []
    for line in p.stdout:
        output = line.rstrip().decode('UTF-8')
        response.append(output)
    return response


def ping_linux(address):
    p = subprocess.Popen('ping -c 3 -w 1000 ' + address, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    response = []
    for line in p.stdout:
        output = line.rstrip().decode('UTF-8')
        response.append(output)
    return response


def status_monitor_scheduler():
    while True:
        print "Start monitor status and monitor content website."
        start_time = int(time.time())

        # # Status monitor
        # list_tasks = TargetsModel.objects.values_list('last_task_id', flat=True)
        list_tasks = TargetsModel.objects.select_related('configuration', 'configuration__scheduler').exclude(
            configuration__scheduler__time_interval=0, status__gte=3).values_list('last_task_id', flat=True)

        list_hosts = HostsModel.objects.prefetch_related('task', 'task__target').filter(task_id__in=list(list_tasks))
        for host in list_hosts:
            try:
                server_node_name = host.task.target.server_node.name
                queue_name = "{}_mstatus".format(server_node_name)
                rabbitmq = Rabbitmq(queue_name)
                rabbitmq.add(str(host.id))
                print "Added website {}: {} to queue {}".format(str(host.id), str(host.ip_addr), queue_name)
            except Exception, ex:
                print "Cannot add message to server, exception {}".format(str(ex))
        #
        # # Content monitor
        # list_urls = WebsiteMonitorUrl.objects.filter(is_enabled=True)
        # for url in list_urls:
        #     queue_name = "mcontents"
        #     rabbitmq = Rabbitmq(queue_name)
        #     rabbitmq.add(str(url.id))

        finish_time = int(time.time())
        print "Finish monitor status and monitor content website."
        time.sleep(settings.IS_STATUS_MONITOR_INTERVAL - finish_time + start_time)


def website_content_monitor_scheduler():
    while True:
        print "Start website content monitor"
        start_time = int(time.time())

        # Status monitor
        list_tasks = TargetsModel.objects.select_related('configuration', 'configuration__scheduler').exclude(
            configuration__scheduler__time_interval=0, status__gte=3).values_list('last_task_id', flat=True)
        list_hosts = HostsModel.objects.prefetch_related('task', 'task__target').filter(task_id__in=list(list_tasks))
        for host in list_hosts:
            try:
                url_monitor = WebsiteMonitorUrl.objects.filter(is_enabled=True, url=host.ip_addr,
                                                               target=host.task.target).first()
                if url_monitor is not None:
                    server_node_name = url_monitor.target.server_node.name
                    queue_name = "{}_mcontents".format(server_node_name)
                    rabbitmq = Rabbitmq(queue_name)
                    rabbitmq.add(str(url_monitor.id))
                    print "Added Url monitor {}: {} to queue {}".format(str(url_monitor.id), str(url_monitor.url),
                                                                        queue_name)
            except Exception, ex:
                print "Cannot add message to server, exception {}".format(str(ex))

        extends_url = [381, 33, 8, 380]
        for url_monitor_id in extends_url:
            try:
                if url_monitor_id is not None:
                    server_node_name = "localhost"
                    queue_name = "{}_mcontents".format(server_node_name)
                    rabbitmq = Rabbitmq(queue_name)
                    rabbitmq.add(str(url_monitor_id))
                    print "Added Url monitor {} to queue {}".format(str(url_monitor_id), queue_name)
            except Exception, ex:
                print "Cannot add message to server, exception {}".format(str(ex))

        finish_time = int(time.time())
        print "Finish website content monitor website."
        time.sleep(settings.IS_STATUS_MONITOR_INTERVAL - finish_time + start_time)


def add_report_job(report_job):
    try:
        server_node_name = "localhost"
        queue_name = "{}_reports".format(server_node_name)
        rabbitmq = Rabbitmq(queue_name)
        rabbitmq.add(str(report_job.id))
    except Exception, ex:
        print "Cannot add message to server, exception {}".format(str(ex))


def get_last_task_finish(target):
    last_task_finish = TasksModel.objects.filter(target=target, status=5).order_by('-id').first()
    if last_task_finish is None:
        last_task_finish = TasksModel.objects.filter(target=target).order_by('-id').first()
    return last_task_finish
