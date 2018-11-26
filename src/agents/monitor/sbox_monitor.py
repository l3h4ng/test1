# -*- coding: utf-8 -*-
from __future__ import unicode_literals
from agents.monitor.serializers import WebsiteBlacklistChecking2DetailsSerializer, \
    WebsiteMonitorStatusSerializer, WebsiteMonitorContentHistoryInfoSerializer
from django.utils.translation import ugettext_lazy as _
from agents.hosts.models import HostsModel
from agents.hosts.serializers import HostInfoSerializer
from agents.monitor.models import SecurityEventsModels, WebsiteSecurityAlertModel, SoftwareLastVersionModel, \
    WebsiteMonitorContentStatusModel
from agents.services.models import HostServicesModel
from agents.services.serializers import ServiceSerializer
from agents.database.serializers import WebsiteDatabaseSerializer
from agents.vulns.models import HostVulnerabilityModel
from agents.vulns.serializers import HostVulnerabilityDetailSerializer
from sbox4web.libs import update_host_statistic, update_target_statistic, update_office_statistic, \
    update_unit_statistic, \
    update_system_statisticsv2
from sbox4web.libs import update_task_statistic
from systems.models import SystemsAlert
from targets.models import TasksModel

__author__ = 'TOANTV'


class SboxSecurityMonitor:
    def __init__(self, event_type):
        self.event_type = event_type
        self.current_target = None
        self.current_task = None
        self.current_host = None
        self.current_service = None
        self.current_vuln = None
        self.current_host_vulns = None
        self.current_session = None

        # last task
        self.last_task = None
        self.last_host = None
        self.last_service = None
        self.last_vuln = None
        self.last_host_vulns = None
        self.last_session = None

    def get_task_info(self, object):
        # object is a task object
        if self.event_type == "TASK":
            self.current_task = object

        # object is a host object
        elif self.event_type == "HOST":
            self.current_host = object

        # object is a service object
        elif self.event_type == "SERVICE":
            self.current_service = object
            self.current_host = self.current_service.host

        elif self.event_type == "VULNERABLITY":
            self.current_host_vulns = object
            self.current_vuln = object.vulnerability
            self.current_host = self.current_host_vulns.host

        elif self.event_type == "PENETRATION":
            self.db_attack = object
            self.current_host = self.db_attack.website

        elif self.event_type == "BLACKLIST":
            self.current_blacklist_object = object
            self.current_host = object.website

        elif self.event_type == "MALWARE":
            self.current_blacklist_object = object
            self.current_host = object.website

        elif self.event_type == "SITE_DOWN":
            self.realtime_object = object
            self.current_host = object.website

        elif self.event_type == "WEB_DEFACE":
            self.url_monitor = object
            host = HostsModel.objects.prefetch_related('task', 'task__target').filter(
                task__id=object.target.last_task_id, ip_addr=object.url)
            if host.count() > 0:
                self.current_host = host[0]

        if self.current_host != None:
            self.current_task = self.current_host.task

    def get_last_task(self):
        if self.current_task != None:
            self.current_target = self.current_task.target
            # get all list task of target
            list_tasks = TasksModel.objects.filter(target=self.current_target).order_by("-id")
            if len(list_tasks) >= 2:
                self.last_task = list_tasks[1]
                return True
            return None
        return None

    def monitor2(self, object, alert=""):
        self.get_task_info(object)
        if self.event_type == "HOST":
            self.monitor_host_events()

    def monitor_host_events(self):
        print "Host {}: Start detect host {} unexpected".format(str(self.current_host.ip_addr),
                                                                str(self.current_host.ip_addr))
        if self.get_last_task():  # if have last task
            host_info = self.monitor_new_host()
            print "Host {}: {}".format(str(self.current_host.ip_addr), host_info)
            if host_info == "NEW_DEVICE":
                self.create_new_device_alert()

            elif host_info == "DEVICE_CHANGE_IP":
                self.create_new_security_event_alert(alert="DEVICE_CHANGE_IP", severity=1)

    def create_new_device_alert(self):
        alert = "NEW_DEVICE"
        event_security = self.get_security_event(alert=alert, type=self.event_type, severity=3)
        details = HostInfoSerializer(self.current_host).data
        security_alert = WebsiteSecurityAlertModel.objects.create(type="ABNORMAL",
                                                                  events=event_security,
                                                                  host=self.current_host,
                                                                  details=details,
                                                                  description=alert,
                                                                  name=event_security.get_alert_display(),
                                                                  solution=alert)
        # add system alert
        SystemsAlert.objects.create(contents=security_alert)

    def create_new_device_change_ip_alert(self):
        alert = "DEVICE_CHANGE_IP"
        event_security = self.get_security_event(alert=alert, type=self.event_type, severity=1)
        if not WebsiteSecurityAlertModel.objects.filter(events=event_security,
                                                        host=self.current_host).count() > 0:
            details = {
                "old": HostInfoSerializer(self.last_host).data,
                "new": HostInfoSerializer(self.current_host).data,
            }
            security_alert = WebsiteSecurityAlertModel.objects.create(type="ABNORMAL",
                                                                      events=event_security,
                                                                      host=self.current_host,
                                                                      details=details,
                                                                      description=alert,
                                                                      name=event_security.get_alert_display(),
                                                                      solution=alert)

    def monitor(self, object):
        self.get_task_info(object)
        if self.event_type == "HOST":
            print "Host {}: Start detect host {} unexpected".format(str(self.current_host.ip_addr),
                                                                    str(self.current_host.ip_addr))
            if self.get_last_task():  # if have last task
                host_info = self.monitor_new_host()
                print "Host {}: {}".format(str(self.current_host.ip_addr), host_info)
                if host_info == "NEW_DEVICE":
                    self.create_new_security_event_alert(alert="NEW_DEVICE", severity=3)
                elif host_info == "DEVICE_CHANGE_IP":
                    self.create_new_security_event_alert(alert="DEVICE_CHANGE_IP", severity=1)

        # object is a service object
        elif self.event_type == "SERVICE":
            print "Host {}: Start detect service {} unexpected".format(str(self.current_host.ip_addr),
                                                                       str(self.current_service.port))
            if self.get_last_task() and self.monitor_new_host() in ["OLD_DEVICE", "DEVICE_CHANGE_IP"]:
                service_info = self.detect_service_change()
                # if "SERVICE_CHANGED" in service_info:
                #	 self.create_new_security_event_alert(alert="SERVICE_CHANGED", severity=1)
                #	 print "Host {}: {} ==> SERVICE_CHANGED".format(str(self.current_host.ip_addr), str(self.current_service.port))

                if "SERVICE_VERSION_TOO_OLD" in service_info:
                    self.create_new_security_event_alert(alert="SERVICE_VERSION_TOO_OLD", severity=3)
                    print "Host {}: {} ==> SERVICE_VERSION_TOO_OLD".format(str(self.current_host.ip_addr),
                                                                           str(self.current_service.port))

                if "NEW_SERVICE" in service_info:
                    self.create_new_security_event_alert(alert="NEW_SERVICE", severity=3)
                    print "Host {}: {} ==> NEW_SERVICE".format(str(self.current_host.ip_addr),
                                                               str(self.current_service.port))

        elif self.event_type == "VULNERABLITY":
            print "Host {}: Start detect vuln {} unexpected".format(str(self.current_host.ip_addr),
                                                                    str(self.current_host_vulns.name))
            # if self.current_vuln.severity >= 3:
            self.create_new_security_event_alert(alert="NEW_VULNERABILITY",
                                                 severity=self.current_host_vulns.vulnerability.severity)
            print "Host {}: {} ==> NEW_VULNERABILITY".format(str(self.current_host.ip_addr),
                                                             str(self.current_host_vulns.name))
        # if self.get_last_task():
        # if self.detect_vuln_high_is_not_fix():
        # self.create_new_security_event_alert(alert="VULNERABILITY_IS_NOT_FIX", severity=3)
        # print "Host {}: {} ==> VULNERABILITY_IS_NOT_FIX".format(str(self.current_host.ip_addr),
        # str(self.current_host_vulns.name))

        elif self.event_type == "PENETRATION":
            print "Host {}: Penetration testing is successful".format(str(self.current_host.ip_addr))
            self.create_new_security_event_alert(alert="NEW_PENETRATION", severity=4)
            print "Host {}==> NEW_PENETRATION IS SUCCESSFULL".format(str(self.current_host.ip_addr))

        elif self.event_type == "BLACKLIST":
            print "Host {}: Start detect blacklist {} unexpected".format(str(self.current_host.ip_addr),
                                                                         str(
                                                                             self.current_blacklist_object.get_type_display()))
            self.create_new_security_event_alert(alert="BKACLIST_DETECTED", severity=3)
            print "BKACLIST_DETECTED"

        elif self.event_type == "MALWARE":
            self.create_new_security_event_alert(alert="MALWARE_DETECTED", severity=4)
            print "MALWARE_DETECTED"

        elif self.event_type == "SITE_DOWN":
            if self.realtime_object.web_status >= 400:
                self.create_new_security_event_alert(alert="SERVER_STATUS", severity=3)
                print "SITE_DOWN"

        elif self.event_type == "WEB_DEFACE":
            self.create_new_security_event_alert(alert="WEBSITE_CONTENT_DETECTED", severity=3)
            print "WEB_DEFACE"

        elif self.event_type == "TASK":
            print "Task {}: Start detect task unexpected".format(str(self.current_task.id))
            if self.current_task.statistics.hosts_count == 0:
                self.create_new_security_event_alert(alert="CANNOT_CONNECT_TO_TARGET", severity=2)
                print "CANNOT_CONNECT_TO_TARGET"

            if self.get_last_task():  # if have last task
                list_current_hosts = HostsModel.objects.filter(task=self.current_task)
                list_last_hosts = HostsModel.objects.filter(task=self.current_task)

                for current_host in list_current_hosts:
                    self.current_host = current_host
                    host_monitor = self.monitor_new_host()

                    # Redetect device chang ip
                    if host_monitor == "DEVICE_CHANGE_IP":
                        self.create_new_security_event_alert(alert="DEVICE_CHANGE_IP", severity=1)

                    if host_monitor in ["DEVICE_CHANGE_IP", "OLD_DEVICE"]:
                        # Detect service change and service is old version
                        list_current_service = HostServicesModel.objects.filter(host=self.current_host)
                        for current_service in list_current_service:
                            self.current_service = current_service
                            service_info = self.detect_service_change()
                            if "SERVICE_CHANGED" in service_info:
                                self.create_new_security_event_alert(alert="SERVICE_CHANGED", severity=3)
                                print "Host {}: {} ==> SERVICE_CHANGED".format(str(self.current_host.ip_addr),
                                                                               str(self.current_service.port))

                            if "SERVICE_VERSION_TOO_OLD" in service_info:
                                self.create_new_security_event_alert(alert="SERVICE_VERSION_TOO_OLD", severity=3)
                                print "Host {}: {} ==> SERVICE_VERSION_TOO_OLD".format(str(self.current_host.ip_addr),
                                                                                       str(self.current_service.port))

                        # Detect service off
                        list_last_services = HostServicesModel.objects.filter(host=self.last_host)
                        for last_service in list_last_services:
                            if self.detect_service_off(last_service):
                                self.last_service = last_service
                                self.create_new_security_event_alert(alert="SERVICE_CLOSED", severity=1)
                                print "SERVICE_CLOSED"

                for last_host in list_last_hosts:
                    if self.detect_host_off(last_host):
                        self.last_host = last_host
                        self.create_new_security_event_alert(alert="DEVICE_TURN_OFF", severity=1)
                        print "DEVICE_TURN_OFF"

            else:
                print "No last task"
                return True

    def create_new_security_event_alert(self, alert="", severity=0):
        if alert != "" and severity > 0:
            # Get security event
            list_event_security = SecurityEventsModels.objects.filter(alert=alert, type=self.event_type,
                                                                      severity=severity)
            if list_event_security.count() == 0:
                event_security = SecurityEventsModels.objects.create(alert=alert, severity=severity,
                                                                     type=self.event_type)
                event_security.save()
            else:
                event_security = list_event_security[0]

            # Content of security alert
            if alert == "NEW_DEVICE":
                details = HostInfoSerializer(self.current_host).data
                description = _("Detect new device in your network.")
                solution = _("Please check list devices connected in your network.")
                security_alert = WebsiteSecurityAlertModel.objects.create(type="ABNORMAL",
                                                                          events=event_security,
                                                                          host=self.current_host,
                                                                          details=details,
                                                                          description=alert,
                                                                          name=event_security.get_alert_display(),
                                                                          solution=alert)

                # add system alert
                SystemsAlert.objects.create(contents=security_alert)

            elif alert == "DEVICE_TURN_OFF":
                details = HostInfoSerializer(self.last_host).data
                description = _("A device is turn off in your network.")
                solution = _("Please check your network connection with your device.")
                security_alert = WebsiteSecurityAlertModel.objects.create(type="ABNORMAL",
                                                                          events=event_security,
                                                                          host=self.current_host,
                                                                          details=details,
                                                                          description=alert,
                                                                          name=event_security.get_alert_display(),
                                                                          solution=alert)

                # add system alert
                SystemsAlert.objects.create(contents=security_alert)

            elif alert == "DEVICE_CHANGE_IP":
                # check is exits
                if not WebsiteSecurityAlertModel.objects.filter(events=event_security,
                                                                host=self.current_host).count() > 0:
                    details = {
                        "old": HostInfoSerializer(self.last_host).data,
                        "new": HostInfoSerializer(self.current_host).data,
                    }
                    description = _("Ip address of device is changed.")
                    solution = _("Please check network connection if you don't setting dhcp.")
                    security_alert = WebsiteSecurityAlertModel.objects.create(type="ABNORMAL",
                                                                              events=event_security,
                                                                              host=self.current_host,
                                                                              details=details,
                                                                              description=alert,
                                                                              name=event_security.get_alert_display(),
                                                                              solution=alert)

            elif alert == "CANNOT_CONNECT_TO_TARGET":
                # check is exits
                from targets.serializers import TargetDetailsInfoSerializer

                if not WebsiteSecurityAlertModel.objects.filter(events=event_security,
                                                                host=self.current_host).count() > 0:
                    details = TargetDetailsInfoSerializer(self.current_task.target).data
                    description = _("Ip address of device is changed.")
                    solution = _("Please check network connection if you don't setting dhcp.")
                    security_alert = WebsiteSecurityAlertModel.objects.create(type="ABNORMAL",
                                                                              events=event_security,
                                                                              host=self.current_host,
                                                                              details=details,
                                                                              description=alert,
                                                                              name=event_security.get_alert_display(),
                                                                              solution=alert)
                    # add system alert
                    SystemsAlert.objects.create(contents=security_alert)

            elif alert == "NEW_SERVICE":
                details = ServiceSerializer(self.current_service).data
                description = _("New service is open on your device.")
                solution = _("Please check the service of your device is you don't open port.")
                security_alert = WebsiteSecurityAlertModel.objects.create(type="ABNORMAL",
                                                                          events=event_security,
                                                                          host=self.current_host,
                                                                          details=details,
                                                                          description=alert,
                                                                          name=event_security.get_alert_display(),
                                                                          solution=alert)
                # add system alert
                SystemsAlert.objects.create(contents=security_alert)

            elif alert == "SERVICE_CHANGED":
                details = {
                    "old": ServiceSerializer(self.last_service).data,
                    "new": ServiceSerializer(self.current_service).data,
                }
                description = _("A service is change information.")
                solution = _("Please check the service of your device is you don't open port.")
                security_alert = WebsiteSecurityAlertModel.objects.create(type="ABNORMAL",
                                                                          events=event_security,
                                                                          host=self.current_host,
                                                                          details=details,
                                                                          description=alert,
                                                                          name=event_security.get_alert_display(),
                                                                          solution=alert)

            elif alert == "SERVICE_CLOSED":
                details = ServiceSerializer(self.last_service).data
                description = _("A service is closed on your device.")
                solution = _("Please check the service of your device is you don't close port.")
                security_alert = WebsiteSecurityAlertModel.objects.create(type="ABNORMAL",
                                                                          events=event_security,
                                                                          host=self.current_host,
                                                                          details=details,
                                                                          description=alert,
                                                                          name=event_security.get_alert_display(),
                                                                          solution=alert)

            elif alert == "SERVICE_VERSION_TOO_OLD":
                details = ServiceSerializer(self.current_service).data
                description = _("The version of service is too old.")
                solution = _("Please update the last version of software.")
                security_alert = WebsiteSecurityAlertModel.objects.create(type="ABNORMAL",
                                                                          events=event_security,
                                                                          host=self.current_host,
                                                                          details=details,
                                                                          description=alert,
                                                                          name=event_security.get_alert_display(),
                                                                          solution=alert)

                # add system alert
                SystemsAlert.objects.create(contents=security_alert)

            # send email alert

            elif alert == "NEW_VULNERABILITY":
                details = HostVulnerabilityDetailSerializer(self.current_host_vulns).data
                description = _("New high vulnerability is detected.")
                solution = _("Please fix the vulnerability.")
                solution += "\nDetail:\n" + self.current_vuln.solution
                security_alert = WebsiteSecurityAlertModel.objects.create(type="VULNERABILITY",
                                                                          events=event_security,
                                                                          host=self.current_host,
                                                                          details=details,
                                                                          description=self.current_host_vulns.vulnerability.description,
                                                                          name=self.current_host_vulns.name,
                                                                          solution=self.current_host_vulns.vulnerability.solution)

                if severity >= 3:
                    # add system alert
                    SystemsAlert.objects.create(contents=security_alert)

                    # send email alert

            elif alert == "VULNERABILITY_IS_NOT_FIX":
                details = HostVulnerabilityDetailSerializer(self.current_host_vulns).data
                description = _("New high vuln is detected in last scan. This vulnerability isn't fixed.")
                solution = _("Please fix the vulnerability.")
                solution += "\nDetail:\n" + self.current_vuln.solution
                security_alert = WebsiteSecurityAlertModel.objects.create(type="VULNERABILITY",
                                                                          events=event_security,
                                                                          host=self.current_host,
                                                                          details=details,
                                                                          description=alert,
                                                                          name=self.current_host_vulns.name,
                                                                          solution=alert)

                # add system alert
                SystemsAlert.objects.create(contents=security_alert)

            # send email alert

            elif alert == "NEW_PENETRATION":
                details = WebsiteDatabaseSerializer(self.db_attack).data
                description = _("Penetration testing is successful.")
                solution = _("Please fix the vulnerability.")
                security_alert = WebsiteSecurityAlertModel.objects.create(type="PENETRATION",
                                                                          events=event_security,
                                                                          host=self.current_host,
                                                                          details=details,
                                                                          description=alert,
                                                                          name=event_security.get_alert_display(),
                                                                          solution=alert)

                # add system alert
                SystemsAlert.objects.create(contents=security_alert)

            # send email alert

            elif alert == "BKACLIST_DETECTED":
                details = WebsiteBlacklistChecking2DetailsSerializer(self.current_blacklist_object).data
                description = _("Your domain is making blacklist by domain blacklists checker.")
                solution = _(
                    "Please check mail or website content or contact domain blacklists checker with to unblock.")
                security_alert = WebsiteSecurityAlertModel.objects.create(type="BLACKLIST",
                                                                          events=event_security,
                                                                          host=self.current_host,
                                                                          details=details,
                                                                          description=alert,
                                                                          name=event_security.get_alert_display(),
                                                                          solution=alert)

                # add system alert
                SystemsAlert.objects.create(contents=security_alert)

            # send email alert

            elif alert == "MALWARE_DETECTED":
                from agents.crawldata.serializers import CrawlDataSerializer

                details = CrawlDataSerializer(self.current_blacklist_object).data
                description = _("A malware is detect in website link.")
                solution = _("Please check website content source security.")
                security_alert = WebsiteSecurityAlertModel.objects.create(type="MALWARE",
                                                                          events=event_security,
                                                                          host=self.current_host,
                                                                          details=details,
                                                                          description=alert,
                                                                          name=event_security.get_alert_display(),
                                                                          solution=alert)

                # add system alert
                SystemsAlert.objects.create(contents=security_alert)

            # send email alert

            elif alert == "WEBSITE_CONTENT_DETECTED":
                mcontent_status = WebsiteMonitorContentStatusModel.objects.filter(url_monitor=self.url_monitor).last()
                details = WebsiteMonitorContentHistoryInfoSerializer(mcontent_status).data
                description = _("Website content is changed.")
                solution = _("Please check website status if you didn't do this.")
                security_alert = WebsiteSecurityAlertModel.objects.create(type="WEB_DEFACE",
                                                                          events=event_security,
                                                                          host=self.current_host,
                                                                          details=details,
                                                                          description=alert,
                                                                          name=event_security.get_alert_display(),
                                                                          solution=alert)

                # add system alert
                SystemsAlert.objects.create(contents=security_alert)

            elif alert == "SERVER_STATUS":
                details = WebsiteMonitorStatusSerializer(self.realtime_object).data
                security_alert = WebsiteSecurityAlertModel.objects.create(type="SITE_DOWN",
                                                                          events=event_security,
                                                                          host=self.current_host,
                                                                          details=details,
                                                                          description=alert,
                                                                          name=event_security.get_alert_display(),
                                                                          solution=alert)
                # add system alert
                SystemsAlert.objects.create(contents=security_alert)

            # send email alert

            # update statistic
            self.update_statistics()

        else:  # detected > 0 and severity > 0
            print "Detected event or serverity alert is invalid!!!"

    def get_security_event(self, alert, type, severity=4):
        # Get security event
        list_event_security = SecurityEventsModels.objects.filter(alert=alert, type=type, severity=severity)
        if list_event_security.count() == 0:
            event_security = SecurityEventsModels.objects.create(alert=alert, type=type, severity=severity)
            event_security.save()
        else:
            event_security = list_event_security[0]
        return event_security

    def update_statistics(self):
        update_host_statistic(self.current_host)
        update_task_statistic(self.current_task)
        update_target_statistic(self.current_task.target)
        update_office_statistic(self.current_task.target.office)
        update_unit_statistic(self.current_task.target.office.unit)
        update_system_statisticsv2()

    ####################################################################################################################
    ###									   HOST INFO MONITOR													     ###
    ####################################################################################################################
    # detect new host
    def monitor_new_host(self):
        current_ip_address = self.current_host.ip_addr
        mac_addr = self.current_host.details.mac_addr
        hostname = self.current_host.details.hostname
        if mac_addr is not None and mac_addr != "":
            list_hosts = HostsModel.objects.select_related('details').filter(details__mac_addr=mac_addr,
                                                                             task=self.last_task)
            if list_hosts.count() > 0:
                self.last_host = list_hosts[0]
                if self.current_host.ip_addr == self.last_host.ip_addr:
                    return "OLD_DEVICE"
                else:
                    return "DEVICE_CHANGE_IP"
                    # else: Unknown

        elif hostname is not None and hostname != "" and hostname != current_ip_address:
            list_hosts = HostsModel.objects.select_related('details').filter(details__hostname=hostname,
                                                                             task=self.last_task)
            if list_hosts.count() > 0:
                self.last_host = list_hosts[0]
                if self.current_host.ip_addr == self.last_host.ip_addr:
                    return "OLD_DEVICE"
                else:
                    return "DEVICE_CHANGE_IP"
                    # else: Unknown

        elif current_ip_address != "":
            list_hosts = HostsModel.objects.select_related('details').filter(ip_addr=current_ip_address,
                                                                             task=self.last_task)
            if list_hosts.count() > 0:
                self.last_host = list_hosts[0]
                return "OLD_DEVICE"
            else:
                return "NEW_DEVICE"

    def detect_host_off(self, last_host=None):
        if last_host != None:
            current_ip_address = last_host.ip_addr
            mac_addr = last_host.details.mac_addr
            hostname = last_host.details.hostname
            if mac_addr is not None and mac_addr != "":
                list_hosts = HostsModel.objects.select_related('details').filter(details__mac_addr=mac_addr,
                                                                                 task=self.current_task)
                if list_hosts.count() > 0:
                    return False
            if hostname is not None and hostname != "" and hostname != current_ip_address:
                list_hosts = HostsModel.objects.select_related('details').filter(details__hostname=hostname,
                                                                                 task=self.current_task)
                if list_hosts.count() > 0:
                    return False
            if current_ip_address != "":
                list_hosts = HostsModel.objects.filter(ip_addr=current_ip_address, task=self.current_task)
                if list_hosts.count() > 0:
                    return False
            return True

    ####################################################################################################################
    ###									   SERVICE MONITOR													         ###
    ####################################################################################################################
    # service closed
    # service change version
    # service version expried
    def detect_service_change(self):
        service_info = []
        port = self.current_service.port
        if self.last_host != None:
            list_services = HostServicesModel.objects.filter(port=port, host=self.last_host)
            if list_services.count() > 0:
                self.last_service = list_services[0]

                # Detect service change
                if self.current_service.name != "" and self.current_service.name != self.last_service.name:
                    service_info.append("SERVICE_CHANGED")
                elif self.current_service.version != "" and self.current_service.version != self.last_service.version:
                    service_info.append("SERVICE_CHANGED")
                elif self.current_service.protocol != "" and self.current_service.protocol != self.last_service.protocol:
                    service_info.append("SERVICE_CHANGED")

                # Detect service version is old
                last_service_list = SoftwareLastVersionModel.objects.filter(service_name=self.current_service.name)
                if last_service_list.count() > 0:
                    for service in last_service_list:
                        if service.software_name.lower() in self.current_service.version.lower():
                            if service.software_name.version != self.current_service.version:
                                service_info.append("SERVICE_VERSION_TOO_OLD")
                return service_info
            else:
                return ["NEW_SERVICE"]
        else:
            return []

    def detect_service_off(self, last_service=None):
        if self.current_host != None and last_service != None:
            list_services = HostServicesModel.objects.filter(port=last_service.port, host=self.current_host)
            if list_services.count() == 0:
                return True

    ####################################################################################################################
    ###									   VULNERABILITY MONITOR												     ###
    ####################################################################################################################
    def detect_vuln_high_is_not_fix(self):
        if self.monitor_new_host() in ["OLD_DEVICE", "DEVICE_CHANGE_IP"]:
            list_old_host_vulns = HostVulnerabilityModel.objects.select_related('vulnerability').filter(
                name=self.current_host_vulns.name,
                host=self.last_host,
                vulnerability__severity=self.current_vuln.severity)
            if list_old_host_vulns.count() > 0:
                return True
