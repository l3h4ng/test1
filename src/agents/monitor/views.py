# -*- coding: utf-8 -*-
from agents.hosts.models import HostsModel
from agents.monitor.models import GoogleHackingKeywordModels, WebsiteMonitorStatusModel, WebsiteMonitorUrl, \
    WebsiteMonitorContentStatusModel, WebsiteSecurityAlertModel, WebsiteBlacklistCheckingModel, \
    WebsiteGoogleHackingDetectModel, WebsitePhishingDomainDetectModel, WebsiteContentModel, SecurityEventsModels, \
    SoftwareLastVersionModel, TargetTechnologyVersionModel, WebsiteMonitorContentChangeModel
from agents.monitor.sbox_monitor import SboxSecurityMonitor
from agents.monitor.serializers import GoogleHackingKeywordSerializer, WebsiteMonitorStatusSerializer, \
    WebsiteMonitorUrlSerializer, WebsiteMonitorContentSerializer, \
    WebsiteMonitorContentDetailsSerializer, WebsiteSecurityAlertSerializer, WebsiteSecurityAlertDetailsSerializer, \
    WebsiteBlacklistCheckingSerializer, WebsiteGoogleHackingDetectSerializer, WebsitePhishingDomainDetectSerializer, \
    WebsiteGoogleHackingDetectDetailsSerializer, WebsiteContentSerializer, SecurityEventsSerializer, \
    SoftwareLastVersionSerializer, TargetTechnologyVersionSerializer, TargetTechnologyVersionDetailsSerializer, \
    WebsiteMonitorContentHistorySerializer, WebsiteMonitorContentChangeSerializer, \
    WebsiteMonitorContentChangeDetailsSerializer, WebsiteMonitorContentHistoryInfoSerializer, \
    WebsiteSecurityAlertDetailsSerializer2
from django.db.models import Q
from django_filters.rest_framework import DjangoFilterBackend
from sbox4web.libs import update_task_statistic, update_system_statisticsv2, update_host_task_system_statistic
from sbox4web.libs import update_target_statistic
from sbox4web.libs import update_office_statistic
from sbox4web.libs import update_unit_statistic
from sbox4web.views import JSONResponse
from rest_framework import status
from systems.models import SystemStatistics
from targets.models import TasksModel

__author__ = 'TOANTV'
from rest_framework import generics
from rest_framework import filters
from rest_framework.renderers import JSONRenderer

from one_auth.authentication import OneTokenAuthentication
from one_users.permissions import IsOneUserAuthenticatedReadOnlyOrScanner, IsOneUserAuthenticatedReadOnlyOrAdmin

########################################################################################################################
#####                                            GOOGLE HACKING DB                                                 #####
########################################################################################################################
# /agents/ghdb
class GoogleHackingKeywordListView(generics.ListCreateAPIView):
    queryset = GoogleHackingKeywordModels.objects.all().order_by('-id')
    serializer_class = GoogleHackingKeywordSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('category', 'google_search',)
    search_fields = ('category', 'google_search',)


# /agents/ghdb/pk/
class GoogleHackingKeywordView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = GoogleHackingKeywordSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        queryset = GoogleHackingKeywordModels.objects.filter(pk=pk)
        return queryset


# /agents/ghdbdetect
class WebsiteGoogleHackingDetectListView(generics.ListCreateAPIView):
    queryset = WebsiteGoogleHackingDetectModel.objects.all().order_by('-id')
    serializer_class = WebsiteGoogleHackingDetectSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('website', 'keyword',)
    search_fields = ('link')

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = WebsiteGoogleHackingDetectDetailsSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = WebsiteGoogleHackingDetectDetailsSerializer(queryset, many=True)
        return JSONResponse(serializer.data, status=status.HTTP_200_OK)


# /agents/ghdbdetect/pk/
class WebsiteGoogleHackingDetectView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = WebsiteGoogleHackingDetectDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        queryset = WebsiteGoogleHackingDetectModel.objects.filter(pk=pk)
        return queryset

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', True)
        instance = self.get_object()
        serializer = WebsiteGoogleHackingDetectSerializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        return JSONResponse(WebsiteGoogleHackingDetectDetailsSerializer(instance).data, status=status.HTTP_200_OK)


########################################################################################################################
#####                                            PHISHING DOMAIN WARNING                                           #####
########################################################################################################################
# /agents/phishingchecking
class WebsitePhishingDomainDetectListView(generics.ListCreateAPIView):
    queryset = WebsitePhishingDomainDetectModel.objects.all().order_by('-id')
    serializer_class = WebsitePhishingDomainDetectSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('website', 'domain', 'is_exits', 'ip_addr', 'security_level',)
    search_fields = ('domain', 'ip_addr',)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()

        # Update host and task statistic
        instance.website.statistics.phishing_domain_count = WebsitePhishingDomainDetectModel.objects.filter(
            website=instance.website).count()
        instance.website.statistics.save()

        instance.website.task.statistics.phishing_domain_count = WebsitePhishingDomainDetectModel.objects.select_related(
            "website__task").filter(website__task=instance.website.task).exclude(security_level=0).count()
        instance.website.task.statistics.save()
        return JSONResponse(serializer.data, status=status.HTTP_201_CREATED)


# /agents/phishingchecking/pk/
class WebsitePhishingDomainDetectView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = WebsitePhishingDomainDetectSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        queryset = WebsitePhishingDomainDetectModel.objects.filter(pk=pk)
        return queryset

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()

        # Update task phishing_domain_count
        instance.website.task.statistics.phishing_domain_count = WebsitePhishingDomainDetectModel.objects.select_related(
            "website__task").filter(website__task=instance.website.task).exclude(security_level=0).count()
        instance.website.task.statistics.save()
        return JSONResponse(serializer.data)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()

        # Update host and task statistic
        if instance.website.statistics.phishing_domain_count > 1:
            instance.website.statistics.WebsitePhishingDomainDetectModel.objects.filter(
                website=instance.website).count()
            instance.website.statistics.save()

        if instance.website.task.statistics.phishing_domain_count > 1:
            instance.website.task.statistics.phishing_domain_count = WebsitePhishingDomainDetectModel.objects.select_related(
                "website__task").filter(task=instance.website.task).exclude(security_level=0).count()
            instance.website.task.statistics.save()

        instance.delete()
        return JSONResponse(status=status.HTTP_204_NO_CONTENT)


########################################################################################################################
#####                                            BLACKLIST WARNING                                                 #####
########################################################################################################################
# /agents/bchecking
class WebsiteBlacklistCheckingListView(generics.ListCreateAPIView):
    queryset = WebsiteBlacklistCheckingModel.objects.all().order_by('-id')
    serializer_class = WebsiteBlacklistCheckingSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('website', 'type', 'result',)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()

        # Update statistic
        if instance.result == 1:
            instance.website.severity = 3
            instance.website.save()

            # host_statistic = instance.website.statistics
            # host_statistic.is_blacklist_detected = True
            # host_statistic.save()
            #
            # instance.website.task.statistics.domain_blacklist_alert_count += 1
            # instance.website.task.statistics.severity = 3
            # instance.website.task.statistics.save()

            # malware monitor alert
            SboxSecurityMonitor("BLACKLIST").monitor(instance)
        return JSONResponse(serializer.data, status=status.HTTP_201_CREATED)


# /agents/bchecking/pk/
class WebsiteBlacklistCheckingView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = WebsiteBlacklistCheckingSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        queryset = WebsiteBlacklistCheckingModel.objects.filter(pk=pk)
        return queryset

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()

        # Update host and task statistic
        count = WebsiteBlacklistCheckingModel.objects.filter(website=instance.website, result=1).count()
        if count > 0:
            instance.website.statistics.is_blacklist_detected = True
            instance.website.statistics.save()
        else:
            instance.website.statistics.is_blacklist_detected = False
            instance.website.statistics.save()

        if instance.website.task.statistics.is_blacklist_detected > 1:
            instance.website.task.statistics.is_blacklist_detected = WebsiteBlacklistCheckingModel.objects.filter(
                website__task=instance.website.task, result=1).count()
            instance.website.task.statistics.save()

        instance.delete()
        return JSONResponse(status=status.HTTP_204_NO_CONTENT)


########################################################################################################################
#####                                            MONITOR STATUS                                                    #####
########################################################################################################################
# /agents/mstatus
class WebsiteMonitorStatusListView(generics.ListCreateAPIView):
    queryset = WebsiteMonitorStatusModel.objects.all().order_by('-id')
    serializer_class = WebsiteMonitorStatusSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('website', 'monitor_time',)
    search_fields = ('website',)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        if instance.web_status >= 400:
            instance.website.statistics.is_site_down = True
            instance.website.statistics.save()
            SboxSecurityMonitor("SITE_DOWN").monitor(instance)
        else:
            instance.website.statistics.is_site_down = False
            instance.website.statistics.save()
            update_host_task_system_statistic(instance.website)
        return JSONResponse(serializer.data, status=status.HTTP_201_CREATED)

# /agents/mstatus/pk/
class WebsiteMonitorStatusDetailsView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = WebsiteMonitorStatusSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        queryset = WebsiteMonitorStatusModel.objects.filter(pk=pk)
        return queryset


########################################################################################################################
#####                                            MONITOR CONTENTS                                                  #####
########################################################################################################################
# /agents/urlmonitor
class WebsiteMonitorUrlListView(generics.ListCreateAPIView):
    queryset = WebsiteMonitorUrl.objects.all().order_by('-id')
    serializer_class = WebsiteMonitorUrlSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('target', 'url', 'path', 'is_enabled', 'max_level',)
    search_fields = ('target', 'url', 'path',)


# /agents/urlmonitor/pk/
class WebsiteMonitorUrlDetailsView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = WebsiteMonitorUrlSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        self.kwargs["partial"] = True
        queryset = WebsiteMonitorUrl.objects.filter(pk=pk)
        return queryset


########################################################################################################################
#####                                            MONITOR CONTENTS                                                  #####
########################################################################################################################
# /agents/mcstatus
class WebsiteContentMonitorStatusListView(generics.ListCreateAPIView):
    queryset = WebsiteMonitorContentStatusModel.objects.all().order_by('-id')
    serializer_class = WebsiteMonitorContentHistorySerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('target', 'url', 'path', 'is_enabled', 'max_level',)
    search_fields = ('target', 'url', 'path',)

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = WebsiteMonitorContentHistoryInfoSerializer(queryset, many=True)
        return JSONResponse(serializer.data)


# /agents/mcstatus/pk/
class WebsiteContentMonitorStatusDetailsView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = WebsiteMonitorContentHistorySerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        self.kwargs["partial"] = True
        queryset = WebsiteMonitorContentStatusModel.objects.filter(pk=pk)
        return queryset

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()

        if instance.is_changed == True:
            # website content change monitor alert
            lists_host = HostsModel.objects.prefetch_related('task', 'task__target').filter(
                task__id=instance.url_monitor.target.last_task_id, ip_addr=instance.url)
            if lists_host.count() > 0:
                host = lists_host[0]
                host.statistics.is_website_content_alert = True
            SboxSecurityMonitor("WEB_DEFACE").monitor(instance.url_monitor)
        else:
            lists_host = HostsModel.objects.prefetch_related('task', 'task__target').filter(
                task__id=instance.url_monitor.target.last_task_id, ip_addr=instance.url)
            if lists_host.count() > 0:
                host = lists_host[0]
                host.statistics.is_website_content_alert = False
        return JSONResponse(serializer.data, status=status.HTTP_200_OK)

########################################################################################################################
#####                                            MONITOR CONTENTS COMPARE                                           #####
########################################################################################################################
# /agents/mcstatus
class WebsiteMonitorContentChangeListView(generics.ListCreateAPIView):
    queryset = WebsiteMonitorContentChangeModel.objects.all().order_by('-id')
    serializer_class = WebsiteMonitorContentChangeSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('target', 'url', 'path', 'is_enabled', 'max_level',)
    search_fields = ('target', 'url', 'path',)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        return JSONResponse(WebsiteMonitorContentChangeDetailsSerializer(instance).data, status=status.HTTP_201_CREATED)


# /agents/mcstatus/pk/
class WebsiteMonitorContentChangeDetailsView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = WebsiteMonitorContentChangeDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        self.kwargs["partial"] = True
        queryset = WebsiteMonitorContentChangeModel.objects.filter(pk=pk)
        return queryset


# # /agents/contents
# class WebsiteContentListView(generics.ListCreateAPIView):
#     queryset = WebsiteContentModel.objects.all().order_by('-id')
#     serializer_class = WebsiteContentSerializer
#     authentication_classes = (OneTokenAuthentication,)
#     permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
#     renderer_classes = (JSONRenderer,)
#     filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
#     filter_fields = ('url_monitor', 'tag', 'parent', 'level',)
#     search_fields = ('url_monitor', 'tag', 'parent',)
#
#
# # /agents/contents/pk/
# class WebsiteContentDetailsView(generics.RetrieveUpdateDestroyAPIView):
#     serializer_class = WebsiteContentSerializer
#     authentication_classes = (OneTokenAuthentication,)
#     permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
#     renderer_classes = (JSONRenderer,)
#
#     def get_queryset(self):
#         pk = self.kwargs['pk']
#         queryset = WebsiteContentModel.objects.filter(pk=pk)
#         return queryset

# /agents/contents
class WebsiteContentListView(generics.ListCreateAPIView):
    queryset = WebsiteContentModel.objects.all().order_by('-id')
    serializer_class = WebsiteContentSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('url_monitor', 'monitor_time', 'crawler_count',)
    search_fields = ('url_monitor', 'content',)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()
        return JSONResponse(serializer.data, status=status.HTTP_201_CREATED)


# /agents/contents/pk/
class WebsiteContentDetailsView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = WebsiteContentSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        queryset = WebsiteContentModel.objects.filter(pk=pk)
        return queryset


# /agents/urlmonitors/url_id/lastcontents
class WebsiteLastContentDetailsView(generics.RetrieveAPIView):
    queryset = WebsiteContentModel.objects.all()
    serializer_class = WebsiteContentSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    # def get_queryset(self):
    #     pk = self.kwargs['pk']
    #     queryset = WebsiteContentModel.objects.filter(url_monitor__id=pk).order_by('-monitor_time')
    #     self.kwargs['pk'] = queryset.first().id
    #     return queryset

    def get_object(self, *args, **kwargs):
        return self.queryset.filter(url_monitor__id=self.kwargs.get('pk')).latest('monitor_time')

        # def retrieve(self, request, *args, **kwargs):
        #     instance = self.get_object()
        #     serializer = self.get_serializer(instance)
        #     return JSONResponse(serializer.data, status=status.HTTP_200_OK)


# /agents/mcstatus
class WebsiteMonitorContentListView(generics.ListCreateAPIView):
    queryset = WebsiteMonitorContentStatusModel.objects.all().order_by('-id')
    serializer_class = WebsiteMonitorContentSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('url_monitor',)
    search_fields = ('url_monitor',)

    def get_queryset(self):
        queryset = WebsiteMonitorContentStatusModel.objects.all().order_by('-id')
        queryset = queryset.prefetch_related('old_content', 'new_content')
        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = WebsiteMonitorContentDetailsSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = WebsiteMonitorContentDetailsSerializer(queryset, many=True)
        return JSONResponse(serializer.data, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        data = request.data
        if 'old_contents' in data and isinstance(data["old_contents"], list):
            if len(data["old_contents"]) > 0:
                data["is_changed"] = True
        if 'new_contents' in data and isinstance(data["new_contents"], list):
            if len(data["new_contents"]) > 0:
                data["is_changed"] = True
        serializer = self.get_serializer(data=data)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()

        host = HostsModel.objects.prefetch_related('task', 'task__target').filter(
            task__id=instance.url_monitor.target.last_task_id,
            ip_addr=instance.url_monitor.url)
        if host.count() > 0:
            host = host[0]
            host.statistics.is_website_content_alert = instance.is_changed
            host.statistics.save()
            host.task.statistics.website_content_alert_count = HostsModel.objects.prefetch_related('task',
                                                                                                   'statistics').filter(
                task=host.task, statistics__is_website_content_alert=True).count()
            host.task.statistics.save()
        return JSONResponse(serializer.data, status=status.HTTP_201_CREATED)


# /agents/mcstatus/pk
class WebsiteMonitorContentDetailsView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = WebsiteMonitorContentDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        queryset = WebsiteMonitorContentStatusModel.objects.filter(pk=pk)
        return queryset

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', True)
        instance = self.get_object()
        serializer = WebsiteMonitorContentSerializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        instance = serializer.save()

        # Update host is_website_content_alert
        host = HostsModel.objects.prefetch_related('task', 'task__target').filter(
            task__id=instance.url_monitor.target.last_task_id,
            ip_addr=instance.url_monitor.url)
        if host.count() > 0:
            host = host[0]
            host.statistics.is_website_content_alert = instance.is_changed
            host.statistics.save()
            if instance.is_changed:
                SboxSecurityMonitor("WEB_DEFACE").monitor(instance.url_monitor)
            else:
                host.statistics.is_website_content_alert = False
                host.statistics.save()
                update_host_task_system_statistic(host)
            #     host.severity = 3
            #     host.statistics.is_website_content_alert = True
            #
            # host.save()
            # host.task.statistics.website_content_alert_count = HostsModel.objects.prefetch_related('task',
            #                                                                                        'statistics').filter(
            #     task=host.task, statistics__is_website_content_alert=True).count()
            # if host.task.statistics.website_content_alert_count > 0:
            #     host.task.severity = 3
            #     host.task.save()
            #     host.task.statistics.severity = 3
            #     host.task.statistics.save()
            #     if TasksModel.objects.filter(target=host.task.target).count() == 1:
            #         host.task.target.severity = 3
            #         host.task.target.save()

        return JSONResponse(WebsiteMonitorContentDetailsSerializer(instance).data, status=status.HTTP_200_OK)


########################################################################################################################
#####                                            SECURITY EVENTS                                                   #####
########################################################################################################################
# /sevents
class SecurityEventsListView(generics.ListCreateAPIView):
    queryset = SecurityEventsModels.objects.all().order_by('-id')
    serializer_class = SecurityEventsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrAdmin,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('type', 'alert', 'severity')
    search_fields = ('type',)


# /sevents/pk/
class SecurityEventsDetailsView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = SecurityEventsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrAdmin,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        queryset = SecurityEventsModels.objects.filter(pk=pk)
        return queryset


########################################################################################################################
#####                                            SOFTWARE LAST VERSION                                             #####
########################################################################################################################
# /technology/lasted
class SoftwareLastVersionListView(generics.ListCreateAPIView):
    queryset = SoftwareLastVersionModel.objects.all().order_by('-id')
    serializer_class = SoftwareLastVersionSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrAdmin,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('service_name', 'software_name')
    search_fields = ('service_name', 'software_name')


# /technology/lasted/pk/
class SoftwareLastVersionDetailsView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = SoftwareLastVersionSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrAdmin,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        queryset = SoftwareLastVersionModel.objects.filter(pk=pk)
        return queryset


########################################################################################################################
#####                                            TARGET SOFTWARE VERSION                                           #####
########################################################################################################################
# /sevents
class TargetTechnologyVersionListView(generics.ListCreateAPIView):
    queryset = TargetTechnologyVersionModel.objects.all().order_by('-id')
    serializer_class = TargetTechnologyVersionSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrAdmin,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('service_name', 'software_name', 'target', 'host')
    search_fields = ('service_name', 'software_name', 'host')

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = TargetTechnologyVersionDetailsSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = TargetTechnologyVersionDetailsSerializer(queryset, many=True)
        return JSONResponse(serializer.data, status=status.HTTP_200_OK)


# /sevents/pk/
class TargetTechnologyVersionView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = TargetTechnologyVersionDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrAdmin,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        queryset = TargetTechnologyVersionModel.objects.filter(pk=pk)
        return queryset

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', True)
        instance = self.get_object()
        serializer = TargetTechnologyVersionSerializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        security_alert = serializer.save()
        return JSONResponse(TargetTechnologyVersionDetailsSerializer(security_alert).data, status=status.HTTP_200_OK)


########################################################################################################################
#####                                            WEBSITE SECURITY ALERT                                            #####
########################################################################################################################
# /agents/msecurity
class WebsiteSecurityAlertListView(generics.ListCreateAPIView):
    serializer_class = WebsiteSecurityAlertSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('host', 'events', 'resolve', 'type',)
    search_fields = ('host',)

    def get_queryset(self):
        queryset = WebsiteSecurityAlertModel.objects.all().order_by('-id')
        queryset = queryset.select_related('host', 'events', 'host__task', 'host__task__target',
                                           'host__task__target__office', 'host__task__target__office__unit')

        # severity search
        severity_search = self.request.GET.get('severity', None)
        if severity_search is not None and severity_search!='':
            list_severities = severity_search.split(',')
            queryset = queryset.filter(events__severity__in=list_severities)

        # # type search
        # type_search = self.request.GET.get('type', None)
        # if type_search is not None:
        #     queryset = queryset.filter(events__type=type_search)

        # alert search
        alert_search = self.request.GET.get('alert', None)
        if alert_search is not None and alert_search != '':
            queryset = queryset.filter(events__alert=alert_search)

        # unit search
        unit_search = self.request.GET.get('unit', None)
        if unit_search is not None and unit_search != '':
            queryset = queryset.filter(host__task__target__office__unit=unit_search)

        # office search
        office_search = self.request.GET.get('office', None)
        if office_search is not None and office_search != '':
            queryset = queryset.filter(host__task__target__office=office_search)

        # target search
        target_search = self.request.GET.get('target', None)
        if target_search is not None and target_search != '':
            queryset = queryset.filter(host__task__target=target_search)

        # order_by search
        filter_search = self.request.GET.get('order', None)
        if filter_search is not None and filter_search != '':
            if filter_search == "host":
                queryset = queryset.order_by('host',
                                             '-events__severity')
            elif filter_search == "-severity":
                queryset = queryset.order_by('-events__severity',
                                             'host')
            else:
                queryset = queryset.order_by('host',
                                             '-events__severity',
                                             'events')

        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = WebsiteSecurityAlertDetailsSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = WebsiteSecurityAlertDetailsSerializer2(queryset, many=True)
        return JSONResponse(serializer.data, status=status.HTTP_200_OK)



# /agents/msecurity/pk
class WebsiteSecurityAlertDetailsView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = WebsiteSecurityAlertDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        queryset = WebsiteSecurityAlertModel.objects.filter(pk=pk)
        return queryset

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', True)
        instance = self.get_object()
        serializer = WebsiteSecurityAlertSerializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        security_alert = serializer.save()
        return JSONResponse(WebsiteSecurityAlertDetailsSerializer(security_alert).data, status=status.HTTP_200_OK)


# /msecurity
class WebsiteSecurityAlertLastedListView(generics.ListCreateAPIView):
    serializer_class = WebsiteSecurityAlertSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    # filter_fields = ('type', 'host', 'events', 'resolve',)
    # search_fields = ('host',)

    def get_queryset(self):
        queryset = WebsiteSecurityAlertModel.objects.all()
        queryset = queryset.prefetch_related('host', 'host__task', 'host__task__target', 'host__task__target__office',
                                             'host__task__target__office__unit')
        queryset = queryset.filter(host__task__is_lasted=True)

        time_search = self.request.GET.get('time', None)
        if time_search is not None and time_search != '':
            try:
                system_statistic = SystemStatistics.objects.get(pk=time_search)
                queryset = queryset.filter(host__task__in=system_statistic.tasks)
            except SystemStatistics.DoesNotExist:
                queryset = queryset.filter(host__task__is_lasted=True)
        else:
            queryset = queryset.filter(host__task__is_lasted=True)

        # time_created search
        time_search = False
        timelte_search = self.request.GET.get('timelte', None)
        if timelte_search is not None and timelte_search != '':
            queryset = queryset.filter(time_created__lte=timelte_search)

        timegte_search = self.request.GET.get('timegte', None)
        if timegte_search is not None and timegte_search != '':
            queryset = queryset.filter(time_created__gte=timegte_search)

        # severity search
        severity_search = self.request.GET.get('severity', None)
        if severity_search is not None and severity_search != '':
            list_severities = severity_search.split(',')
            queryset = queryset.filter(events__severity__in=list_severities)

        # # type search
        # type_search = self.request.GET.get('type', None)
        # if type_search is not None:
        #     queryset = queryset.filter(events__type=type_search)

        # type search
        type_search = self.request.GET.get('type', None)
        if type_search is not None and type_search != '':
            if type_search == "WEB_DEFACE":
                all_mscurities = queryset.filter(type=type_search, host__statistics__is_website_content_alert=True).order_by("-id")
                hosts = []
                list_msecurity = []
                for mscurity in all_mscurities.all():
                    if mscurity.host not in hosts:
                        hosts.append(mscurity.host)
                        list_msecurity.append(mscurity.id)
                queryset = queryset.filter(pk__in=list_msecurity)
            elif type_search == "SITE_DOWN":
                all_mscurities = queryset.filter(type=type_search, host__statistics__is_site_down=True).order_by("-id")
                hosts = []
                list_msecurity = []
                for mscurity in all_mscurities.all():
                    if mscurity.host not in hosts:
                        hosts.append(mscurity.host)
                        list_msecurity.append(mscurity.id)
                queryset = queryset.filter(pk__in=list_msecurity)
            else:
                 queryset = queryset.filter(type=type_search)

        # host search
        host_search = self.request.GET.get('host', None)
        if host_search is not None and host_search != '':
            queryset = queryset.filter(host=host_search)

        # events search
        events_search = self.request.GET.get('events', None)
        if events_search is not None and events_search != '':
            queryset = queryset.filter(events=events_search)

        # resolve search
        resolve_search = self.request.GET.get('resolve', None)
        if resolve_search is not None and resolve_search != '':
            queryset = queryset.filter(resolve=resolve_search)

        # unit search
        unit_search = self.request.GET.get('unit', None)
        if unit_search is not None and unit_search != '':
            queryset = queryset.filter(host__task__target__office__unit=unit_search)

        # office search
        office_search = self.request.GET.get('office', None)
        if office_search is not None and office_search != '':
            queryset = queryset.filter(host__task__target__office=office_search)

        # target search
        target_search = self.request.GET.get('target', None)
        if target_search is not None and target_search != '':
            queryset = queryset.filter(host__task__target=target_search)

        # search field
        search_query = self.request.GET.get('search', None)
        if search_query is not None and search_query != "":
            queryset = queryset.select_related('host', 'host__details', 'host__task__target')
            # queryset = queryset.prefetch_related('vulns', 'services', 'vulns__vulnerability', 'sessions', 'msecurity')
            # queryset = queryset.filter(
            #     Q(ip_addr__contains=search_query))
            list_search = search_query.split(',')
            query = Q()
            for seach in list_search:
                query_tem = Q(host__ip_addr__icontains=seach) | Q(
                    name__icontains=seach) | Q(description__contains=seach) | Q(solution__contains=seach) | Q(
                    host__details__mac_addr__icontains=seach) | Q(host__details__hostname__icontains=seach) | Q(
                    host__task__target__name__icontains=seach)
                query = query & query_tem
            queryset = queryset.filter(query)

        # order_by search
        filter_search = self.request.GET.get('order', None)
        if filter_search is not None and filter_search != '':
            if filter_search == "ip_addr":
                queryset = queryset.order_by('host__ip_addr',
                                             '-events__severity')
            elif filter_search == "mac":
                queryset = queryset.order_by('host__details__mac_addr',
                                             '-time_created')
            elif filter_search == "severity":
                queryset = queryset.order_by('events__severity',
                                             '-time_created')
            elif filter_search == "-severity":
                queryset = queryset.order_by('-events__severity',
                                             '-time_created')
            elif filter_search == "time":
                queryset = queryset.order_by('time_created',
                                             '-events__severity')
            elif filter_search == "-time":
                queryset = queryset.order_by('-time_created',
                                             '-events__severity')
            else:
                queryset = queryset.order_by('-events__severity',
                                         '-id')
        else:
            queryset = queryset.order_by('-events__severity',
                                         '-id')

        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = WebsiteSecurityAlertDetailsSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = WebsiteSecurityAlertDetailsSerializer(queryset, many=True)
        return JSONResponse(serializer.data, status=status.HTTP_200_OK)

########################################################################################################################
#####                                            ABNORMAL EVENTS                                                   #####
########################################################################################################################
# /agents/msecurity
class WebsiteAbnormalEventsListView(generics.ListCreateAPIView):
    serializer_class = WebsiteSecurityAlertSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)
    filter_backends = (filters.SearchFilter, DjangoFilterBackend,)
    filter_fields = ('host', 'events', 'resolve',)
    search_fields = ('host',)

    def get_queryset(self):
        queryset = WebsiteSecurityAlertModel.objects.all().order_by('-id')
        queryset = queryset.select_related('host', 'events', 'host__task', 'host__task__target',
                                           'host__task__target__office', 'host__task__target__office__unit')

        # severity search
        severity_search = self.request.GET.get('severity', None)
        if severity_search is not None and severity_search!='':
            list_severities = severity_search.split(',')
            queryset = queryset.filter(events__severity__in=list_severities)

        # # type search
        # type_search = self.request.GET.get('type', None)
        # if type_search is not None:
        #     queryset = queryset.filter(events__type=type_search)

        # alert search
        alert_search = self.request.GET.get('alert', None)
        if alert_search is not None and alert_search != '':
            queryset = queryset.filter(events__alert=alert_search)

        # unit search
        unit_search = self.request.GET.get('unit', None)
        if unit_search is not None and unit_search != '':
            queryset = queryset.filter(host__task__target__office__unit=unit_search)

        # office search
        office_search = self.request.GET.get('office', None)
        if office_search is not None and office_search != '':
            queryset = queryset.filter(host__task__target__office=office_search)

        # target search
        target_search = self.request.GET.get('target', None)
        if target_search is not None and target_search != '':
            queryset = queryset.filter(host__task__target=target_search)

        # order_by search
        filter_search = self.request.GET.get('filter', None)
        if filter_search is not None and filter_search != '':
            if filter_search == "host":
                queryset = queryset.order_by('host',
                                             '-events__severity')
            elif filter_search == "severity":
                queryset = queryset.order_by('-events__severity',
                                             'host')
            else:
                queryset = queryset.order_by('host',
                                             '-events__severity',
                                             'events')

        return queryset

    def list(self, request, *args, **kwargs):
        queryset = self.filter_queryset(self.get_queryset())

        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = WebsiteSecurityAlertDetailsSerializer(page, many=True)
            return self.get_paginated_response(serializer.data)

        serializer = WebsiteSecurityAlertDetailsSerializer(queryset, many=True)
        return JSONResponse(serializer.data, status=status.HTTP_200_OK)


# /agents/msecurity/pk
class WebsiteAbnormalEventsDetailsView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = WebsiteSecurityAlertDetailsSerializer
    authentication_classes = (OneTokenAuthentication,)
    permission_classes = (IsOneUserAuthenticatedReadOnlyOrScanner,)
    renderer_classes = (JSONRenderer,)

    def get_queryset(self):
        pk = self.kwargs['pk']
        queryset = WebsiteSecurityAlertModel.objects.filter(pk=pk)
        return queryset

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', True)
        instance = self.get_object()
        serializer = WebsiteSecurityAlertSerializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        security_alert = serializer.save()
        return JSONResponse(WebsiteSecurityAlertDetailsSerializer(security_alert).data, status=status.HTTP_200_OK)