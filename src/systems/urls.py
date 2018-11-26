from django.conf.urls import url

from sadmin.plugins.views import PluginLicensesList, PluginLicenseDetails
from systems.views import NetworkConfigView, ProxyView, SMPTView, SystemStatisticNow, SystemStatisticList, \
    SystemsLicenseView, GetSystemsStatus, ListIface, SystemStatisticTopVulnerability, \
    SystemStatisticTopHostsVulnerbility, ShutDown, LoggingAlertList, LoggingSystemList, LoggingAlertDetail, \
    LoggingSystemDetail, VpnNetworkView, NetworkConnectionPingView, WebsiteGoogleHackingDetectListView, \
    WebsiteMonitorStatusListView, WebsitePhishingDomainDetectListView, WebsiteBlacklistCheckingListView, \
    SystemStatisticTopSecurityAlert, LoggingAlertReadDetail, LoggingSystemReadDetail, LoggingSystemReadAllView, \
    LoggingAlertReadAllView

urlpatterns = [
    url(r'^status$', GetSystemsStatus.as_view(), name='systems-status'),

    url(r'^alerts$', LoggingAlertList.as_view(), name='systems-alerts'),
    url(r'^alerts/readall$', LoggingAlertReadAllView.as_view(), name='systems-alerts-readall'),
    url(r'^alerts/(?P<pk>[0-9]+)$', LoggingAlertDetail.as_view(), name='systems-alert details'),
    url(r'^alerts/(?P<pk>[0-9]+)/read$', LoggingAlertReadDetail.as_view(), name='systems-alert read'),

    url(r'^loggings$', LoggingSystemList.as_view(), name='systems-logings'),
    url(r'^loggings/readall$', LoggingSystemReadAllView.as_view(), name='systems-logings-realall'),
    url(r'^loggings/(?P<pk>[0-9]+)$', LoggingSystemDetail.as_view(), name='systems-loging-details'),
    url(r'^loggings/(?P<pk>[0-9]+)/read$', LoggingSystemReadDetail.as_view(), name='systems-loging-read'),

    url(r'^shutdown$', ShutDown.as_view(), name='systems-shutdown'),
    url(r'^networks$', NetworkConfigView.as_view(), name='networks'),
    url(r'^networks/interfaces$', ListIface.as_view(), name='systems-list-interface'),
    url(r'^networks/ping$', NetworkConnectionPingView.as_view(), name='systems-network-ping'),
    url(r'^networks/proxy$', ProxyView.as_view(), name='networks-proxy'),
    url(r'^networks/vpn$', VpnNetworkView.as_view(), name='networks-vpn'),
    url(r'^networks/smtp$', SMPTView.as_view(), name='networks-smtp'),
    url(r'^license$', SystemsLicenseView.as_view(), name='systems-license'),
    url(r'^license/plugins$', PluginLicensesList.as_view(), name='systems-license-plugins-list'),
    url(r'^license/plugins/(?P<pk>[0-9]+)$', PluginLicenseDetails.as_view(), name='systems-license-plugins-detali'),
    url(r'^statistic$', SystemStatisticNow.as_view(), name='systems-statistic'),
    url(r'^statistic/history$', SystemStatisticList.as_view(), name='systems-statistic'),
    url(r'^statistic/topvulns', SystemStatisticTopVulnerability.as_view(), name='systems-top-vulns'),
    url(r'^statistic/topmsecurities', SystemStatisticTopSecurityAlert.as_view(), name='systems-top-msecurity'),
    url(r'^statistic/tophosts', SystemStatisticTopHostsVulnerbility.as_view(), name='systems-top-hosts'),
    url(r'^statistic/topghdb', SystemStatisticTopHostsVulnerbility.as_view(), name='systems-top-hosts'),
    url(r'^statistic/webstatus', WebsiteMonitorStatusListView.as_view(), name='systems-top-mstatus'),
    url(r'^statistic/ghdb', WebsiteGoogleHackingDetectListView.as_view(), name='systems-top-ghdb'),
    url(r'^statistic/phishing', WebsitePhishingDomainDetectListView.as_view(), name='systems-top-phishing'),
    url(r'^statistic/blacklist', WebsiteBlacklistCheckingListView.as_view(), name='systems-top-blacklist'),
]
