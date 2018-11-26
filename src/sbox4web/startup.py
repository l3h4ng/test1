# -*- coding: utf-8 -*-
__author__ = 'TOANTV'
from sys import platform

from django.conf import settings
from systems.models import SystemsNetworkConfig
from systems.serializers import NetworkConfigSerializer

if platform == "win32":
    from systems.network_config_win import net_ipconfig
else:
    from systems.network_config import net_ipconfig


def update_ip_addr_currents():
    print "Update ip address interfaces."
    network_manager = net_ipconfig()
    list_interface_current = network_manager.list_iface_all()
    list_interface_current = list(set(list_interface_current) - set(settings.EXCLUDE_INTERFACE))
    interface_objects = SystemsNetworkConfig.objects.all().values('interface')
    list_interface_saved = [inf['interface'] for inf in interface_objects]

    list_interface_delete = list(set(list_interface_saved) - set(list_interface_current))
    list_interface_new = list(set(list_interface_current) - set(list_interface_saved))
    list_interface_change = list(set(list_interface_current) - set(list_interface_new))

    for interface in list_interface_delete:
        instance = SystemsNetworkConfig.objects.get(interface=interface)
        instance.delete()
        print "Delete interface {}".format(str(interface))
    for interface in list_interface_new:
        ip_info = network_manager.list_ifconfig_detail(interface)
        if interface in settings.ADMIN_INTERFACE:
            ip_info["type"] = 1

        print "Add new interface {} info: {}".format(str(interface), str(ip_info))
        SystemsNetworkConfig.objects.create(**ip_info)

    for interface in list_interface_change:
        ip_info = network_manager.list_ifconfig_detail(interface)
        if interface in settings.ADMIN_INTERFACE:
            ip_info["type"] = 1
        print "Update interface {} info: {}".format(str(interface), str(ip_info))
        instance = SystemsNetworkConfig.objects.get(interface=interface)
        serializer = NetworkConfigSerializer(instance, data=ip_info, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

