# -*- coding: utf-8 -*-
import socket
import subprocess

import time

import struct

__author__ = 'TOANTV'
import json
import os
from rest_framework import settings

class NetworkConfiguration():
    def get_ip_address(self, ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            return socket.inet_ntoa(fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack('256s', ifname[:15])
            )[20:24])
        except:
            return None

    def get_netmask(iface):
        return socket.inet_ntoa(fcntl.ioctl(
            socket.socket(socket.AF_INET,
                          socket.SOCK_DGRAM), 35099, struct.pack('256s', iface)
        )[20:24])

    def get_gateway(self):
        """Read the default gateway directly from /proc."""
        with open("/proc/net/route") as fh:
            for line in fh:
                fields = line.strip().split()
                if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                    continue

                return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16)))

    def list_ifconfig_detail(self, iface):
        interface = os.listdir('/sys/class/net')
        if iface in interface and iface != 'lo' and iface != settings.INTERFACE:
            if self.get_ip_address(iface):
                network = {'interface': iface, 'ip': self.get_ip_address(iface), 'netmask': self.get_netmask(iface),
                           'gateway': self.get_gateway()}
            else:
                network = {'interface': iface, 'ip': None, 'netmask': None,
                           'gateway': None}
        else:
            data = {
                "status": "error",
                "exception": "Not found network."
            }
            network = data
        result = json.dumps(network)
        return json.loads(result)

    def list_iface(self):
        interface = os.listdir('/sys/class/net')
        interface.remove('lo')
        if settings.INTERFACE in interface:
            interface.remove(settings.INTERFACE)
        list_ip = []
        for iface in interface:
            if self.get_ip_address(iface):
                network = {'interface': iface, 'ip': self.get_ip_address(iface), 'netmask': self.get_netmask(iface),
                           'gateway': self.get_gateway()}
            else:
                network = {'interface': iface, 'ip': None, 'netmask': None,
                           'gateway': None}
            list_ip.append(network)
        return json.loads(json.dumps(list_ip))

    def list_iface_all(self):
        result = os.listdir('/sys/class/net')
        iface = settings.INTERFACE
        if iface in result:
            result.remove(iface)
        result.remove('lo')
        result = json.dumps(result)
        return json.loads(result)

    # print list_iface()

    def choose_mode(self, task_info):
        if task_info.interface == settings.INTERFACE:
            data = {
                "status": "error",
                "exception": "Interface is forbidden."
            }
            return data
        if not task_info.static:
            return self.dhcp(task_info)
        else:
            return self.static(task_info)

    def dhcp(self, task_info):
        interface = task_info.interface
        print(interface)
        # subprocess.Popen(['ifconfig', interface], stdout=subprocess.PIPE).communicate()[0]
        command = "sudo ip link set dev " + interface + " down"
        print(command)
        subprocess.Popen(command, shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)
        command = "sudo dhclient " + interface
        print(command)
        subprocess.Popen(command, shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)
        time.sleep(2)
        return self.list_ifconfig_detail(str(interface))

    def static(self, task_info):
        interface = task_info.interface
        ip = task_info.ip
        netmask = task_info.netmask
        gateway = task_info.gateway

        if (not ip) or (not netmask) or (not gateway):
            err = {"ERROR": "IP, SubnetMask or Gateway must not NULL!"}
            result = json.dumps(err)
            return json.loads(result)
        else:

            command = "sudo ifconfig " + interface + " " + ip + " netmask " + netmask
            print(command)
            subprocess.Popen(command, shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)
            #   time.sleep(10)
            # sudo route add default gw 192.168.0.1 ens33
            command = "sudo route add default gw " + gateway + " " + interface
            print (command)
            subprocess.Popen(command, shell=True, stdin=None, stdout=None, stderr=None, close_fds=True)
            # print list_ifconfig(str(interface))
            time.sleep(2)
            return self.list_ifconfig_detail(str(interface))
