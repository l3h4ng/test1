import json
import os
import socket
import struct
import subprocess
import time

import fcntl

from sbox4web import settings


class net_ipconfig(object):
    def __init__(self):
        self.list_iface = None
        self.list_iface_all()

    def list_iface_all(self):
        result = os.listdir('/sys/class/net')
        for iface in settings.EXCLUDE_INTERFACE:
            if iface in result:
                result.remove(iface)
        self.list_iface = result
        result = json.dumps(result)
        return json.loads(result)

    def getHwAddr(self, ifname):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        info = fcntl.ioctl(s.fileno(), 0x8927, struct.pack('256s', ifname[:15]))
        return ':'.join(['%02x' % ord(char) for char in info[18:24]])

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

    def get_netmask(self, iface):
        return socket.inet_ntoa(fcntl.ioctl(
            socket.socket(socket.AF_INET,
                          socket.SOCK_DGRAM), 35099, struct.pack('256s', iface)
        )[20:24])

    def get_gateway(sels, iface):
        """Read the default gateway directly from /proc."""
        try:
            command = '''
netstat -rn |awk '{if($1=="0.0.0.0") if($8=="%s") {print $2; exit}}'
            ''' % str(iface)
            print command
            netshcmd = subprocess.Popen(command, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None)
            a = netshcmd.communicate()[0].split("\n")[0]
            print a
            return a if a else "0.0.0.0"
        except:
            return "0.0.0.0"

    def list_ifconfig_detail(self, iface):
        if iface in self.list_iface:
            ip = self.get_ip_address(iface)
            try:
                mac_addr = self.getHwAddr(iface)
            except:
                mac_addr = None
            if ip:
                network = {'interface': iface, 'ip_addr': ip, 'netmask': self.get_netmask(iface),
                           'gateway': self.get_gateway(iface), "mac_addr": mac_addr}
            else:
                network = {'interface': iface, 'ip_addr': None, 'netmask': None,
                           'gateway': None, "mac_addr": mac_addr}
        else:
            data = {
                "status": "error",
                "exception": "Not found network."
            }
            network = data
        result = json.dumps(network)
        return json.loads(result)

    def record_config(sels, addr):
        info = "'use strict';\nvar ip = '{0}';\nvar servicePort = 8442;\nvar CURRENT_LANGUAGE = 'vi';".format(str(addr))
        f = open(settings.PATH_CONFIG, 'w')
        f.write(info)
        return info

    def choose_mode(self, task_info):
        if task_info.interface not in self.list_iface:
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
        self.set_dhcp(interface)
        time.sleep(5)
        data = self.list_ifconfig_detail(str(interface))
        data["test_connection"] = True
        data["static"] = False
        task_info.test_connection = True
        task_info.save()
        return data

    def static(self, task_info):
        interface = task_info.interface
        ip = task_info.ip_addr
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
            self.set_static(iface=interface, address=ip, gateway=gateway, netmask=netmask)
            time.sleep(2)
            data = self.list_ifconfig_detail(str(interface))
            if "ip_addr" in data and data["ip_addr"] == ip:
                data["test_connection"] = True
                task_info.test_connection = True
                task_info.save()
            else:
                data["test_connection"] = False
            data["static"] = True
            return data

    def set_dhcp(self, iface):
        command = "sudo awk -f {0} {1} dev={2} mode=dhcp > inf".format(str(self.get_path()),
                                                                       str(settings.PATH_ETC), str(iface))
        print command
        subprocess.Popen(command, shell=True)
        subprocess.Popen("ls", shell=True)
        time.sleep(1)
        command = "sudo mv inf {0}".format(str(settings.PATH_ETC))
        print command
        subprocess.Popen(command, shell=True)
        subprocess.Popen("ls", shell=True)

    def set_static(self, iface, address, gateway, netmask):
        command = "sudo awk -f {0} {1} dev={2} mode=static address={3} gateway={4} netmask={5} > inf".format(
            str(self.get_path()),
            str(settings.PATH_ETC), str(iface), str(address), str(gateway), str(netmask))
        print command
        subprocess.Popen(command, shell=True)
        subprocess.Popen("ls", shell=True)
        time.sleep(1)
        command = "sudo mv inf {0}".format(str(settings.PATH_ETC))
        print command
        subprocess.Popen(command, shell=True)
        subprocess.Popen("ls", shell=True)

    def get_path(self, path=settings.PATH_CHANGE_IFACE,
                 current_path=os.path.normpath(os.path.join(os.path.realpath(__file__), '../'))):
        # Check directory is exits
        absolute_path = path
        if os.path.abspath(path):
            absolute_path = os.path.join(current_path, path)
        if os.path.isfile(absolute_path):
            if not os.path.exists(os.path.dirname(absolute_path)):
                os.makedirs(os.path.dirname(absolute_path))
        else:
            if not os.path.exists(absolute_path):
                os.makedirs(absolute_path)
        return absolute_path
