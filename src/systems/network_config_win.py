import json
import subprocess
import time

from sbox4web import settings


class net_ipconfig(object):
    def __init__(self):
        self.list_iface = None
        self.list_iface_all()

    def list_iface_all(self):
        list_iface = []
        command = "netsh interface ip show config"
        netshcmd = subprocess.Popen(command, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None)
        output = str(netshcmd.communicate()).split('Configuration for interface "')
        for split in output:
            if '"' in split:
                iface = split.split('"')[0]
                if iface not in settings.EXCLUDE_INTERFACE:
                    list_iface.append(split.split('"')[0])
        self.list_iface = list_iface
        result = json.dumps(list_iface)
        return json.loads(result)

    def list_ifconfig_detail(self, iface):
        if iface not in self.list_iface:
            data = {
                "status": "error",
                "exception": "Not found network."
            }
            result = json.dumps(data)
            return json.loads(result)
        network = {'interface': iface, 'ip_addr': None, 'netmask': None,
                   'gateway': '0.0.0.0', "mac_addr": None}
        command = 'netsh interface ip show config name="{0}"'.format(str(iface))
        netshcmd = subprocess.Popen(command, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None)
        output = str(netshcmd.communicate()).split("\\r\\n")
        for split in output:
            if 'IP Address' in split:
                network['ip_addr'] = split.split(" ")[-1]
            elif 'Subnet Prefix' in split:
                # print(split)
                network['netmask'] = split.split(" ")[-1][:-1]
            elif 'Default Gateway' in split:
                network['gateway'] = split.split(" ")[-1]
            elif 'DHCP enabled' in split:
                dhcp_config = split.split(" ")[-1]
                if dhcp_config == "No":
                    network['static'] = 1
                else:
                    network['static'] = 0
        network["mac_addr"] = self.get_mac(iface)
        result = json.dumps(network)
        return json.loads(result)

    def get_mac(self, iface):
        command = 'getmac /v  /fo CSV | find "{0}"'.format(str(iface))
        netshcmd = subprocess.Popen(command, shell=True, stdin=None, stdout=subprocess.PIPE, stderr=None)
        output = str(netshcmd.communicate()).split('","')
        if len(output) > 2:
            output = output[-2]
        else:
            output = None
        return output

    def choose_mode(self, task_info):
        if task_info.interface not in self.list_iface:
            data = {
                "status": "error",
                "exception": "Interface is forbidden."
            }
            result = json.dumps(data)
            return json.loads(result)
        if not task_info.static:
            return self.dhcp(task_info)
        else:
            return self.static(task_info)

    def dhcp(self, task_info):
        try:
            # Enable DHCP
            command = 'netsh interface ip set address "{0}" dhcp'.format(str(task_info.interface))
            subprocess.Popen(command, shell=True)
            time.sleep(0.5)
            command_dns = 'netsh interface ip set dns "{0}" dhcp'.format(str(task_info.interface))
            subprocess.Popen(command_dns, shell=True)
            time.sleep(2)
            data = self.list_ifconfig_detail(str(task_info.interface))
            data["test_connection"] = True
            data["static"] = False
            task_info.test_connection = True
            task_info.save()
            return data
        except:
            data = {
                "status": "error",
                "exception": "Interface is forbidden."
            }
            result = json.dumps(data)
            return json.loads(result)

    def static(self, task_info):
        try:
            command = 'netsh interface ip set address "{0}" static {1} {2} {3}'.format(str(task_info.interface),
                                                                                       str(task_info.ip_addr),
                                                                                       str(task_info.netmask),
                                                                                       str(task_info.gateway))
            subprocess.Popen(command, shell=True)
            time.sleep(0.5)
            dns_server = task_info.dns_server
            if dns_server is None or dns_server == "":
                dns_server = "8.8.8.8 8.8.4.4"
            list_dns = str(dns_server).split(" ")
            index = 1
            for dns in list_dns:
                if dns != "":
                    if index == 1:
                        command_dns = 'netsh interface ip set dns "{0}" static {1}'.format(str(task_info.interface),
                                                                                           str(dns))
                    else:
                        command_dns = 'netsh interface ip add dns "{0}" {1} index={}'.format(str(task_info.interface),
                                                                                             str(dns), str(index))
                    subprocess.Popen(command_dns, shell=True)
                    index += 1

            time.sleep(4)
            data = self.list_ifconfig_detail(str(task_info.interface))
            if "ip_addr" in data and data["ip_addr"] == str(task_info.ip_addr):
                data["test_connection"] = True
                task_info.test_connection = True
                task_info.save()
            else:
                data["test_connection"] = False
            data["static"] = True
            # print data
            return data
        except:
            data = {
                "status": "error",
                "exception": "Interface is forbidden."
            }
            result = json.dumps(data)
            return json.loads(result)

# if __name__ == "__main__":
#     a = net_ipconfig()
#     list = a.list_iface
#     print (list)
#     for k in list:
#         print (a.list_ifconfig_detail(str(k)))
# print (a.get_mac(str(k)))
# command = 'netsh interface ip set address "Wi-Fi" static 192.168.30.124 255.255.255.0 192.168.30.1'
# netshcmd = subprocess.Popen(command, shell=True)
# task_info = NetworkConfigModel()
# # a = get_driver_name_from_guid()
# # print a
# # print(get_ip(str(a[0])))
