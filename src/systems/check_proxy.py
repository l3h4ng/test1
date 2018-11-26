# import urllib2, threading

import socket
import urllib2
import six

from systems.serializers import SystemsProxySerializers
from sbox4web import settings


def is_working_proxy(ProxyModel):
    if not ProxyModel.enable:
        ProxyModel.test_connection = False
        ProxyModel.save()
        return SystemsProxySerializers(ProxyModel).data
    protocol = ProxyModel.protocol
    address = ProxyModel.address
    port = ProxyModel.port
    username = ProxyModel.username
    password = ProxyModel.password
    timeout = 3
    try:
        headers = {'User-Agent': 'Mozilla/5.0 Firefox/33.0'}
        proxies = '{0}://{1}:{2}/'.format(str(protocol), str(address), str(port))
        if username is not None and password is not None:
            proxies = '{0}://{1}:{2}@{3}:{4}/'.format(protocol, username, password, address, port)
        req = six.moves.urllib.request.Request(settings.ADDRESS_CHECK, None, headers)
        proxy_support = six.moves.urllib.request.ProxyHandler({str(protocol): proxies})
        opener = six.moves.urllib.request.build_opener(proxy_support)
        page = opener.open(req, timeout=timeout)
        print("connect: %s") % settings.ADDRESS_CHECK
        ProxyModel.test_connection = True
        ProxyModel.save()
        print "proxy co ton tai"
        serilizer = SystemsProxySerializers(ProxyModel)
        return serilizer.data
    except Exception as detail:
        print "ERROR:", detail
        ProxyModel.test_connection = False
        ProxyModel.save()
        serilizer = SystemsProxySerializers(ProxyModel)
        return serilizer.data
