# -*- coding: utf-8 -*-
import json
import re

__author__ = 'TOANTV'
import time
from urlparse import urlparse

import requests
from requests.exceptions import RequestException
from django.conf import settings

requests.packages.urllib3.disable_warnings()

sbox4net = {
    "server": "192.168.30.190",
    "port": "8443",
    "username": "admin@mvs.vn",
    "password": "Admin12345"
}

sbox4web = {
    "server": "192.168.30.136",
    "port": "8442",
    "username": "admin@mvs.vn",
    "password": "Admin12345"
}

settings.SBOX4NET_TOKEN = ""
settings.SBOX4WEB_TOKEN = ""


def forward_request(method, uri, data=None):
    if uri.find("/website"):
        headers = {
            "one-token": settings.SBOX4WEB_TOKEN,
            "Content-Type": "application/json"
        }
        obj = re.search(".*\/website(.*)", uri)
        if obj:
            uri = obj.group(1)
        url = build_url(sbox4web["server"], sbox4web["port"], uri, is_https=False)
        r = connect(method, url, headers, data)
        return r.json()
    else:
        headers = {
            "one-token": settings.SBOX4WEB_TOKEN,
            "Content-Type": "application/json"
        }
        obj = re.search(".*\/network(.*)", uri)
        if obj:
            uri = obj.group(1)
        url = build_url(sbox4web["server"], sbox4web["port"], uri, is_https=False)
        r = connect(method, url, headers, data)
        return r.json()


def connect(method, url, headers=None, data=None):
    r = send(method, url, headers=headers, data=data)
    if r is not None:
        if r.status_code == 401:
            if sbox4web["server"] in url and sbox4web["port"] in url:
                login(is_website=True)
                headers["one-token"] = settings.SBOX4WEB_TOKEN
            else:
                login(is_website=False)
                headers["one-token"] = settings.SBOX4NET_TOKEN
            r = connect(method, url, headers=headers, data=data)
        elif r.status_code >= 500:
            print "Cannot connect to web server, url: {}, status: {}".format(url, str(r.status_code))
    return r


def login(is_website=True):
    if is_website:
        uri = build_url(sbox4web["server"], sbox4web["port"], "/auth/login", is_https=False)
        auth = {"email": sbox4web["username"], "password": sbox4web["password"]}
    else:
        uri = build_url(sbox4net["server"], sbox4net["port"], "/auth/login", is_https=False)
        auth = {"email": sbox4net["username"], "password": sbox4net["password"]}
    r = send("POST", uri, data=json.dumps(auth))
    status_code = r.status_code
    if status_code == 200:
        user_info = r.json()
        if "one-token" in user_info:
            if is_website:
                settings.SBOX4WEB_TOKEN = user_info["one-token"]
            else:
                settings.SBOX4NET_TOKEN = user_info["one-token"]
            print "Login Successful!"
    else:
        print "Cannot login to web service, uri: {}, status: {}".format(uri, str(r.status_code))


def build_url(server, port, uri, is_https=False):
    url = server
    if is_https:
        if url.find("https://") == -1:
            url = "https://" + url
    else:
        if url.find("http://") == -1:
            url = "http://" + url
    url_parsed = urlparse(url)
    if url_parsed.port is None:
        if port is not "":
            new_url = url_parsed.netloc + ":" + str(port)
            url = url_parsed._replace(netloc=new_url)
            url = url.geturl()
    return '{0}{1}'.format(url, uri)


def send(method, uri, headers=None, data=None, files=None, stream=None, is_https=False):
    repeat_times = 3
    count = 0
    response = None
    while (count < repeat_times):
        try:
            if is_https:
                response = https_connect(method, uri, headers=headers, data=data, files=files, stream=stream)
            else:
                response = http_connect(method, uri, headers=headers, data=data, files=files, stream=stream)
            if stream == True:
                return response
            response.raise_for_status()
            return response
        except (ValueError, RequestException) as exc:
            if hasattr(exc, 'response') and hasattr(exc.response, 'status_code'):
                return exc.response
            else:
                print "Cannot send requests, url {}, except {}".format(str(uri), str(exc))
                time.sleep(3)
                count += 1
                continue
    print "Send requests is error, aborted!!!"


def http_connect(method, uri, headers=None, data=None, files=None, stream=None):
    if headers is None:
        headers = {'content-type': 'application/json'}
    if method == 'POST':
        return requests.post(uri, data=data, headers=headers, files=files, stream=stream)
    elif method == 'PUT':
        return requests.put(uri, data=data, headers=headers, files=files, stream=stream)
    elif method == 'DELETE':
        return requests.delete(uri, data=data, headers=headers, files=files, stream=stream)
    elif method == 'PATCH':
        return requests.patch(uri, data=data, headers=headers, files=files, stream=stream)
    else:
        return requests.get(uri, params=data, headers=headers, files=files, stream=stream)


def https_connect(method, uri, headers=None, data=None, files=None, stream=None, verify=False):
    if headers is None:
        headers = {'content-type': 'application/json'}
    if method == 'POST':
        return requests.post(uri, data=data, headers=headers, verify=verify, files=files, stream=stream)
    elif method == 'PUT':
        return requests.put(uri, data=data, headers=headers, verify=verify, files=files, stream=stream)
    elif method == 'DELETE':
        return requests.delete(uri, data=data, headers=headers, verify=verify, files=files, stream=stream)
    elif method == 'PATCH':
        return requests.patch(uri, data=data, headers=headers, files=files, stream=stream, verify=verify)
    else:
        return requests.get(uri, params=data, headers=headers, verify=verify, files=files, stream=stream)
