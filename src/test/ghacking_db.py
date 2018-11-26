# -*- coding: utf-8 -*-
import json

import requests

file = open('ghdb.txt', 'r')
data = json.load(file)
uri = "http://192.168.0.116:8442/agents/ghdb"
headers = {'Content-Type': 'application/json',
           'one-token': '74bb5a194a7b7ccf80fa779232cef6c33daf8b9f9654ea894c903233fb427c58'}
for d in data:
    if d:
        try:
            r = requests.post(uri, headers=headers, data=json.dumps(d))
            status_code = r.status_code
            if r.status_code != 201:
                print "Cannot import {}, status {}".format(str(d['keyword'].encode('utf8')), str(r.status_code))
        except Exception, ex:
            print "Cannot import {}, ex {}".format(str(d['keyword'].encode('utf8')), str(ex))
