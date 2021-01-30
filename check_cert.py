#!/usr/bin/env python3

from elasticsearch import Elasticsearch
import datetime
import pytz
import dateutil.parser
import uuid
import pprint
import json

import os
import sys
import argparse

import requests

from certinfo import crt_cert_info



### MAIN
pp = pprint.PrettyPrinter(indent=4)
#pp.pprint(to_investigate)


crt_cert_info = crt_cert_info.Crt_Cert_Info()

vulnerable_list = []
clean_list = []
other_ca_list = []

certinfo_list = crt_cert_info.retrieve_match_all()
for certinfo in certinfo_list:
    if crt_cert_info.is_certinfo_valid_cert(certinfo):
        # Only consider valid certs
        if crt_cert_info.check_if_cert_info_is_PKIO_2020(certinfo):
            if certinfo['common_name'] not in clean_list:
                clean_list.append(certinfo['common_name'])
        elif crt_cert_info.check_if_cert_info_is_PKIO_G3(certinfo):
            if certinfo['common_name'] not in vulnerable_list:
                vulnerable_list.append(certinfo['common_name'])
        else:
            if certinfo['common_name'] not in other_ca_list:
                other_ca_list.append(certinfo['common_name'])


pp.pprint(vulnerable_list)
pp.pprint(clean_list)


for v in vulnerable_list:
    if v in clean_list:
        vulnerable_list.remove(v)

print(vulnerable_list)
