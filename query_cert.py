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

# Match all certs
certinfo_list_all = crt_cert_info.retrieve_match_all()
# Only valid certs
certinfo_list_valid_only = crt_cert_info.filter_cert_info_list_to_only_valid_certificates(certinfo_list_all)

# list common names
to_investigate = crt_cert_info.extract_common_names_from_cert_info_list(certinfo_list_valid_only)


for to_i in to_investigate:
    found = False
    # Gather all certificates with this common name
    common_name_certinfo_list = crt_cert_info.search_for_common_name(to_i)


    # Of this list, check if any are PKIO 2020
    for c in common_name_certinfo_list:
        if crt_cert_info.check_if_CA_is_OK(c):
            found = True
            break

    if not found:
        print("---", to_i, "POSSIBLE NOT SAFE")

        # What it is in the DB
#        print("---- got this in the DB")
#        pp.pprint(common_name_certinfo_list)
#
#        print("---- got this on crt.sh")
#            pp.pprint(item)

        # Get from crt.sh
        fetched_certs = crt_cert_info.get_certs(to_i)

        only_valid = crt_cert_info.filter_cert_info_list_to_only_valid_certificates(fetched_certs)
        for c in only_valid:
            if crt_cert_info.check_if_CA_is_OK(c):
                found = True
                break

        # After fixing with after care
        if not found:
            print("===", to_i, "FOR SURE NOT SAFE")

            for item in fetched_certs:
                pp.pprint(item)
                if not crt_cert_info.check_if_cert_info_exists(item):
                    pp.pprint(item)
                    print('Adding cert', 'id:', item['id'], 'serial:', item['serial_number'], 'issuer:', item['issuer_name'])
                    crt_cert_info.add_cert_info(item)


sys.exit(0)
#pp.pprint(common_name_certinfo_list)



#            ci_list_json = crt_cert_info.get_certs(ci_item['common_name'])
#            if ci_list_json is None:
#                continue
#
#            for item in ci_list_json:
#                if not crt_cert_info.check_if_cert_info_exists(item):
#                    crt_cert_info.add_cert_info(item)


