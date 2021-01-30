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

import requests


class Crt_Cert_Info():
    def __init__(self):
        self.INDEX_NAME = "crt.sh"
        self.DOC_TYPE = "cert_info"

        self.client = Elasticsearch(hosts=["elastic.koeroo.lan:9200"])
        self.client.indices.create(index=self.INDEX_NAME, ignore=400)

    def get_certs(self, domain):
        url = 'https://crt.sh/'

        kv = {}
        kv['output'] = 'json'
        kv['q'] = domain

        r = requests.get(url, params=kv)
        if r.status_code >= 200 and r.status_code <= 299:
            return r.json()
        else:
            print("Error", r.status_code)
            return None

    def norm_from_elastic_results_to_list(self, e_res):
        cleaned = []
        for i in e_res['hits']['hits']:
            cleaned.append(i['_source'])

        return cleaned

    def retrieve_match_all(self):
        search_param_match_all = {
            "query": {
                "match_all": {}
            }
        }

        # get a response from the cluster
        response = self.client.search(index=self.INDEX_NAME,
                                      body=search_param_match_all, size=10000)
        return self.norm_from_elastic_results_to_list(response)

    def retrieve_all_PKIO_2020(self):
        search_param_wildcard = {
            "query": {
                "match_phrase": {
                   "issuer_name": "C=NL, O=KPN B.V., CN=KPN PKIoverheid Server CA 2020"
                   }
                }
            }

        # get a response from the cluster
        response = self.client.search(index=self.INDEX_NAME, body=search_param_wildcard, size=10000)
        return self.norm_from_elastic_results_to_list(response)

    def retrieve_all_PKIO_G3(self):
        search_param = {
            "query": {
                "match_phrase": {
                   "issuer_name": ""
                   }
                }
            }

        search_param['query']['match_phrase']['issuer_name'] = \
            "C=NL, O=KPN B.V., organizationIdentifier=NTRNL-27124701, CN=KPN BV PKIoverheid Organisatie Server CA - G3"

        # get a response from the cluster
        response = self.client.search(index=self.INDEX_NAME, body=search_param, size=10000)
        return self.norm_from_elastic_results_to_list(response)

    def is_certinfo_valid_cert(self, cert_info):
        # Not After
        date_time_obj_not_after_tz_unaware = \
                dateutil.parser.parse(cert_info['not_after'])
        date_time_obj_not_after_tz_aware = \
                date_time_obj_not_after_tz_unaware.replace(tzinfo=pytz.UTC)

        # Not before
        date_time_obj_not_before_tz_unaware = \
                dateutil.parser.parse(cert_info['not_before'])
        date_time_obj_not_before_tz_aware = \
                date_time_obj_not_before_tz_unaware.replace(tzinfo=pytz.UTC)

        # Now in UTC
        now_utc = datetime.datetime.now(tz=datetime.timezone.utc)

        # Has a valid certificate (now is between not after and not before)
        if now_utc < date_time_obj_not_after_tz_aware and \
                date_time_obj_not_before_tz_aware < now_utc:
            return True
        else:
            return False

    def filter_cert_info_list_to_only_valid_certificates(self, certinfo_list):
        certinfo_list_cleaned = []
        for cert_info in certinfo_list:
            # Has a valid certificate (now is between not after and not before)
            if self.is_certinfo_valid_cert(cert_info):
                certinfo_list_cleaned.append(cert_info)

        return certinfo_list_cleaned

    def extract_common_names_from_cert_info_list(self, certinfo_list):
        to_investigate = []
        for cert_info in certinfo_list:
            if cert_info['common_name'] not in to_investigate:
                to_investigate.append(cert_info['common_name'])

        return to_investigate

    def search_cert_info_exists(self, cert_info):
        search_param_search_by = { 
              "query": {
                "bool": {
                  "must": []
                }
              }
            }

        m = {}
        m['match_phrase'] = {}
        m['match_phrase']['issuer_ca_id'] = cert_info['issuer_ca_id']

        search_param_search_by['query']['bool']['must'].append(m)

        m = {}
        m['match_phrase'] = {}
        m['match_phrase']['serial_number'] = cert_info['serial_number']

        search_param_search_by['query']['bool']['must'].append(m)

        # search
        response = self.client.search(index=self.INDEX_NAME, 
                                    body=search_param_search_by, size=3000)

        # Normalize
        cert_info_list = self.norm_from_elastic_results_to_list(response)
        return cert_info_list

    def check_if_cert_info_exists(self, cert_info):
        return len(self.search_cert_info_exists(cert_info)) > 0

    def add_cert_info(self, cert_info):
        res = self.client.create(index=self.INDEX_NAME, doc_type=self.DOC_TYPE,
                                    id=uuid.uuid4(), body=cert_info)
        return True

    def check_if_CA_is_OK(self, cert_info):
        return \
            cert_info['issuer_name'] == \
                "C=BE, O=GlobalSign nv-sa, CN=GlobalSign GCC R3 DV TLS CA 2020" or \
            cert_info['issuer_name'] == \
                "C=US, O=Amazon, OU=Server CA 1B, CN=Amazon" or \
            cert_info['issuer_name'] == \
                "C=NL, O=KPN B.V., CN=KPN PKIoverheid Server CA 2020" or \
            cert_info['issuer_name'] == \
                "C=NL, O=KPN B.V., CN=KPN PKIoverheid Server CA 2020" or \
            cert_info['issuer_name'] == \
                "C=GB, ST=Greater Manchester, L=Salford, O=Sectigo Limited, CN=Sectigo RSA Domain Validation Secure Server CA" or \
            cert_info['issuer_name'] == \
                "C=GB, ST=Greater Manchester, L=Salford, O=Sectigo Limited, CN=Sectigo RSA Extended Validation Secure Server CA" or \
            cert_info['issuer_name'] == \
                "C=BE, O=GlobalSign nv-sa, CN=GlobalSign RSA OV SSL CA 2018" or \
            cert_info['issuer_name'] == \
                "C=BE, O=GlobalSign nv-sa, CN=GlobalSign Extended Validation CA - SHA256 - G3" or \
            cert_info['issuer_name'] == \
                "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=RapidSSL TLS RSA CA G1" or \
            cert_info['issuer_name'] == \
                "C=US, O=DigiCert Inc, CN=DigiCert TLS RSA SHA256 2020 CA1" or \
            cert_info['issuer_name'] == \
                "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=Thawte RSA CA 2018" or \
            cert_info['issuer_name'] == \
                "C=US, O=DigiCert Inc, OU=www.digicert.com, CN=Thawte TLS RSA CA G1" or \
            cert_info['issuer_name'] == \
                "C=BE, O=GlobalSign nv-sa, CN=GlobalSign GCC R3 DV TLS CA 2020" or \
            cert_info['issuer_name'] == \
                "C=GB, ST=Greater Manchester, L=Salford, O=Sectigo Limited, CN=Sectigo RSA Domain Validation Secure Server CA" or \
            cert_info['issuer_name'] == \
                "C=US, O=Amazon, OU=Server CA 1B, CN=Amazon" or \
            cert_info['issuer_name'] == \
                "C=BE, O=GlobalSign nv-sa, CN=GlobalSign Domain Validation CA - SHA256 - G2" or \
            cert_info['issuer_name'] == \
                "C=GB, ST=Greater Manchester, L=Salford, O=Sectigo Limited, CN=Sectigo RSA Organization Validation Secure Server CA" or \
            cert_info['issuer_name'] == \
                "C=US, O=Let's Encrypt, CN=Let's Encrypt Authority X3"


    def check_if_cert_info_is_PKIO_G3(self, cert_info):
        return \
            "C=NL, O=KPN B.V., organizationIdentifier=NTRNL-27124701, CN=KPN BV PKIoverheid Organisatie Server CA - G3" == \
            cert_info['issuer_name']

    def check_if_cert_info_is_PKIO_2020(self, cert_info):
        return \
            "C=NL, O=KPN B.V., CN=KPN PKIoverheid Server CA 2020" == \
            cert_info['issuer_name']

    def search_for_common_name(self, common_name):
        # Search param template
        search_param_search_by_common_name = { 
            "query": {
                "match_phrase": {
                    "common_name": "ciso-ksp-acc.kpnnet.org"
                }
            }
        }

        search_param_search_by_common_name['query']['match_phrase']['common_name'] = common_name
        response = self.client.search(index=self.INDEX_NAME, body=search_param_search_by_common_name, size=3000)

        cert_info_list = self.norm_from_elastic_results_to_list(response)
        return cert_info_list


