#!/usr/bin/env python3

from elasticsearch import Elasticsearch
import datetime
import uuid
import pprint
import json

import os
import sys
import argparse

import requests


pp = pprint.PrettyPrinter(indent=4)


INDEX_NAME = "crt.sh"
DOC_TYPE = "cert_info"


def argparsing():
    # Parser
    parser = argparse.ArgumentParser(os.path.basename(__file__))
    parser.add_argument("-d", "--domain",
                        dest='domain',
                        help="Domain to lookup",
                        default=None,
                        type=str)

    args = parser.parse_args()
    return args

def get_certs(domain):
    url = 'https://crt.sh/'

    kv = {}
    kv['output'] = 'json'
    kv['q'] = domain

    r = requests.get(url, params=kv)
    if r.status_code >= 200 and r.status_code <= 299:
        return r.json()
    else:
        print(r.text())
        return None

### MAIN
args = argparsing()
if args.domain is None:
    print("No domain provided")
    sys.exit(1)

c_j = get_certs(args.domain)
if c_j is None:
    sys.exit(1)

#pp.pprint(c_j)


# Connect to Elastic
client = Elasticsearch(hosts=["elastic.koeroo.lan:9200"])
client.indices.create(index=INDEX_NAME, ignore=400)



for cert_info in c_j:
    # Search param template
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

    response = client.search(index=INDEX_NAME, body=search_param_search_by, size=3000)
    pp.pprint(response)

    if len(response['hits']['hits']) == 0:
        print("Nothing found, adding...")

        res = client.create(index=INDEX_NAME, doc_type=DOC_TYPE, id=uuid.uuid4(), body=cert_info)
        print(res)
    else:
        print("Found! Nothing to do..")


