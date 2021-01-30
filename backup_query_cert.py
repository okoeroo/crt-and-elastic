#!/usr/bin/env python3

from elasticsearch import Elasticsearch
import datetime
import uuid
import pprint
import json

import os
import argparse


pp = pprint.PrettyPrinter(indent=4)


INDEX_NAME = "crt.sh"
DOC_TYPE = "cert_info"

client = Elasticsearch(hosts=["elastic.koeroo.lan:9200"])
client.indices.create(index=INDEX_NAME, ignore=400)


#def argparsing():
#    # Parser
#    parser = argparse.ArgumentParser(os.path.basename(__file__))
#    parser.add_argument("-i", "--input",
#                        dest='input',
#                        help="Input file",
#                        default=None,
#                        type=str)
#
#    args = parser.parse_args()
#    return args
#
#args = argparsing()


# create a Python dictionary for the search query:
#search_param_match_all = {
#    "query": {
#        "match_all": {}
#    }
#}
#
## get a response from the cluster
#response = client.search(index=INDEX_NAME, body=search_param_match_all)
#pp.pprint(response)
#


search_param_wildcard = {
    "query": {
        "wildcard": {
           "issuer_name": {
              "value": "*G3*"
           }
        }
    }
}

# get a response from the cluster
print("Wildcard")
response = client.search(index=INDEX_NAME, body=search_param_wildcard, size=10)
if len(response['hits']['hits']) > 0:
    print("Yes, more then 1")


pp.pprint(response)



print("common name")
search_param_search_by_common_name = { 
    "query": {
        "match_phrase": {
            "common_name": "ciso-ksp-acc.kpnnet.org"
            }
        }
    }

response = client.search(index=INDEX_NAME, body=search_param_search_by_common_name, size=3000)
pp.pprint(response)


