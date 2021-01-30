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


def argparsing():
    # Parser
    parser = argparse.ArgumentParser(os.path.basename(__file__))
    parser.add_argument("-i", "--input",
                        dest='input',
                        help="Input file",
                        default=None,
                        type=str)

    args = parser.parse_args()
    return args

args = argparsing()
if args.input is None:
    print("No input file")


with open(args.input) as json_file:
    data = json.load(json_file)


#pp.pprint(data)

for d in data:
    d['name_values'] = []
    for i in d['name_value'].split('\n'):
        d['name_values'].append(i)

#pp.pprint(data)


client = Elasticsearch(hosts=["elastic.koeroo.lan:9200"])
client.indices.create(index=INDEX_NAME, ignore=400)


for d in data:
    print(d['name_value'])
    res = client.create(index=INDEX_NAME, doc_type=DOC_TYPE, id=uuid.uuid4(), body=d)



#########################

# create a Python dictionary for the search query:
search_param_match_all = {
    "query": {
        "match_all": {}
    }
}

# get a response from the cluster
response = client.search(index=INDEX_NAME, body=search_param_match_all)
pp.pprint(response)

