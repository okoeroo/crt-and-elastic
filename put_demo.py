#!/usr/bin/env python3

from elasticsearch import Elasticsearch
import datetime
import uuid
import pprint

pp = pprint.PrettyPrinter(indent=4)


INDEX_NAME = "crt"
DOC_TYPE = "cert_info_test1"

e2 = {}
e2['foo'] = 'foo'
e2['bar'] = 'bar'


client = Elasticsearch(hosts=["elastic.koeroo.lan:9200"])
client.indices.create(index=INDEX_NAME, ignore=400)
res = client.create(index=INDEX_NAME, doc_type=DOC_TYPE, id=uuid.uuid4(), body=e2)



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

