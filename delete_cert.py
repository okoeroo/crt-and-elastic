#!/usr/bin/env python3

from elasticsearch import Elasticsearch
import datetime
import uuid
import pprint
import json


INDEX_NAME = "crt.sh"
DOC_TYPE = "cert_info"


client = Elasticsearch(hosts=["elastic.koeroo.lan:9200"])
client.indices.delete(index=INDEX_NAME, ignore=[400, 404])

