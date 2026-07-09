import json
from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk

es = Elasticsearch("http://amy_elasticsearch:9200")

# Delete and recreate
es.indices.delete(index="modsecurity-clean", ignore_unavailable=True)
es.indices.create(index="modsecurity-clean", body={
    "mappings": {
        "properties": {
            "@timestamp": {"type": "date"},
            "attack_type": {"type": "keyword"},
            "rule_id": {"type": "keyword"},
            "message": {"type": "text"},
            "uri": {"type": "keyword"},
            "target": {"type": "keyword"},
            "raw_log": {"type": "text"}
        }
    }
})
print("Index recreated")

with open('/app/es_export.json', 'r') as f:
    docs = json.load(f)

print(f"Total: {len(docs)}")

def generate_actions(docs):
    for doc in docs:
        yield {
            "_index": "modsecurity-clean",
            "_source": doc['_source']
        }

success, failed = bulk(es, generate_actions(docs), chunk_size=500, request_timeout=60)
print(f"✅ Imported {success} documents, {failed} failed")
