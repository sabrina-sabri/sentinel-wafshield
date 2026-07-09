import json
from elasticsearch import Elasticsearch

es = Elasticsearch("http://amy_elasticsearch:9200")

# Delete and recreate index with correct mapping
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

# Import documents in batches
with open('/app/es_export.json', 'r') as f:
    docs = json.load(f)

print(f"Total documents to import: {len(docs)}")

batch_size = 1000
count = 0
for i in range(0, len(docs), batch_size):
    batch = docs[i:i+batch_size]
    for doc in batch:
        es.index(
            index="modsecurity-clean",
            body=doc['_source']
        )
        count += 1
    print(f"Imported {count}/{len(docs)}...")

print(f"✅ Successfully imported {count} documents!")
