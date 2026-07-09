import json
from datetime import datetime
from elasticsearch import Elasticsearch

es = Elasticsearch(["http://amy_elasticsearch:9200"], request_timeout=30)
count = 0

def get_attack_type(rule_id):
    if not rule_id:
        return 'Other'
    if rule_id.startswith('942'):
        return 'SQL Injection'
    elif rule_id.startswith('941'):
        return 'XSS'
    elif rule_id.startswith('930') or rule_id.startswith('931'):
        return 'LFI/Path Traversal'
    elif rule_id.startswith('932'):
        return 'Command Injection'
    elif rule_id.startswith('920'):
        return 'Protocol Anomaly'
    elif rule_id.startswith('949') or rule_id.startswith('980'):
        return 'Anomaly Score'
    elif rule_id.startswith('921'):
        return 'HTTP Violation'
    else:
        return 'Other'

def get_target(uri):
    if not uri:
        return 'Dashboard'
    uri_lower = uri.lower()
    if '/dvwa' in uri_lower:
        return 'DVWA'
    elif '/webgoat' in uri_lower:
        return 'WebGoat'
    elif '/vulnapp' in uri_lower:
        return 'VulnApp'
    else:
        return 'Dashboard'

with open("/var/log/nginx/modsec_audit.log", "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
            transaction = data.get('transaction', {})
            messages = transaction.get('messages', [])
            uri = transaction.get('request', {}).get('uri', '')
            timestamp = transaction.get('time_stamp', '')
            
            try:
                ts = datetime.strptime(timestamp, "%a %b %d %H:%M:%S %Y")
                timestamp_iso = ts.isoformat() + "Z"
            except:
                timestamp_iso = datetime.now().isoformat() + "Z"

            target = get_target(uri)

            for msg in messages:
                rule_id = msg.get('details', {}).get('ruleId', '')
                message = msg.get('message', '')
                attack_type = get_attack_type(rule_id)

                if not rule_id:
                    continue

                doc = {
                    "@timestamp": timestamp_iso,
                    "rule_id": rule_id,
                    "message": message,
                    "attack_type": attack_type,
                    "uri": uri,
                    "target": target,
                    "raw_log": line[:500]
                }

                es.index(index="modsecurity-clean", body=doc)
                count += 1

        except json.JSONDecodeError:
            continue
        except Exception as e:
            continue

print(f"✅ Successfully indexed {count} attack logs!")
