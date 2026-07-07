import re
from datetime import datetime
from elasticsearch import Elasticsearch

es = Elasticsearch(["http://localhost:9200"], request_timeout=30)

count = 0
with open("/var/log/nginx/modsec_audit.log", "r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        if "ModSecurity:" in line:
            rule_match = re.search(r'id "(\d+)"', line)
            msg_match = re.search(r'msg "([^"]+)"', line)
            uri_match = re.search(r'uri "([^"]+)"', line)
            time_match = re.search(r'\[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2})', line)

            rule_id = rule_match.group(1) if rule_match else None
            message = msg_match.group(1) if msg_match else line[:400]
            uri = uri_match.group(1) if uri_match else ''

            if time_match:
                try:
                    ts = datetime.strptime(time_match.group(1), "%d/%b/%Y:%H:%M:%S")
                    timestamp = ts.isoformat() + "Z"
                except:
                    timestamp = datetime.now().isoformat() + "Z"
            else:
                timestamp = datetime.now().isoformat() + "Z"

            if rule_id:
                if rule_id.startswith('942'):
                    attack_type = 'SQL Injection'
                elif rule_id.startswith('941'):
                    attack_type = 'XSS'
                elif rule_id.startswith('930'):
                    attack_type = 'LFI/Path Traversal'
                elif rule_id.startswith('932') or rule_id.startswith('933'):
                    attack_type = 'Command Injection'
                elif rule_id.startswith('913'):
                    attack_type = 'Scanner Detection'
                elif rule_id.startswith('920'):
                    attack_type = 'Protocol Anomaly'
                elif rule_id.startswith('949') or rule_id.startswith('980'):
                    attack_type = 'Anomaly Score'
                elif rule_id.startswith('931'):
                    attack_type = 'RFI'
                elif rule_id.startswith('934'):
                    attack_type = 'PHP Injection'
                elif rule_id.startswith('921'):
                    attack_type = 'HTTP Violation'
                else:
                    attack_type = 'Other'
            else:
                attack_type = 'Other'

            # Detect target website from URI
            if '/dvwa' in uri.lower():
                target = 'DVWA'
            elif '/webgoat' in uri.lower() or '/WebGoat' in uri:
                target = 'WebGoat'
            elif '/vulnapp' in uri.lower():
                target = 'VulnApp'
            else:
                target = 'Dashboard'

            doc = {
                "@timestamp": timestamp,
                "rule_id": rule_id,
                "message": message,
                "attack_type": attack_type,
                "uri": uri,
                "target": target,
                "raw_log": line.strip()[:500]
            }

            try:
                es.index(index="modsecurity-clean", document=doc)
                count += 1
            except Exception as e:
                print("Error:", e)

print(f"✅ Successfully indexed {count} attack logs!")
