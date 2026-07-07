import re
import pandas as pd
from elasticsearch import Elasticsearch
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pickle

es = Elasticsearch(["http://localhost:9200"])

def extract_features(url, message=""):
    text = (url + " " + str(message)).lower()
    features = {}
    features['url_length'] = len(url)
    features['special_char_count'] = len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', url))
    features['digit_count'] = len(re.findall(r'\d', url))
    features['quote_count'] = text.count("'") + text.count('"')
    features['equal_count'] = text.count('=')
    features['has_sql'] = 1 if re.search(r"(?i)(union|select|drop|insert|update|delete|or 1=1|1'|1=1|--|exec|cast)", text) else 0
    features['has_xss'] = 1 if re.search(r"(?i)(<script|alert|onerror|onload|javascript|src=)", text) else 0
    features['has_lfi'] = 1 if re.search(r"(?i)(\.\./|\.\.\\|%2e%2e|web-inf|passwd|etc/)", text) else 0
    features['has_cmd'] = 1 if re.search(r"(?i)(whoami|cat |ls |bash|cmd.exe|system|exec)", text) else 0
    return list(features.values())

print("Loading data...")
res = es.search(index="modsecurity-clean", body={"size": 10000, "sort": [{"@timestamp": "desc"}]})

data = []
for hit in res['hits']['hits']:
    src = hit['_source']
    url = src.get('uri', 'http://example.com')
    message = src.get('message', '')
    attack_type = src.get('attack_type', 'Other')
    label = 1 if attack_type != "Other" else 0
    features = extract_features(url, message)
    data.append(features + [label])

df = pd.DataFrame(data, columns=['url_length','special_char_count','digit_count',
                                 'quote_count','equal_count','has_sql','has_xss',
                                 'has_lfi','has_cmd','label'])

print(f"Loaded {len(df)} samples | Malicious: {df['label'].sum()}")

X = df.drop('label', axis=1)
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.25, random_state=42)

model = RandomForestClassifier(n_estimators=400, random_state=42, class_weight='balanced')
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
print("\n✅ Model Performance:")
print(classification_report(y_test, y_pred))

with open('rf_model.pkl', 'wb') as f:
    pickle.dump(model, f)

print("✅ Model saved successfully!")

