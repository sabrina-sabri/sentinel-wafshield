import re
import pandas as pd
from elasticsearch import Elasticsearch
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE
import pickle

es = Elasticsearch(["http://localhost:9200"])

def extract_features(text):
    text = str(text).lower()
    return [
        len(text),
        len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', text)),
        len(re.findall(r'\d', text)),
        text.count("'") + text.count('"'),
        text.count('='),
        1 if re.search(r"(?i)(union|select|drop|insert|update|delete|or 1=1|1'|1=1|--|exec|cast|sqli|libinjection)", text) else 0,
        1 if re.search(r"(?i)(<script|alert|onerror|onload|javascript|src=|xss)", text) else 0,
        1 if re.search(r"(?i)(\.\./|\.\.\\|%2e%2e|web-inf|passwd|etc/|path traversal|lfi)", text) else 0,
        1 if re.search(r"(?i)(whoami|cat |ls |bash|cmd.exe|system|exec)", text) else 0,
    ]

print("Loading data from Elasticsearch...")
res = es.search(index="modsecurity-clean", body={
    "size": 10000,
    "sort": [{"@timestamp": "desc"}]
})

# Benign types - protocol/anomaly are not real attacks
BENIGN_TYPES = {'Protocol Anomaly', 'Anomaly Score', 'HTTP Violation', 'Other'}

data = []
for hit in res['hits']['hits']:
    src = hit['_source']
    message = src.get('message', '')
    attack_type = src.get('attack_type', 'Other')
    label = 0 if attack_type in BENIGN_TYPES else 1
    features = extract_features(message)
    data.append(features + [label, attack_type])

df = pd.DataFrame(data, columns=[
    'text_length', 'special_char_count', 'digit_count',
    'quote_count', 'equal_count', 'has_sql', 'has_xss',
    'has_lfi', 'has_cmd', 'label', 'attack_type'])

print(f"Total: {len(df)}")
print(f"Benign: {(df['label']==0).sum()} | Malicious: {(df['label']==1).sum()}")
print("\nAttack breakdown:")
print(df[df['label']==1]['attack_type'].value_counts())

# Synthetic URL samples
synthetic_malicious = [
    "http://example.com/?id=1' OR 1=1 --",
    "http://example.com/?id=1 UNION SELECT * FROM users--",
    "http://example.com/?id=1; DROP TABLE users--",
    "http://example.com/?id=1' AND SLEEP(5)--",
    "http://example.com/?id=1 ORDER BY 10--",
    "http://example.com/?q=<script>alert('xss')</script>",
    "http://example.com/?q=<img src=x onerror=alert(1)>",
    "http://example.com/?q=<svg onload=alert(1)>",
    "http://example.com/?file=../../etc/passwd",
    "http://example.com/?page=../../../etc/shadow",
    "http://example.com/?file=....//....//etc/passwd",
    "http://example.com/?cmd=whoami",
    "http://example.com/?exec=ls -la",
    "http://example.com/?cmd=cat /etc/passwd",
    "http://example.com/?q=;whoami",
]

synthetic_benign = [
    "http://example.com/index.html",
    "http://example.com/about",
    "http://example.com/contact",
    "http://example.com/products",
    "http://example.com/login",
    "http://example.com/home",
    "http://example.com/dashboard",
    "http://example.com/profile",
    "http://example.com/search?q=laptop",
    "http://example.com/search?q=phone",
    "http://example.com/api/users",
    "http://example.com/api/products",
    "http://example.com/blog/post-1",
    "http://example.com/?page=1",
    "http://example.com/?category=electronics",
]

for url in synthetic_malicious:
    for _ in range(500):
        data.append(extract_features(url) + [1, 'Synthetic'])

for url in synthetic_benign:
    for _ in range(500):
        data.append(extract_features(url) + [0, 'Synthetic'])

df = pd.DataFrame(data, columns=[
    'text_length', 'special_char_count', 'digit_count',
    'quote_count', 'equal_count', 'has_sql', 'has_xss',
    'has_lfi', 'has_cmd', 'label', 'attack_type'])

print(f"\nAfter synthetic: {len(df)}")
print(f"Benign: {(df['label']==0).sum()} | Malicious: {(df['label']==1).sum()}")

X = df.drop(['label', 'attack_type'], axis=1)
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y)

print(f"\nBefore SMOTE — Malicious: {y_train.sum()}")
smote = SMOTE(random_state=42)
X_train_bal, y_train_bal = smote.fit_resample(X_train, y_train)
print(f"After SMOTE  — Malicious: {y_train_bal.sum()}")

model = RandomForestClassifier(
    n_estimators=400,
    random_state=42,
    class_weight='balanced',
    min_samples_leaf=2,
    max_features='sqrt'
)
model.fit(X_train_bal, y_train_bal)

y_pred = model.predict(X_test)
print("\n✅ Model Performance:")
print(classification_report(y_test, y_pred))
print("Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

with open('/home/amelia/SENTINEL/waf_flask/rf_model.pkl', 'wb') as f:
    pickle.dump(model, f)

print("\n✅ Model saved!")
