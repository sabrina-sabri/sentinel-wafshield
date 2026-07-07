import re
import pandas as pd
import numpy as np
from datetime import datetime
from elasticsearch import Elasticsearch
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import pickle
import seaborn as sns
import matplotlib.pyplot as plt

# Connect to Elasticsearch
es = Elasticsearch(["http://localhost:9200"])

def extract_features(url, message=""):
    features = {}
    features['url_length'] = len(url)
    features['special_char_count'] = len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', url))
    features['digit_count'] = len(re.findall(r'\d', url))
    features['has_sql'] = 1 if re.search(r'(?i)(select|union|drop|insert|update|delete|exec|script|or 1=1)', url + message) else 0
    features['has_xss'] = 1 if re.search(r'(?i)(<script|alert|onerror|onload|javascript)', url + message) else 0
    features['has_lfi'] = 1 if re.search(r'(?i)(\.\./|\.\.\\|%2e%2e|web-inf)', url.lower()) else 0
    features['has_cmd'] = 1 if re.search(r'(?i)(whoami|cat |ls |exec|system)', url + message) else 0
    return list(features.values())

# Load real data from Elasticsearch
print("Loading data from Elasticsearch...")
res = es.search(index="modsecurity-clean", body={
    "size": 10000,
    "query": {"match_all": {}}
})

hits = res['hits']['hits']
data = []

for hit in hits:
    src = hit['_source']
    url = src.get('uri', '') or "http://example.com"
    message = src.get('message', '')
    attack_type = src.get('attack_type', 'Other')
    
    features = extract_features(url, message)
    label = 1 if attack_type != "Other" else 0   # 1 = Malicious, 0 = Benign
    
    data.append(features + [label])

df = pd.DataFrame(data, columns=['url_length', 'special_char_count', 'digit_count', 
                                 'has_sql', 'has_xss', 'has_lfi', 'has_cmd', 'label'])

print(f"Loaded {len(df)} samples")

# Train-Test Split
X = df.drop('label', axis=1)
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# Train Random Forest
model = RandomForestClassifier(n_estimators=200, random_state=42, max_depth=10)
model.fit(X_train, y_train)

# Evaluation
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)

print(f"\n✅ Model Training Completed!")
print(f"Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Save Model
with open('rf_model.pkl', 'wb') as f:
    pickle.dump(model, f)

print("Model saved as 'rf_model.pkl'")

# Feature Importance
importances = model.feature_importances_
feature_names = X.columns
fi_df = pd.DataFrame({'Feature': feature_names, 'Importance': importances})
print("\nTop Important Features:")
print(fi_df.sort_values('Importance', ascending=False))
