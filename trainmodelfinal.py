import re
import pandas as pd
from elasticsearch import Elasticsearch
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import pickle

# Connect Elasticsearch
es = Elasticsearch("http://localhost:9200")

# ================= FEATURE EXTRACTION =================
def extract_features(url, message=""):
    text = (url + " " + str(message)).lower()

    features = {}

    features['url_length'] = len(url)
    features['special_char_count'] = len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', text))
    features['digit_count'] = len(re.findall(r'\d', text))
    features['quote_count'] = text.count("'") + text.count('"')
    features['equal_count'] = text.count('=')

    # SQLi patterns
    features['has_sql'] = 1 if re.search(
        r"(union|select|drop|insert|update|delete|or 1=1|--|exec|cast|sleep|benchmark)",
        text,
        re.IGNORECASE
    ) else 0

    # XSS patterns
    features['has_xss'] = 1 if re.search(
        r"(<script|alert|onerror|onload|javascript:|<img)",
        text,
        re.IGNORECASE
    ) else 0

    # LFI patterns
    features['has_lfi'] = 1 if re.search(
        r"(\.\./|etc/passwd|web-inf|boot.ini)",
        text,
        re.IGNORECASE
    ) else 0

    # Command injection
    features['has_cmd'] = 1 if re.search(
        r"(whoami|ls |cat |bash|cmd.exe|powershell)",
        text,
        re.IGNORECASE
    ) else 0

    return list(features.values())

# ================= LOAD DATA =================
print("Loading attack logs from Elasticsearch...")

res = es.search(
    index="modsecurity-clean",
    body={
        "size": 10000
    }
)

data = []

for hit in res['hits']['hits']:
    src = hit['_source']

    url = src.get('uri', '')
    message = src.get('message', '')
    attack_type = src.get('attack_type', 'Other')

    # Binary classification
    label = 1 if attack_type != "Other" else 0

    features = extract_features(url, message)

    data.append(features + [label])

# ================= DATAFRAME =================
columns = [
    'url_length',
    'special_char_count',
    'digit_count',
    'quote_count',
    'equal_count',
    'has_sql',
    'has_xss',
    'has_lfi',
    'has_cmd',
    'label'
]

df = pd.DataFrame(data, columns=columns)

print(df.head())

print(f"\nLoaded {len(df)} samples")
print(f"Malicious samples: {df['label'].sum()}")

# ================= TRAIN MODEL =================
X = df.drop('label', axis=1)
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.25,
    random_state=42
)

model = RandomForestClassifier(
    n_estimators=300,
    random_state=42,
    class_weight='balanced'
)

print("\nTraining Random Forest model...")
model.fit(X_train, y_train)

# ================= EVALUATION =================
y_pred = model.predict(X_test)

print("\n===== MODEL PERFORMANCE =====")
print(classification_report(y_test, y_pred))

# ================= SAVE MODEL =================
with open("rf_model.pkl", "wb") as f:
    pickle.dump(model, f)

print("\n✅ Model successfully saved as rf_model.pkl")
