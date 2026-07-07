import re
import pickle
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# Feature Extraction Function
def extract_features(url):
    features = {}
    features['url_length'] = len(url)
    features['special_chars'] = len(re.findall(r'[!@#$%^&*(),.?":{}|<>]', url))
    features['digit_count'] = len(re.findall(r'\d', url))
    features['has_sql_keywords'] = 1 if re.search(r'(?i)(select|union|drop|insert|update|delete|exec|script)', url) else 0
    features['has_xss_keywords'] = 1 if re.search(r'(?i)(<script|alert|onerror|onload)', url) else 0
    features['has_path_traversal'] = 1 if re.search(r'(\.\./|\.\.\\|%2e%2e)', url) else 0
    features['has_ip_address'] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
    return list(features.values())

# Sample Training Data (you can expand this later)
def train_model():
    # Dummy dataset (replace with real data later)
    urls = [
        "http://example.com", "http://test.com?id=1", 
        "http://evil.com?id=1' OR 1=1 --", 
        "http://site.com/<script>alert(1)</script>",
        "http://site.com/../../etc/passwd",
        "http://normal.com/login"
    ]
    labels = [0, 0, 1, 1, 1, 0]  # 0 = Benign, 1 = Malicious

    X = [extract_features(url) for url in urls]
    y = labels

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)

    # Save model
    with open('rf_model.pkl', 'wb') as f:
        pickle.dump(model, f)

    print("✅ Random Forest Model Trained and Saved!")
    return model

# Load or Train Model
try:
    with open('rf_model.pkl', 'rb') as f:
        model = pickle.load(f)
except:
    model = train_model()

def predict_url(url):
    features = extract_features(url)
    pred = model.predict([features])[0]
    prob = model.predict_proba([features])[0]
    
    risk_score = int(prob[1] * 100)  # Probability of malicious
    label = "Malicious" if pred == 1 else "Benign"
    
    return label, risk_score, prob
