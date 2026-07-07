import streamlit as st
import pandas as pd
import re
import sqlite3
import hashlib
from datetime import datetime
from elasticsearch import Elasticsearch
import plotly.express as px
import pickle

# ====================== DATABASE ======================
conn = sqlite3.connect('waf_users.db', check_same_thread=False)
c = conn.cursor()
c.execute('''CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT,
                role TEXT,
                created_at TEXT)''')
conn.commit()

# Default Admin
admin_hash = hashlib.sha256("admin123".encode()).hexdigest()
c.execute("INSERT OR IGNORE INTO users VALUES (?, ?, ?, ?)", 
          ("admin", admin_hash, "admin", datetime.now().strftime("%Y-%m-%d %H:%M")))
conn.commit()

# ====================== CSS ======================
st.markdown("""
<style>
    .stApp { background: linear-gradient(135deg, #0a0a2e, #1a1a5e, #2a1b6e); }
    .glass { background: rgba(15, 23, 42, 0.75) !important; 
              backdrop-filter: blur(20px); border-radius: 20px; 
              border: 1px solid rgba(0, 245, 255, 0.3); }
    .neon-title { color: #00f5ff; text-shadow: 0 0 20px #00f5ff; }
</style>
""", unsafe_allow_html=True)

st.set_page_config(page_title="WAF SHIELD", layout="wide", page_icon="🛡️")

# Session State
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False
    st.session_state.username = ""
    st.session_state.role = ""
    st.session_state.history = []

# Login
if not st.session_state.logged_in:
    st.title("🛡️ WAF SHIELD")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login"):
        hashed = hashlib.sha256(password.encode()).hexdigest()
        c.execute("SELECT role FROM users WHERE username=? AND password=?", (username, hashed))
        result = c.fetchone()
        if result:
            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.role = result[0]
            st.rerun()
    st.stop()

# Sidebar
with st.sidebar:
    st.write(f"**User:** {st.session_state.username}")
    st.write(f"**Role:** {st.session_state.role.upper()}")
    page = st.radio("Go to", ["📊 Dashboard", "🔍 ML Risk Analysis", "📜 History", "⚙️ Admin"])
    if st.button("Logout"):
        st.session_state.logged_in = False
        st.rerun()

# Backend
es = Elasticsearch(["http://localhost:9200"])

@st.cache_resource
def load_model():
    try:
        with open('rf_model.pkl', 'rb') as f:
            return pickle.load(f)
    except:
        return None

model = load_model()

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

def predict_url(url):
    if model is None:
        return "Error", 0
    features = extract_features(url)
    pred = model.predict([features])[0]
    prob = model.predict_proba([features])[0][1]
    risk_score = int(prob * 100)
    label = "Malicious" if pred == 1 else "Benign"
    return label, risk_score

def load_data():
    try:
        res = es.search(index="modsecurity-clean", body={"size": 10000, "sort": [{"@timestamp": "desc"}]})
        df = pd.DataFrame([hit['_source'] for hit in res['hits']['hits']])
        if not df.empty:
            df['@timestamp'] = pd.to_datetime(df['@timestamp'])
        return df
    except:
        return pd.DataFrame()

df = load_data()

# ====================== PAGES ======================
if page == "📊 Dashboard":
    st.title("📊 Main Dashboard")
    col1, col2, col3, col4, col5 = st.columns(5)
    with col1: st.metric("Total Attacks", len(df))
    with col2: st.metric("Unique Rules", df['rule_id'].nunique() if not df.empty else 0)
    with col3: st.metric("SQL Injection", len(df[df['attack_type'] == 'SQL Injection']) if not df.empty else 0)
    with col4: st.metric("XSS", len(df[df['attack_type'] == 'XSS']) if not df.empty else 0)
    with col5: st.metric("LFI", len(df[df['attack_type'].str.contains('LFI', na=False)]) if not df.empty else 0)

    col1, col2 = st.columns([2, 1])
    with col1:
        st.subheader("Attacks Over Time")
        if not df.empty:
            fig = px.histogram(df, x='@timestamp', nbins=40, color_discrete_sequence=['#00f5ff'])
            st.plotly_chart(fig, use_container_width=True)
    with col2:
        st.subheader("Attack Types")
        if not df.empty:
            fig2 = px.pie(df, names='attack_type')
            st.plotly_chart(fig2, use_container_width=True)

    st.subheader("Top 10 Triggered Rules")
    if not df.empty:
        st.bar_chart(df['rule_id'].value_counts().head(10))

    st.subheader("Recent Attacks")
    if not df.empty:
        st.dataframe(df[['@timestamp', 'rule_id', 'attack_type', 'message']].head(10), use_container_width=True)

elif page == "🔍 ML Risk Analysis":
    st.title("🔍 ML Risk Analysis")
    url = st.text_input("Enter URL to analyze:", placeholder="http://example.com/?id=1' OR 1=1 --")
    if st.button("Analyze URL", type="primary"):
        if url:
            label, risk_score = predict_url(url)
            st.session_state.history.append({
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
                "url": url,
                "result": label,
                "confidence": risk_score
            })
            if label == "Malicious":
                st.error(f"**HIGH RISK** — {label} ({risk_score}% confidence)")
            else:
                st.success(f"**SAFE** — {label} ({risk_score}% confidence)")
        else:
            st.warning("Please enter a URL")

elif page == "📜 History":
    st.title("📜 Analysis History")
    if st.session_state.history:
        st.dataframe(pd.DataFrame(st.session_state.history), use_container_width=True)
    else:
        st.info("No history yet.")

elif page == "⚙️ Admin":
    st.title("⚙️ Admin Panel")
    st.write("Total Users:", c.execute("SELECT COUNT(*) FROM users").fetchone()[0])

st.caption("FYP Dashboard | Streamlit + SQLite + Elasticsearch")
