from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import pickle
import re
from datetime import datetime
from elasticsearch import Elasticsearch
import pandas as pd

app = Flask(__name__)
app.secret_key = 'sentinel_wafshield_2024'

# External API Keys
VIRUSTOTAL_API_KEY = "xxxx"
GOOGLE_SB_API_KEY = "xx"

DB_PATH = '/app/waf_users.db'
MODEL_PATH = '/app/rf_model.pkl'

es = Elasticsearch("http://amy_elasticsearch:9200")

with open(MODEL_PATH, 'rb') as f:
    model = pickle.load(f)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password TEXT,
                    role TEXT,
                    created_at TEXT)''')
    existing = c.execute("SELECT * FROM users WHERE username='admin'").fetchone()
    if not existing:
        admin_hash = generate_password_hash('admin123')
        c.execute("INSERT INTO users VALUES (?, ?, ?, ?)",
                  ("admin", admin_hash, "admin",
                   datetime.now().strftime("%Y-%m-%d %H:%M")))
    conn.commit()
    conn.close()

def extract_features(text, message=""):
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
        1 if re.search(r"(?i)(whoami|cat |ls |bash|cmd.exe|system|exec|wget|curl|nmap|chmod|rm -|uname|ifconfig|netcat|nc |python|perl|ruby|php)", text) else 0,
    ]

def check_virustotal(url):
    try:
        import requests as req
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = req.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers=headers, timeout=5)
        if response.status_code == 200:
            data = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            total = sum(stats.values())
            vt_score = int(((malicious + suspicious) / total) * 100) if total > 0 else 0
            return {
                "available": True,
                "malicious": malicious,
                "suspicious": suspicious,
                "total_engines": total,
                "score": vt_score,
                "verdict": "Malicious" if malicious > 0 else "Clean"
            }
        else:
            return {"available": False, "reason": "Not in database"}
    except Exception as e:
        return {"available": False, "reason": str(e)}

def check_google_safebrowsing(url):
    try:
        import requests as req
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SB_API_KEY}"
        payload = {
            "client": {"clientId": "sentinel-wafshield", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING",
                               "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        response = req.post(api_url, json=payload, timeout=5)
        if response.status_code == 200:
            data = response.json()
            matches = data.get("matches", [])
            if matches:
                threat_type = matches[0].get("threatType", "UNKNOWN")
                return {"available": True, "safe": False,
                        "threat_type": threat_type, "verdict": "Unsafe"}
            else:
                return {"available": True, "safe": True,
                        "threat_type": None, "verdict": "Safe"}
        else:
            return {"available": False, "reason": "API error"}
    except Exception as e:
        return {"available": False, "reason": str(e)}

def predict_url(url):
    features = extract_features(url)
    pred = model.predict([features])[0]
    prob = model.predict_proba([features])[0][1]
    risk_score = int(prob * 100)
    label = "Malicious" if pred == 1 else "Benign"
    return label, risk_score

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        if session.get('role') != 'admin':
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

@app.route('/', methods=['GET', 'POST'])
def login():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password'], password):
            session['username'] = user['username']
            session['role'] = user['role']
            return redirect(url_for('dashboard'))
        else:
            error = "Invalid username or password"
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'username' in session:
        return redirect(url_for('dashboard'))
    error = None
    success = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm = request.form['confirm']
        if password != confirm:
            error = "Passwords do not match"
        elif len(password) < 6:
            error = "Password must be at least 6 characters"
        elif len(username) < 3:
            error = "Username must be at least 3 characters"
        else:
            conn = get_db()
            try:
                conn.execute("INSERT INTO users VALUES (?, ?, ?, ?)",
                             (username, generate_password_hash(password),
                              'user', datetime.now().strftime("%Y-%m-%d %H:%M")))
                conn.commit()
                success = "Account created. Please sign in."
            except sqlite3.IntegrityError:
                error = "Username already exists"
            finally:
                conn.close()
    return render_template('signup.html', error=error, success=success)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html',
                           username=session['username'],
                           role=session['role'])

@app.route('/ml-analysis')
@login_required
def ml_analysis():
    return render_template('ml_analysis.html',
                           username=session['username'],
                           role=session['role'])

@app.route('/evaluation')
@login_required
def evaluation():
    return render_template('evaluation.html',
                           username=session['username'],
                           role=session['role'])

@app.route('/logs')
@login_required
def logs():
    return render_template('logs.html',
                           username=session['username'],
                           role=session['role'])

@app.route('/admin')
@admin_required
def admin():
    conn = get_db()
    users = conn.execute(
        "SELECT username, role, created_at FROM users").fetchall()
    conn.close()
    return render_template('admin.html',
                           username=session['username'],
                           role=session['role'],
                           users=users,
                           session_username=session['username'],
                           msg=None,
                           success=None)

@app.route('/admin/add-user', methods=['POST'])
@admin_required
def add_user():
    username = request.form['username']
    password = request.form['password']
    role = request.form['role']
    conn = get_db()
    try:
        conn.execute("INSERT INTO users VALUES (?, ?, ?, ?)",
                     (username, generate_password_hash(password),
                      role, datetime.now().strftime("%Y-%m-%d %H:%M")))
        conn.commit()
        msg, success = "User added successfully", True
    except sqlite3.IntegrityError:
        msg, success = "Username already exists", False
    finally:
        conn.close()
    conn = get_db()
    users = conn.execute(
        "SELECT username, role, created_at FROM users").fetchall()
    conn.close()
    return render_template('admin.html',
                           username=session['username'],
                           role=session['role'],
                           users=users,
                           msg=msg,
                           success=success,
                           session_username=session['username'])

@app.route('/admin/delete-user', methods=['POST'])
@admin_required
def delete_user():
    username = request.form['username']
    conn = get_db()
    if username == session['username']:
        users = conn.execute(
            "SELECT username, role, created_at FROM users").fetchall()
        conn.close()
        return render_template('admin.html',
                               username=session['username'],
                               role=session['role'],
                               users=users,
                               msg="Cannot delete your own account",
                               success=False,
                               session_username=session['username'])
    conn.execute("DELETE FROM users WHERE username=?", (username,))
    conn.commit()
    users = conn.execute(
        "SELECT username, role, created_at FROM users").fetchall()
    conn.close()
    return render_template('admin.html',
                           username=session['username'],
                           role=session['role'],
                           users=users,
                           msg=f"User {username} deleted",
                           success=True,
                           session_username=session['username'])

@app.route('/api/stats')
@login_required
def api_stats():
    try:
        res = es.search(index="modsecurity-clean", body={
            "size": 0,
            "aggs": {
                "attack_types": {
                    "terms": {"field": "attack_type", "size": 10}},
                "top_rules": {
                    "terms": {"field": "rule_id", "size": 10}},
                "over_time": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "calendar_interval": request.args.get('interval','hour')}}

            }
        })
        total = es.count(index="modsecurity-clean")['count']

        # Per website stats
        website_stats = {}
        for target in ['VulnApp', 'DVWA', 'WebGoat']:
            t_res = es.search(index="modsecurity-clean", body={
                "size": 0,
                "query": {"term": {"target": target}},
                "aggs": {
                    "types": {"terms": {"field": "attack_type", "size": 10}}
                }
            })
            t_count = es.count(index="modsecurity-clean", body={
                "query": {"term": {"target": target}}
            })['count']
            type_counts = {b['key']: b['doc_count']
                          for b in t_res['aggregations']['types']['buckets']}
            sql = type_counts.get('SQL Injection', 0)
            xss = type_counts.get('XSS', 0)
            lfi = type_counts.get('LFI/Path Traversal', 0)
            cmd = type_counts.get('Command Injection', 0)
            confirmed_attacks = sql + xss + lfi + cmd
            if t_count > 0:
                attack_ratio = confirmed_attacks / t_count
            else:
                attack_ratio = 0
            severity_score = (sql * 5 + xss * 3 + lfi * 3 + cmd * 4)
            if confirmed_attacks > 0:
                avg_severity = severity_score / confirmed_attacks
            else:
                avg_severity = 0
            risk_pct = min(int((attack_ratio * 50) + (avg_severity * 10)), 100)
            if risk_pct >= 67:
                risk_level = 'HIGH'
            elif risk_pct >= 50:
                risk_level = 'MEDIUM'
            else:
                risk_level = 'LOW'
            website_stats[target] = {
                'total': t_count,
                'sql': sql,
                'xss': xss,
                'lfi': lfi,
                'cmd': cmd,
                'risk_score': risk_pct,
                'risk_level': risk_level
            }

        # Get total attempts from nginx access log
        try:
            import glob
            total_lines = 0
            for logfile in glob.glob('/var/log/nginx/access.log*'):
                if logfile.endswith('.gz'):
                    import gzip
                    try:
                        with gzip.open(logfile, 'rt', errors='ignore') as f:
                            total_lines += sum(1 for _ in f)
                    except:
                        pass
                else:
                    try:
                        with open(logfile, 'r', errors='ignore') as f:
                            total_lines += sum(1 for _ in f)
                    except:
                        pass
            attempts = total_lines
        except:
            attempts = 0

        return jsonify({
            "total": total,
            "total_attempts": attempts,
            "attack_types": res['aggregations']['attack_types']['buckets'],
            "top_rules": res['aggregations']['top_rules']['buckets'],
            "over_time": res['aggregations']['over_time']['buckets'],
            "website_stats": website_stats
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/recent')
@login_required
def api_recent():
    try:
        res = es.search(index="modsecurity-clean", body={
            "size": 10,
            "sort": [{"@timestamp": "desc"}]
        })
        hits = [hit['_source'] for hit in res['hits']['hits']]
        return jsonify(hits)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/logs')
@login_required
def api_logs():
    try:
        size = int(request.args.get('size', 100))
        attack_type = request.args.get('attack_type', '')
        rule_id = request.args.get('rule_id', '')
        search = request.args.get('search', '')
        target = request.args.get('target', '')
        query = {"bool": {"must": []}}
        if attack_type:
            query["bool"]["must"].append(
                {"term": {"attack_type": attack_type}})
        if rule_id:
            query["bool"]["must"].append(
                {"term": {"rule_id": rule_id}})
        if search:
            query["bool"]["must"].append(
                {"match": {"message": search}})
        if target:
            query["bool"]["must"].append(
                {"term": {"target": target}})
        if not query["bool"]["must"]:
            query = {"match_all": {}}
        res = es.search(index="modsecurity-clean", body={
            "size": size,
            "sort": [{"@timestamp": "desc"}],
            "query": query
        })
        total = es.count(index="modsecurity-clean")['count']
        hits = [hit['_source'] for hit in res['hits']['hits']]
        return jsonify({"hits": hits, "total": total})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/predict', methods=['POST'])
@login_required
def api_predict():
    data = request.get_json()
    url = data.get('url', '')
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    label, risk_score = predict_url(url)

    # External verification
    vt_result = check_virustotal(url)
    gsb_result = check_google_safebrowsing(url)

    # Combined verdict
    is_malicious = (
        label == "Malicious" or
        (vt_result.get("malicious", 0) > 0) or
        (not gsb_result.get("safe", True))
    )
    final_verdict = "Malicious" if is_malicious else "Benign"

    return jsonify({
        "url": url,
        "label": label,
        "risk_score": risk_score,
        "virustotal": vt_result,
        "google_safebrowsing": gsb_result,
        "final_verdict": final_verdict,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

@app.route('/api/evaluation')
@login_required
def api_evaluation():
    try:
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import (accuracy_score, precision_score,
                                     recall_score, f1_score,
                                     confusion_matrix)
        res = es.search(index="modsecurity-clean", body={"size": 10000})
        data = []
        for hit in res['hits']['hits']:
            src = hit['_source']
            message = src.get('message', '')
            attack_type = src.get('attack_type', 'Other')
            BENIGN_TYPES = {'Protocol Anomaly', 'Anomaly Score', 'HTTP Violation', 'Other'}
            label = 0 if attack_type in BENIGN_TYPES else 1
            features = extract_features(message)
            data.append(features + [label])
        df = pd.DataFrame(data, columns=[
            'text_length', 'special_char_count', 'digit_count',
            'quote_count', 'equal_count', 'has_sql', 'has_xss',
            'has_lfi', 'has_cmd', 'label'])
        X = df.drop('label', axis=1)
        y = df['label']
        _, X_test, _, y_test = train_test_split(
            X, y, test_size=0.25, random_state=42)
        y_pred = model.predict(X_test)
        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel()
        importance = model.feature_importances_.tolist()
        return jsonify({
            "accuracy": float(accuracy_score(y_test, y_pred)),
            "precision": float(precision_score(
                y_test, y_pred, zero_division=0)),
            "recall": float(recall_score(
                y_test, y_pred, zero_division=0)),
            "f1": float(f1_score(y_test, y_pred, zero_division=0)),
            "tp": int(tp), "fp": int(fp),
            "fn": int(fn), "tn": int(tn),
            "feature_importance": importance,
            "report": [
                {"class": "Benign",
                 "precision": float(precision_score(
                     y_test, y_pred, pos_label=0, zero_division=0)),
                 "recall": float(recall_score(
                     y_test, y_pred, pos_label=0, zero_division=0)),
                 "f1": float(f1_score(
                     y_test, y_pred, pos_label=0, zero_division=0)),
                 "support": int((y_test == 0).sum())},
                {"class": "Malicious",
                 "precision": float(precision_score(
                     y_test, y_pred, zero_division=0)),
                 "recall": float(recall_score(
                     y_test, y_pred, zero_division=0)),
                 "f1": float(f1_score(
                     y_test, y_pred, zero_division=0)),
                 "support": int((y_test == 1).sum())}
            ]
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/parse-logs', methods=['POST'])
@login_required
def api_parse_logs():
    try:
        import subprocess
        result = subprocess.run(
            ['python3', '/app/parse_modsec.py'],
            capture_output=True, text=True)
        indexed = 0
        for line in result.stdout.split('\n'):
            if 'indexed' in line:
                nums = re.findall(r'\d+', line)
                if nums:
                    indexed = int(nums[0])
        return jsonify({"status": "done", "indexed": indexed})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/run-attacks', methods=['POST'])
@login_required
def api_run_attacks():
    try:
        import subprocess, time
        subprocess.Popen(['bash', '/app/attack.sh'])
        time.sleep(8)
        result = subprocess.run(
            ['python3', '/app/parse_modsec.py'],
            capture_output=True, text=True)
        indexed = 0
        for line in result.stdout.split('\n'):
            if 'indexed' in line:
                nums = re.findall(r'\d+', line)
                if nums:
                    indexed = int(nums[0])
        return jsonify({"status": "done", "indexed": indexed})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/retrain', methods=['POST'])
@admin_required
def api_retrain():
    try:
        import subprocess
        global model
        result = subprocess.run(
            ['python3', '/app/train_model.py'],
            capture_output=True, text=True,
            cwd='/home/amelia/SENTINEL/waf_flask')
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
        f1 = 0.0
        for line in result.stdout.split('\n'):
            if '1' in line and 'f1-score' not in line.lower():
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        f1 = float(parts[3])
                    except:
                        pass
        return jsonify({"status": "done", "f1": f1})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/history', methods=['GET'])
@login_required
def api_history_get():
    try:
        conn = get_db()
        rows = conn.execute(
            "SELECT url, label, risk_score, timestamp FROM analysis_history WHERE username=? ORDER BY id DESC LIMIT 50",
            (session['username'],)).fetchall()
        conn.close()
        return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/history', methods=['POST'])
@login_required
def api_history_post():
    try:
        data = request.get_json()
        conn = get_db()
        conn.execute(
            "INSERT INTO analysis_history (username, url, label, risk_score, timestamp) VALUES (?,?,?,?,?)",
            (session['username'], data['url'], data['label'],
             data['risk_score'], data['timestamp']))
        conn.commit()
        conn.close()
        return jsonify({"status": "saved"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/history/clear', methods=['POST'])
@login_required
def api_history_clear():
    try:
        conn = get_db()
        conn.execute("DELETE FROM analysis_history WHERE username=?",
                     (session['username'],))
        conn.commit()
        conn.close()
        return jsonify({"status": "cleared"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=5000)
