#!/bin/bash
echo "🛡️  Starting SENTINEL WAFShield AI..."
echo "========================================"

# Step 1 - Start Docker containers
echo "[1/5] Starting Docker containers..."
sudo docker start elasticsearch
sleep 30
cd /home/amelia/SENTINEL/victim1 && sudo docker-compose up -d 2>/dev/null || true
echo "✅ Docker containers started"

# Step 2 - Wait for Elasticsearch
echo "[2/5] Waiting for Elasticsearch..."
sleep 20
until curl -s "localhost:9200" > /dev/null 2>&1; do
    echo "    Waiting..."
    sleep 5
done
echo "✅ Elasticsearch is ready"

# Step 3 - Start Nginx
echo "[3/5] Starting Nginx..."
sudo systemctl start nginx
sudo systemctl status nginx --no-pager | grep "Active"
echo "✅ Nginx started"

# Step 4 - Start Flask
echo "[4/5] Starting Flask dashboard..."
pkill -f "python app.py" 2>/dev/null
sleep 2
cd /home/amelia/SENTINEL/waf_flask
/home/amelia/SENTINEL/waf_flask/venv/bin/python3 app.py > /tmp/flask.log 2>&1 &
FLASK_PID=$!
echo $FLASK_PID > /tmp/flask.pid
sleep 8
echo "✅ Flask started (PID: $FLASK_PID)"

# Start log watcher in background
echo "Starting log watcher..."
nohup bash /home/amelia/SENTINEL/log_watcher.sh > /tmp/watcher.log 2>&1 &
echo $! > /tmp/watcher.pid
echo "✅ Log watcher started"

# Step 5 - Status check
echo "[5/5] Checking all services..."
sleep 20
echo ""
echo "========================================"
echo "🛡️  SENTINEL WAFShield AI is RUNNING"
echo "========================================"
echo ""
echo "📊 Dashboard:    http://192.168.25.200:5000"
echo "🎯 VulnApp:      http://192.168.25.200/vulnapp/"
echo "🔍 phpMyAdmin:   http://192.168.25.200:8081"
echo "🔓 DVWA:         http://192.168.25.200/dvwa/"
echo "🐐 WebGoat:      http://192.168.25.200/webgoat/login"
echo ""
echo "Services Status:"
curl -s "localhost:9200" > /dev/null 2>&1 && echo "  ✅ Elasticsearch  → Running" || echo "  ❌ Elasticsearch  → Failed"
systemctl is-active nginx > /dev/null 2>&1 && echo "  ✅ Nginx + WAF    → Running" || echo "  ❌ Nginx + WAF    → Failed"
curl -s "localhost:5000" > /dev/null 2>&1 && echo "  ✅ Flask Dashboard → Running" || echo "  ❌ Flask Dashboard → Failed"
curl -s "localhost:8080" > /dev/null 2>&1 && echo "  ✅ VulnApp        → Running" || echo "  ❌ VulnApp        → Failed"
curl -s "localhost:8082" > /dev/null 2>&1 && echo "  ✅ DVWA           → Running" || echo "  ❌ DVWA           → Failed"
curl -s "http://192.168.25.200:8083/WebGoat/login" > /dev/null 2>&1 && echo "  ✅ WebGoat        → Running" || echo "  ❌ WebGoat        → Failed"
echo ""
echo "Logs: tail -f /tmp/flask.log"
echo "Stop: bash /home/amelia/stop_sentinel.sh"
echo "========================================"
