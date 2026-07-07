#!/bin/bash
echo "🛑 Stopping SENTINEL WAFShield AI..."

if [ -f /tmp/flask.pid ]; then
    kill $(cat /tmp/flask.pid) 2>/dev/null
    rm /tmp/flask.pid
fi
pkill -f "python app.py" 2>/dev/null
echo "✅ Flask stopped"

if [ -f /tmp/watcher.pid ]; then
    kill $(cat /tmp/watcher.pid) 2>/dev/null
    rm /tmp/watcher.pid
    echo "✅ Log watcher stopped"
fi

sudo docker stop sqli-web sqli-db sqli-phpmyadmin elasticsearch 2>/dev/null
echo "✅ Docker containers stopped"

sudo systemctl stop nginx
echo "✅ Nginx stopped"

echo "========================================"
echo "🛑 SENTINEL WAFShield AI stopped"
echo "========================================"
