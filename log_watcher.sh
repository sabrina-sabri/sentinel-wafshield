#!/bin/bash
echo "👁️  Log Watcher Started — monitoring /var/log/modsec_audit.log"
LAST_SIZE=0
cd /home/amelia/SENTINEL
source waf_flask/venv/bin/activate

while true; do
    CURRENT_SIZE=$(stat -c%s /var/log/modsec_audit.log 2>/dev/null || echo 0)
    if [ "$CURRENT_SIZE" -gt "$LAST_SIZE" ]; then
        echo "$(date): New logs detected — parsing..."
        python3 parse_modsec.py
        LAST_SIZE=$CURRENT_SIZE
        echo "$(date): Done parsing"
    fi
    sleep 5
done
