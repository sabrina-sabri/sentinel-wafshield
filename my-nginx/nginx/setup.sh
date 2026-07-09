#!/bin/sh

# Fix ModSecurity audit log path
sed -i 's|SecAuditLog /dev/stdout|SecAuditLog /var/log/nginx/modsec_audit.log|' /etc/modsecurity.d/modsecurity.conf

# Disable rule 920350
echo "SecRuleRemoveById 920350" >> /etc/modsecurity.d/modsecurity-override.conf

# Apply custom nginx routing config
cat > /etc/nginx/conf.d/default.conf << 'NGINXEOF'
server_tokens off;
map $http_upgrade $connection_upgrade {
    default upgrade;
    '' close;
}
server {
    listen 8080 default_server;
    server_name sentinel.fskm.amy 10.82.8.65;

    location /dvwa/ {
        proxy_pass http://amy_dvwa:80/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /WebGoat/ {
        proxy_pass http://amy_webgoat:8080/WebGoat/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /vulnapp/ {
        proxy_pass http://amy_vulnapp:80/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /dashboard {
        modsecurity off;
        proxy_pass http://amy_flask:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /api/ {
        modsecurity off;
        proxy_pass http://amy_flask:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /static/ {
        modsecurity off;
        proxy_pass http://amy_flask:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /ml-analysis {
        modsecurity off;
        proxy_pass http://amy_flask:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /evaluation {
        modsecurity off;
        proxy_pass http://amy_flask:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /logs {
        modsecurity off;
        proxy_pass http://amy_flask:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /admin {
        modsecurity off;
        proxy_pass http://amy_flask:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /signup {
        modsecurity off;
        proxy_pass http://amy_flask:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location / {
        proxy_pass http://amy_flask:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        client_max_body_size 0;
    }
}
NGINXEOF
touch /var/log/nginx/modsec_audit.log
chmod 666 /var/log/nginx/modsec_audit.log
echo "Setup complete"
