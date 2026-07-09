FROM owasp/modsecurity-crs:nginx
USER root
COPY nginx/setup.sh /docker-entrypoint.d/99-custom-setup.sh
RUN chmod +x /docker-entrypoint.d/99-custom-setup.sh
