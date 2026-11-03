# Nginx

Runtime Nginx configuration is rendered from `deploy/templates/nginx.conf.tpl` by `deploy/install.sh`.

Do not commit production TLS private keys. Target-specific FQDN/IP/certificate paths belong in `/etc/security-web-gateway`, not in Git.
