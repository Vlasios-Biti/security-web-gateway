upstream swg_manager {
    server 127.0.0.1:8200;
    keepalive 16;
}

server {
    listen __BIND_IP__:443 ssl;
    server_name __FQDN__;
    server_tokens off;

    ssl_certificate __TLS_CERT__;
    ssl_certificate_key __TLS_KEY__;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:SWGSSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    add_header Strict-Transport-Security "max-age=31536000" always;
    client_max_body_size 12m;
    access_log /var/log/nginx/security-web-gateway-access.log;
    error_log /var/log/nginx/security-web-gateway-error.log warn;

    location / {
        proxy_pass http://swg_manager;
        proxy_http_version 1.1;
        proxy_set_header Connection "";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_connect_timeout 3s;
        proxy_send_timeout 30s;
        proxy_read_timeout 15s;
    }
}

server {
    listen __BIND_IP__:8081;
    server_name _;
    server_tokens off;
    access_log /var/log/nginx/security-web-gateway-pac-access.log;

    location = /proxy.pac {
        alias /etc/security-web-gateway/proxy.pac;
        default_type application/x-ns-proxy-autoconfig;
        add_header Cache-Control "no-cache, no-store, must-revalidate" always;
        add_header Pragma "no-cache" always;
        expires -1;
    }

    location / { return 404; }
}
