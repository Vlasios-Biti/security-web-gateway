#!/usr/bin/env bash
set -Eeuo pipefail

VERSION="$(cat "$(cd "$(dirname "$0")/.." && pwd)/VERSION")"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FQDN=""
BIND_IP=""
PROXY_PORT=3128
DNS_SERVERS=""
TLS_CERT=""
TLS_KEY=""
SELF_SIGNED=0
SKIP_BROWSER=0
ADMIN_USER="admin"
INTERNAL_DOMAIN_SUFFIX=""
LOCAL_DNS_CACHE=1

usage(){ cat <<USAGE
Usage: sudo ./deploy/install.sh --fqdn FQDN --bind-ip IP [options]

Required:
  --fqdn NAME              Management FQDN (example: proxy.example.internal)
  --bind-ip IP             Server IPv4 address to bind Nginx/Squid

TLS (choose one):
  --tls-cert FILE --tls-key FILE
  --self-signed            Bootstrap/test only; replace with trusted internal/public CA certificate

Options:
  --proxy-port N           Default: 3128
  --dns-servers A,B        Optional; defaults to resolvers detected from the host
  --admin-user NAME        Initial admin username; default: admin
  --internal-domain-suffix SUFFIX  Optional direct-bypass DNS suffix, e.g. .corp.internal
  --skip-browser-runtime   Skip Playwright/Chromium installation
  --no-local-dns-cache     Do not configure loopback Unbound cache for Squid
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --fqdn) FQDN="$2"; shift 2;;
    --bind-ip) BIND_IP="$2"; shift 2;;
    --proxy-port) PROXY_PORT="$2"; shift 2;;
    --dns-servers) DNS_SERVERS="$2"; shift 2;;
    --tls-cert) TLS_CERT="$2"; shift 2;;
    --tls-key) TLS_KEY="$2"; shift 2;;
    --self-signed) SELF_SIGNED=1; shift;;
    --skip-browser-runtime) SKIP_BROWSER=1; shift;;
    --admin-user) ADMIN_USER="$2"; shift 2;;
    --internal-domain-suffix) INTERNAL_DOMAIN_SUFFIX="$2"; shift 2;;
    --no-local-dns-cache) LOCAL_DNS_CACHE=0; shift;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown option: $1" >&2; usage; exit 2;;
  esac
done

[[ $EUID -eq 0 ]] || { echo "ERROR: run as root." >&2; exit 1; }
[[ -n "$FQDN" && -n "$BIND_IP" ]] || { usage; exit 2; }
python3 - "$BIND_IP" <<'PY'
import ipaddress,sys
ip=ipaddress.ip_address(sys.argv[1])
if ip.version!=4: raise SystemExit('bind-ip must be IPv4')
PY
[[ "$PROXY_PORT" =~ ^[0-9]+$ ]] && (( PROXY_PORT>=1 && PROXY_PORT<=65535 )) || { echo "Invalid proxy port"; exit 2; }

if [[ $SELF_SIGNED -eq 0 ]]; then
  [[ -f "$TLS_CERT" && -f "$TLS_KEY" ]] || { echo "ERROR: provide --tls-cert and --tls-key, or explicitly use --self-signed." >&2; exit 2; }
fi

if [[ -f /etc/os-release ]]; then . /etc/os-release; fi
if [[ "${ID:-}" != "ubuntu" ]]; then echo "WARNING: installer is validated for Ubuntu 24.04 LTS; detected ${PRETTY_NAME:-unknown}."; fi

for port in 443 8081 "$PROXY_PORT"; do
  if ss -lnt 2>/dev/null | awk '{print $4}' | grep -Eq "(^|:)$port$"; then
    echo "ERROR: TCP/$port already has a listener. Fresh install aborted." >&2
    exit 1
  fi
done

echo "===== 1. PACKAGES ====="
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-venv python3-pip nginx squid sqlite3 curl ca-certificates openssl rsync sudo bind9-dnsutils sysstat
if [[ $LOCAL_DNS_CACHE -eq 1 ]]; then
  DEBIAN_FRONTEND=noninteractive apt-get install -y unbound
fi

echo "===== 2. SERVICE ACCOUNT / DIRECTORIES ====="
getent group proxy >/dev/null || groupadd --system proxy
if ! id proxy-mgmt >/dev/null 2>&1; then
  useradd --system --home-dir /var/lib/security-web-gateway --create-home --shell /usr/sbin/nologin --gid proxy-mgmt proxy-mgmt 2>/dev/null || {
    getent group proxy-mgmt >/dev/null || groupadd --system proxy-mgmt
    useradd --system --home-dir /var/lib/security-web-gateway --create-home --shell /usr/sbin/nologin --gid proxy-mgmt proxy-mgmt
  }
fi
usermod -a -G proxy proxy-mgmt
install -d -o root -g proxy-mgmt -m 0750 /opt/security-web-gateway/releases /etc/security-web-gateway /etc/security-web-gateway/tls
install -d -o proxy-mgmt -g proxy-mgmt -m 0750 /var/lib/security-web-gateway/prod /var/lib/security-web-gateway/staging /var/lib/security-web-gateway/playwright /var/log/security-web-gateway
install -d -o root -g proxy -m 0750 /var/lib/security-web-gateway/backups /etc/squid/managed

echo "===== 3. RELEASE + PYTHON RUNTIME ====="
REL="/opt/security-web-gateway/releases/$VERSION"
rm -rf "$REL"; install -d -o root -g proxy-mgmt -m 0750 "$REL"
rsync -a --delete \
  --exclude '__pycache__' --exclude '*.pyc' \
  "$ROOT/app" "$ROOT/bin" "$ROOT/migrations" "$ROOT/static" "$ROOT/templates" "$ROOT/tools" "$ROOT/requirements.txt" "$REL/"
chown -R root:proxy-mgmt "$REL"
find "$REL" -type d -exec chmod 0750 {} +
find "$REL" -type f -exec chmod 0640 {} +
find "$REL/bin" "$REL/tools" -type f -name '*.py' -exec chmod 0750 {} +

if [[ ! -x /opt/security-web-gateway/venv/bin/python ]]; then python3 -m venv /opt/security-web-gateway/venv; fi
/opt/security-web-gateway/venv/bin/pip install --upgrade pip
/opt/security-web-gateway/venv/bin/pip install -r "$REL/requirements.txt"

if [[ $SKIP_BROWSER -eq 0 ]]; then
  echo "===== 4. ISOLATED CHROMIUM RUNTIME ====="
  /opt/security-web-gateway/venv/bin/python -m playwright install-deps chromium
  runuser -u proxy-mgmt -- env PLAYWRIGHT_BROWSERS_PATH=/var/lib/security-web-gateway/playwright /opt/security-web-gateway/venv/bin/python -m playwright install chromium
else
  echo "WARNING: browser discovery runtime skipped. Other SWG functions remain available."
fi

echo "===== 5. TLS ====="
if [[ $SELF_SIGNED -eq 1 ]]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 30 \
    -subj "/CN=$FQDN" -addext "subjectAltName=DNS:$FQDN,IP:$BIND_IP" \
    -keyout /etc/security-web-gateway/tls/management.key -out /etc/security-web-gateway/tls/management.crt
else
  install -o root -g root -m 0644 "$TLS_CERT" /etc/security-web-gateway/tls/management.crt
  install -o root -g root -m 0600 "$TLS_KEY" /etc/security-web-gateway/tls/management.key
fi
chmod 0600 /etc/security-web-gateway/tls/management.key

echo "===== 6. PRODUCTION ENV ====="
if [[ -z "$DNS_SERVERS" ]]; then
  if command -v resolvectl >/dev/null 2>&1; then
    DNS_SERVERS="$(resolvectl dns 2>/dev/null | awk '{for(i=3;i<=NF;i++) if ($i ~ /^([0-9]{1,3}\.){3}[0-9]{1,3}$/ || $i ~ /:/) print $i}' | grep -Ev '^(127\.|::1$)' | awk '!seen[$0]++' | paste -sd, -)"
  fi
  if [[ -z "$DNS_SERVERS" ]]; then
    DNS_SERVERS="$(awk '/^nameserver[[:space:]]+/ {print $2}' /etc/resolv.conf 2>/dev/null | grep -Ev '^(127\.|::1$)' | awk '!seen[$0]++' | paste -sd, -)"
  fi
  [[ -n "$DNS_SERVERS" ]] || { echo "ERROR: no non-loopback DNS resolvers detected. Supply --dns-servers explicitly." >&2; exit 1; }
fi

SQUID_DNS_SERVERS="$DNS_SERVERS"
if [[ $LOCAL_DNS_CACHE -eq 1 ]]; then
  echo "===== 6A. LOCAL DNS CACHE ====="
  # Package installation may auto-start Unbound. Stop our intended service first,
  # then detect only a genuine third-party conflict on 127.0.0.1:53.
  systemctl stop unbound 2>/dev/null || true
  if ss -lntup 2>/dev/null | grep -Eq '127\.0\.0\.1:53[[:space:]]'; then
    echo "WARNING: 127.0.0.1:53 is already in use by another service; local DNS cache disabled."
    LOCAL_DNS_CACHE=0
    systemctl disable unbound 2>/dev/null || true
  else
    python3 - "$DNS_SERVERS" "$ROOT/deploy/templates/unbound.conf.tpl" /etc/unbound/unbound.conf.d/security-web-gateway.conf <<'PYDNS'
import sys
servers=[x.strip() for x in sys.argv[1].split(',') if x.strip()]
template=open(sys.argv[2],encoding='utf-8').read()
forward='\n'.join(f'    forward-addr: {x}' for x in servers)
open(sys.argv[3],'w',encoding='utf-8').write(template.replace('__UNBOUND_FORWARD_ADDRS__',forward))
PYDNS
    unbound-checkconf
    systemctl enable --now unbound
    if dig @127.0.0.1 google.com A +time=2 +tries=1 +short | grep -q .; then
      SQUID_DNS_SERVERS="127.0.0.1"
    else
      echo "WARNING: local DNS cache health check failed; falling back to enterprise DNS servers."
      LOCAL_DNS_CACHE=0
      systemctl disable --now unbound 2>/dev/null || true
    fi
  fi
fi
cat > /etc/security-web-gateway/production.env <<ENV
SWG_MODE=production
SWG_SERVICE_NAME=security-web-gateway
SWG_DATA_ROOT=/var/lib/security-web-gateway/prod
SWG_DB_PATH=/var/lib/security-web-gateway/prod/swg.db
SWG_BACKUP_ROOT=/var/lib/security-web-gateway/backups
SWG_LIVE_MANAGED_CONF=/etc/squid/managed/security-web-gateway.conf
SWG_SQUID_CONF=/etc/squid/squid.conf
SWG_SQUID_ACCESS_LOG=/var/log/squid/access.log
SWG_SQUID_LOG_DIR=/var/log/squid
SWG_DEPLOY_SOCKET=/run/security-web-gateway-deploy.sock
SWG_PROXY_IP=$BIND_IP
SWG_PROXY_PORT=$PROXY_PORT
SWG_FQDN=$FQDN
SWG_DNS_SERVERS=$DNS_SERVERS
SWG_LOCAL_DNS_CACHE=$LOCAL_DNS_CACHE
SWG_LOCAL_DNS_IP=127.0.0.1
SWG_SESSION_TOUCH_INTERVAL_SECONDS=60
SWG_DASHBOARD_CACHE_TTL_SECONDS=20
SWG_TELEMETRY_BATCH_MAX=10000
SWG_SESSION_COOKIE=swg_session
PLAYWRIGHT_BROWSERS_PATH=/var/lib/security-web-gateway/playwright
SWG_DISCOVERY_MAX_HAR_BYTES=10485760
SWG_DISCOVERY_BROWSER_TIMEOUT_MS=20000
SWG_DISCOVERY_BROWSER_MAX_PAGES=6
ENV
chown root:proxy-mgmt /etc/security-web-gateway/production.env; chmod 0640 /etc/security-web-gateway/production.env
ln -sfn "$REL" /opt/security-web-gateway/current

echo "===== 7. DATABASE ====="
runuser -u proxy-mgmt -- env $(grep -v '^#' /etc/security-web-gateway/production.env | xargs) PYTHONPATH="$REL" \
  /opt/security-web-gateway/venv/bin/python "$REL/tools/migrate.py" --db /var/lib/security-web-gateway/prod/swg.db --root "$REL"
chown proxy-mgmt:proxy-mgmt /var/lib/security-web-gateway/prod/swg.db; chmod 0640 /var/lib/security-web-gateway/prod/swg.db

echo "===== 8. INITIAL MANAGED POLICY ====="
TMP_CONF=/var/lib/security-web-gateway/prod/security-web-gateway.initial.conf
runuser -u proxy-mgmt -- env $(grep -v '^#' /etc/security-web-gateway/production.env | xargs) PYTHONPATH="$REL" \
  /opt/security-web-gateway/venv/bin/python "$REL/tools/render_config.py" --output "$TMP_CONF"
install -o root -g proxy -m 0640 "$TMP_CONF" /etc/squid/managed/security-web-gateway.conf
rm -f "$TMP_CONF"

echo "===== 9. SQUID + PAC + NGINX ====="
SQUID_DNS_SPACE="${SQUID_DNS_SERVERS//,/ }"
sed -e "s|__FQDN__|$FQDN|g" -e "s|__BIND_IP__|$BIND_IP|g" -e "s|__PROXY_PORT__|$PROXY_PORT|g" -e "s|__SQUID_DNS_SERVERS_SPACE__|$SQUID_DNS_SPACE|g" \
  "$ROOT/deploy/templates/squid.conf.tpl" > /etc/squid/squid.conf
chown root:proxy /etc/squid/squid.conf; chmod 0640 /etc/squid/squid.conf

sed -e "s|__PROXY_IP__|$BIND_IP|g" -e "s|__PROXY_PORT__|$PROXY_PORT|g" -e "s|__INTERNAL_DOMAIN_SUFFIX__|$INTERNAL_DOMAIN_SUFFIX|g" "$ROOT/pac/proxy.pac.tpl" > /etc/security-web-gateway/proxy.pac
chown root:proxy-mgmt /etc/security-web-gateway/proxy.pac; chmod 0644 /etc/security-web-gateway/proxy.pac

sed -e "s|__FQDN__|$FQDN|g" -e "s|__BIND_IP__|$BIND_IP|g" \
    -e "s|__TLS_CERT__|/etc/security-web-gateway/tls/management.crt|g" -e "s|__TLS_KEY__|/etc/security-web-gateway/tls/management.key|g" \
  "$ROOT/deploy/templates/nginx.conf.tpl" > /etc/nginx/sites-available/security-web-gateway
ln -sfn /etc/nginx/sites-available/security-web-gateway /etc/nginx/sites-enabled/security-web-gateway
rm -f /etc/nginx/sites-enabled/default

/usr/sbin/squid -k parse
/usr/sbin/nginx -t
systemctl restart squid
systemctl restart nginx
# Ensure the telemetry service account can read the active Squid log via proxy group.
chown proxy:proxy /var/log/squid 2>/dev/null || true
chmod 0770 /var/log/squid 2>/dev/null || true
[[ -e /var/log/squid/access.log ]] && chown proxy:proxy /var/log/squid/access.log && chmod 0640 /var/log/squid/access.log || true

echo "===== 10. PRIVILEGED HELPER + SYSTEMD ====="
install -o root -g root -m 0750 "$ROOT/privileged/security-web-gateway-deploy-helper.py" /usr/local/sbin/security-web-gateway-deploy-helper
install -o root -g root -m 0644 "$ROOT/privileged/security-web-gateway-deploy-helper.socket" /etc/systemd/system/security-web-gateway-deploy-helper.socket
install -o root -g root -m 0644 "$ROOT/privileged/security-web-gateway-deploy-helper@.service" /etc/systemd/system/security-web-gateway-deploy-helper@.service
for f in security-web-gateway.service security-web-gateway-source-sync.service security-web-gateway-source-sync.timer security-web-gateway-telemetry.service security-web-gateway-telemetry.timer security-web-gateway-storage-maintenance.service security-web-gateway-storage-maintenance.timer security-web-gateway-discovery.service security-web-gateway-discovery.timer security-web-gateway-performance.service security-web-gateway-performance.timer; do
  install -o root -g root -m 0644 "$ROOT/systemd/$f" "/etc/systemd/system/$f"
done
install -d -o root -g root -m 0755 /etc/systemd/system/squid.service.d
install -o root -g root -m 0644 "$ROOT/systemd/squid-priority.conf" /etc/systemd/system/squid.service.d/10-security-web-gateway-priority.conf
systemctl daemon-reload
systemctl restart squid
systemctl enable --now security-web-gateway-deploy-helper.socket
systemctl enable --now security-web-gateway.service
systemctl enable --now security-web-gateway-source-sync.timer security-web-gateway-telemetry.timer security-web-gateway-storage-maintenance.timer security-web-gateway-discovery.timer security-web-gateway-performance.timer

for i in $(seq 1 30); do curl -fsS http://127.0.0.1:8200/healthz >/tmp/security-web-gateway-health.json 2>/dev/null && break; sleep 1; done
cat /tmp/security-web-gateway-health.json
grep -q "\"version\":\"$VERSION\"" /tmp/security-web-gateway-health.json
runuser -u proxy-mgmt -- env $(grep -v '^#' /etc/security-web-gateway/production.env | xargs) PYTHONPATH="$REL" /opt/security-web-gateway/venv/bin/python "$REL/bin/collect_performance.py" >/dev/null 2>&1 || true
runuser -u proxy-mgmt -- env $(grep -v '^#' /etc/security-web-gateway/production.env | xargs) PYTHONPATH="$REL" /opt/security-web-gateway/venv/bin/python "$REL/bin/collect_telemetry.py" --max-events 10000 >/dev/null 2>&1 || true

echo "===== 11. INITIAL ADMIN ====="
if ! sqlite3 /var/lib/security-web-gateway/prod/swg.db "SELECT 1 FROM users LIMIT 1" | grep -q 1; then
  echo "Create the initial administrator now. Password must be at least 14 characters."
  runuser -u proxy-mgmt -- env $(grep -v '^#' /etc/security-web-gateway/production.env | xargs) PYTHONPATH="$REL" \
    /opt/security-web-gateway/venv/bin/python "$REL/bin/create_user.py" "$ADMIN_USER" admin
fi

echo
echo "============================================================"
echo "Security Web Gateway v$VERSION installed"
echo "GUI:      https://$FQDN"
echo "PAC:      http://$BIND_IP:8081/proxy.pac"
echo "Proxy:    $BIND_IP:$PROXY_PORT"
echo "Policy:   DEFAULT DENY"
echo "Fail-open PAC: PROXY $BIND_IP:$PROXY_PORT; DIRECT"
echo "============================================================"
if [[ $SELF_SIGNED -eq 1 ]]; then echo "WARNING: bootstrap self-signed TLS is active. Replace it with a trusted certificate before production rollout."; fi
