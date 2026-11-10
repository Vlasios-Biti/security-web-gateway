#!/usr/bin/env bash
set -Eeuo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SWG_VERSION="$(cat "$ROOT/VERSION")"
REL="/opt/security-web-gateway/releases/$SWG_VERSION"
VENV="/opt/security-web-gateway/venv"
PDB="/var/lib/security-web-gateway/prod/swg.db"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP="/var/lib/security-web-gateway/backups/release-upgrade-$STAMP"
OLD_REL=""
CUTOVER=0
SUCCESS=0
SKIP_BROWSER=0

[[ "${1:-}" == "--confirm" ]] || { echo "Usage: sudo ./deploy/upgrade.sh --confirm [--skip-browser-runtime]"; exit 2; }
shift
while [[ $# -gt 0 ]]; do case "$1" in --skip-browser-runtime) SKIP_BROWSER=1; shift;; *) echo "Unknown option: $1"; exit 2;; esac; done
[[ $EUID -eq 0 ]] || { echo "ERROR: run as root"; exit 1; }

rollback(){
  rc=$?; trap - ERR EXIT
  if [[ $SUCCESS -eq 1 || $CUTOVER -eq 0 ]]; then exit "$rc"; fi
  echo "ERROR: upgrade failed; rolling back..." >&2
  systemctl stop security-web-gateway.service security-web-gateway-health-monitor.service security-web-gateway-discovery.service security-web-gateway-telemetry.service security-web-gateway-performance.service security-web-gateway-source-sync.service security-web-gateway-storage-maintenance.service 2>/dev/null || true
  systemctl stop security-web-gateway-telemetry.timer security-web-gateway-source-sync.timer security-web-gateway-storage-maintenance.timer security-web-gateway-discovery.timer security-web-gateway-performance.timer security-web-gateway-health-monitor.timer 2>/dev/null || true
  if [[ -f "$BACKUP/swg.db" ]]; then
    rm -f "$PDB" "$PDB-wal" "$PDB-shm"; cp -a "$BACKUP/swg.db" "$PDB"; chown proxy-mgmt:proxy-mgmt "$PDB"; chmod 0640 "$PDB"
  fi
  if [[ -n "$OLD_REL" && -d "$OLD_REL" ]]; then ln -sfn "$OLD_REL" /opt/security-web-gateway/current; fi
  for f in "$BACKUP"/*.service "$BACKUP"/*.timer "$BACKUP"/security-web-gateway-deploy-helper.socket; do [[ -f "$f" ]] && cp -a "$f" /etc/systemd/system/; done
  if [[ -f "$BACKUP/security-web-gateway-deploy-helper" ]]; then
    install -o root -g root -m 0750 "$BACKUP/security-web-gateway-deploy-helper" /usr/local/sbin/security-web-gateway-deploy-helper
  fi
  if [[ -f "$BACKUP/squid-priority.conf" ]]; then
    install -d -o root -g root -m 0755 /etc/systemd/system/squid.service.d
    cp -a "$BACKUP/squid-priority.conf" /etc/systemd/system/squid.service.d/10-security-web-gateway-priority.conf
  else
    rm -f /etc/systemd/system/squid.service.d/10-security-web-gateway-priority.conf
  fi
  if [[ ! -f "$BACKUP/security-web-gateway-health-monitor.service" ]]; then
    systemctl disable security-web-gateway-health-monitor.timer 2>/dev/null || true
    rm -f /etc/systemd/system/security-web-gateway-health-monitor.service /etc/systemd/system/security-web-gateway-health-monitor.timer
  fi
  systemctl daemon-reload
  systemctl restart security-web-gateway-deploy-helper.socket 2>/dev/null || true
  systemctl start security-web-gateway.service 2>/dev/null || true
  systemctl start security-web-gateway-source-sync.timer \
    security-web-gateway-telemetry.timer \
    security-web-gateway-storage-maintenance.timer \
    security-web-gateway-discovery.timer \
    security-web-gateway-performance.timer 2>/dev/null || true
  if [[ -f "$BACKUP/security-web-gateway-health-monitor.timer" ]]; then systemctl start security-web-gateway-health-monitor.timer 2>/dev/null || true; fi
  echo "Rollback source: $BACKUP" >&2
  exit "$rc"
}
trap rollback ERR EXIT

echo "===== 1. PRE-CHECK ====="
[[ -x "$VENV/bin/python" ]] || { echo "Missing SWG virtualenv"; exit 1; }
[[ -f "$PDB" ]] || { echo "Missing production database"; exit 1; }
[[ -f /etc/security-web-gateway/production.env ]] || { echo "Missing production.env"; exit 1; }
OLD_REL="$(readlink -f /opt/security-web-gateway/current || true)"
[[ -n "$OLD_REL" && -d "$OLD_REL" ]] || { echo "Invalid current release"; exit 1; }
[[ "$OLD_REL" != "$REL" ]] || { echo "This version is already active; use a new release version for upgrades."; exit 1; }
systemctl is-active --quiet security-web-gateway.service
curl -fsS http://127.0.0.1:8200/healthz

echo "===== 2. BACKUP ====="
install -d -o root -g root -m 0700 "$BACKUP"
python3 - "$PDB" "$BACKUP/swg.db" <<'PY'
import sqlite3,sys
s=sqlite3.connect(sys.argv[1]);d=sqlite3.connect(sys.argv[2]);s.backup(d);d.close();s.close()
PY
cp -a /etc/security-web-gateway/production.env "$BACKUP/production.env"
cp -a /etc/squid/managed/security-web-gateway.conf "$BACKUP/security-web-gateway.conf" 2>/dev/null || true
for f in /etc/systemd/system/security-web-gateway*.service /etc/systemd/system/security-web-gateway*.timer /etc/systemd/system/security-web-gateway-deploy-helper.socket; do [[ -f "$f" ]] && cp -a "$f" "$BACKUP/"; done
[[ -f /usr/local/sbin/security-web-gateway-deploy-helper ]] && cp -a /usr/local/sbin/security-web-gateway-deploy-helper "$BACKUP/security-web-gateway-deploy-helper"
echo "$OLD_REL" > "$BACKUP/previous-release"
if [[ -f /etc/systemd/system/squid.service.d/10-security-web-gateway-priority.conf ]]; then cp -a /etc/systemd/system/squid.service.d/10-security-web-gateway-priority.conf "$BACKUP/squid-priority.conf"; fi

echo "===== 3. STAGE RELEASE ====="
rm -rf "$REL"; install -d -o root -g proxy-mgmt -m 0750 "$REL"
rsync -a --delete --exclude '__pycache__' --exclude '*.pyc' "$ROOT/app" "$ROOT/bin" "$ROOT/migrations" "$ROOT/static" "$ROOT/templates" "$ROOT/tools" "$ROOT/privileged" "$ROOT/requirements.txt" "$ROOT/VERSION" "$REL/"
chown -R root:proxy-mgmt "$REL"; find "$REL" -type d -exec chmod 0750 {} +; find "$REL" -type f -exec chmod 0640 {} +; find "$REL/bin" "$REL/tools" -type f -name '*.py' -exec chmod 0750 {} +
"$VENV/bin/pip" install -r "$REL/requirements.txt"
if [[ $SKIP_BROWSER -eq 0 ]]; then
  "$VENV/bin/python" -m playwright install-deps chromium
  install -d -o proxy-mgmt -g proxy-mgmt -m 0750 /var/lib/security-web-gateway/playwright
  runuser -u proxy-mgmt -- env PLAYWRIGHT_BROWSERS_PATH=/var/lib/security-web-gateway/playwright "$VENV/bin/python" -m playwright install chromium
fi

echo "===== 4. SHADOW MIGRATION / VALIDATION ====="
SHADOW="/var/lib/security-web-gateway/staging/v${SWG_VERSION}-${STAMP}.db"
install -d -o proxy-mgmt -g proxy-mgmt -m 0750 /var/lib/security-web-gateway/staging
python3 - "$PDB" "$SHADOW" <<'PY'
import sqlite3,sys
s=sqlite3.connect(sys.argv[1]);d=sqlite3.connect(sys.argv[2]);s.backup(d);d.close();s.close()
PY
chown proxy-mgmt:proxy-mgmt "$SHADOW"; chmod 0640 "$SHADOW"
runuser -u proxy-mgmt -- env $(grep -v '^#' /etc/security-web-gateway/production.env | xargs) PYTHONPATH="$REL" SWG_DB_PATH="$SHADOW" \
  "$VENV/bin/python" "$REL/tools/migrate.py" --db "$SHADOW" --root "$REL"
runuser -u proxy-mgmt -- env $(grep -v '^#' /etc/security-web-gateway/production.env | xargs) PYTHONPATH="$REL" SWG_DB_PATH="$SHADOW" \
  "$VENV/bin/python" -c 'from app.main import app; print("APP IMPORT OK",len(app.routes))'
runuser -u proxy-mgmt -- env $(grep -v '^#' /etc/security-web-gateway/production.env | xargs) PYTHONPATH="$REL" SWG_DB_PATH="$SHADOW" \
  "$VENV/bin/python" "$REL/tools/validate_policy.py"

echo "===== 5. TRANSACTIONAL CUTOVER ====="
CUTOVER=1
systemctl stop security-web-gateway-telemetry.timer security-web-gateway-source-sync.timer security-web-gateway-storage-maintenance.timer security-web-gateway-discovery.timer security-web-gateway-performance.timer security-web-gateway-health-monitor.timer 2>/dev/null || true
systemctl stop security-web-gateway-health-monitor.service 2>/dev/null || true
systemctl stop security-web-gateway.service security-web-gateway-discovery.service security-web-gateway-telemetry.service security-web-gateway-performance.service security-web-gateway-source-sync.service security-web-gateway-storage-maintenance.service
runuser -u proxy-mgmt -- env $(grep -v '^#' /etc/security-web-gateway/production.env | xargs) PYTHONPATH="$REL" \
  "$VENV/bin/python" "$REL/tools/migrate.py" --db "$PDB" --root "$REL"
ln -sfn "$REL" /opt/security-web-gateway/current
for f in security-web-gateway.service security-web-gateway-source-sync.service security-web-gateway-source-sync.timer security-web-gateway-telemetry.service security-web-gateway-telemetry.timer security-web-gateway-storage-maintenance.service security-web-gateway-storage-maintenance.timer security-web-gateway-discovery.service security-web-gateway-discovery.timer security-web-gateway-performance.service security-web-gateway-performance.timer security-web-gateway-health-monitor.service security-web-gateway-health-monitor.timer; do
  install -o root -g root -m 0644 "$ROOT/systemd/$f" "/etc/systemd/system/$f"
done
install -o root -g root -m 0750 "$ROOT/privileged/security-web-gateway-deploy-helper.py" /usr/local/sbin/security-web-gateway-deploy-helper
install -o root -g root -m 0644 "$ROOT/privileged/security-web-gateway-deploy-helper.socket" /etc/systemd/system/security-web-gateway-deploy-helper.socket
install -o root -g root -m 0644 "$ROOT/privileged/security-web-gateway-deploy-helper@.service" /etc/systemd/system/security-web-gateway-deploy-helper@.service
install -d -o root -g root -m 0755 /etc/systemd/system/squid.service.d
install -o root -g root -m 0644 "$ROOT/systemd/squid-priority.conf" /etc/systemd/system/squid.service.d/10-security-web-gateway-priority.conf
systemctl daemon-reload
systemctl restart security-web-gateway-deploy-helper.socket
systemctl restart squid
systemctl start security-web-gateway.service
systemctl enable --now security-web-gateway-source-sync.timer security-web-gateway-telemetry.timer security-web-gateway-storage-maintenance.timer security-web-gateway-discovery.timer security-web-gateway-performance.timer security-web-gateway-health-monitor.timer

for i in $(seq 1 30); do curl -fsS http://127.0.0.1:8200/healthz >/tmp/security-web-gateway-upgrade-health.json 2>/dev/null && break; sleep 1; done
cat /tmp/security-web-gateway-upgrade-health.json
grep -q '"version":"'$SWG_VERSION'"' /tmp/security-web-gateway-upgrade-health.json

# Safe stale-pending reconciliation: clears flags only when effective Squid directives match live policy.
runuser -u proxy-mgmt -- env $(grep -v '^#' /etc/security-web-gateway/production.env | xargs) PYTHONPATH="$REL" "$VENV/bin/python" "$REL/bin/reconcile_pending.py" || true

SUCCESS=1; CUTOVER=0; trap - ERR EXIT
rm -f "$SHADOW"
echo "============================================================"
echo "Security Web Gateway v$SWG_VERSION upgrade successful"
echo "Upgrade did not publish pre-existing pending policy. Existing Squid policy remains unchanged; future Admin Saves use validated Save & Apply."
echo "Rollback backup: $BACKUP"
echo "============================================================"
