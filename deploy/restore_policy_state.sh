#!/usr/bin/env bash
set -Eeuo pipefail
ARCHIVE="${1:-}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
[[ $EUID -eq 0 ]] || { echo 'ERROR: run as root'; exit 1; }
[[ -f "$ARCHIVE" ]] || { echo 'Usage: sudo ./deploy/restore_policy_state.sh /path/policy-state.tar.gz'; exit 2; }
[[ -f /etc/security-web-gateway/production.env ]] || { echo 'ERROR: install the target server first.'; exit 1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
tar -xzf "$ARCHIVE" -C "$TMP"
(cd "$TMP" && sha256sum -c SHA256SUMS.txt)
python3 - "$TMP/swg.db" <<'PY'
import sqlite3,sys
c=sqlite3.connect(sys.argv[1]);
assert c.execute('pragma integrity_check').fetchone()[0]=='ok'
print('backup integrity OK')
c.close()
PY
STAMP=$(date +%Y%m%d-%H%M%S)
mkdir -p /var/lib/security-web-gateway/backups/state-restore-$STAMP
python3 - /var/lib/security-web-gateway/prod/swg.db /var/lib/security-web-gateway/backups/state-restore-$STAMP/pre-restore.db <<'PY'
import sqlite3,sys,os
if os.path.exists(sys.argv[1]):
 s=sqlite3.connect(sys.argv[1]);d=sqlite3.connect(sys.argv[2]);s.backup(d);d.close();s.close()
PY
systemctl stop security-web-gateway.service security-web-gateway-telemetry.timer security-web-gateway-source-sync.timer security-web-gateway-storage-maintenance.timer security-web-gateway-discovery.timer 2>/dev/null || true
cp "$TMP/swg.db" /var/lib/security-web-gateway/prod/swg.db
chown proxy-mgmt:proxy-mgmt /var/lib/security-web-gateway/prod/swg.db; chmod 0640 /var/lib/security-web-gateway/prod/swg.db
runuser -u proxy-mgmt -- env $(grep -v '^#' /etc/security-web-gateway/production.env | xargs) PYTHONPATH=/opt/security-web-gateway/current \
  /opt/security-web-gateway/venv/bin/python /opt/security-web-gateway/current/tools/migrate.py --db /var/lib/security-web-gateway/prod/swg.db --root /opt/security-web-gateway/current
# Never carry active sessions to a different server.
python3 - "/var/lib/security-web-gateway/backups/state-restore-$STAMP/pre-restore.db" <<'PY'
import sqlite3,sys,os
p='/var/lib/security-web-gateway/prod/swg.db';c=sqlite3.connect(p);c.execute('DELETE FROM sessions')
c.execute("UPDATE application_learning_sessions SET status='stopped' WHERE status='active'")
# The connection policy/PAC belongs to the target host, just like its TLS/IP.
c.execute("DELETE FROM settings WHERE key='connection_policy'")
if os.path.exists(sys.argv[1]):
 previous=sqlite3.connect(sys.argv[1])
 try: row=previous.execute("SELECT value FROM settings WHERE key='connection_policy'").fetchone()
 finally: previous.close()
 if row:c.execute("INSERT INTO settings(key,value) VALUES('connection_policy',?)",row)
c.commit();c.close()
PY
chown proxy-mgmt:proxy-mgmt /var/lib/security-web-gateway/prod/swg.db
systemctl start security-web-gateway.service
systemctl start security-web-gateway-telemetry.timer security-web-gateway-source-sync.timer security-web-gateway-storage-maintenance.timer security-web-gateway-discovery.timer
curl -fsS http://127.0.0.1:8200/healthz
echo
echo "Policy state restored. Re-login is required; target-server IP/FQDN/TLS/PAC remain local to the new server."
