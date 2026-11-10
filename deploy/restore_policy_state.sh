#!/usr/bin/env bash
set -Eeuo pipefail
ARCHIVE="${1:-}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CURRENT="$(readlink -f /opt/security-web-gateway/current)"
PDB=/var/lib/security-web-gateway/prod/swg.db
VENV=/opt/security-web-gateway/venv
[[ $EUID -eq 0 ]] || { echo 'ERROR: run as root'; exit 1; }
[[ -f "$ARCHIVE" ]] || { echo 'Usage: sudo ./deploy/restore_policy_state.sh /path/policy-state.tar.gz'; exit 2; }
[[ -f "$CURRENT/VERSION" && "$(cat "$CURRENT/VERSION")" == "$(cat "$ROOT/VERSION")" ]] || { echo 'Upgrade the target VM to this release before restoring state.'; exit 1; }
TMP="$(mktemp -d)"
BACKUP="/var/lib/security-web-gateway/backups/state-restore-$(date -u +%Y%m%d-%H%M%S)-$$"
CUTOVER=0; SUCCESS=0; RESTART=()
finish(){
  rc=$?; trap - ERR EXIT
  if [[ $CUTOVER -eq 1 && $SUCCESS -eq 0 ]]; then
    systemctl stop security-web-gateway.service 2>/dev/null || true
    rm -f "$PDB-wal" "$PDB-shm"
    cp "$BACKUP/pre-restore.db" "$PDB"
    chown proxy-mgmt:proxy-mgmt "$PDB"; chmod 0640 "$PDB"
    echo "Restore failed; prior database restored from $BACKUP" >&2
  fi
  if [[ ${#RESTART[@]} -gt 0 ]]; then systemctl start "${RESTART[@]}" || rc=1; fi
  rm -rf "$TMP"
  exit "$rc"
}
trap finish ERR EXIT
python3 "$ROOT/tools/prepare_state_restore.py" "$ARCHIVE" "$TMP"
"$VENV/bin/python" "$ROOT/tools/migrate.py" --db "$TMP/swg.db" --root "$ROOT"
PYTHONPATH="$ROOT" SWG_DB_PATH="$TMP/swg.db" "$VENV/bin/python" -c 'from app.db import verify_schema; verify_schema()'
TIMERS=(security-web-gateway-telemetry.timer security-web-gateway-source-sync.timer security-web-gateway-storage-maintenance.timer security-web-gateway-discovery.timer security-web-gateway-performance.timer security-web-gateway-health-monitor.timer)
WORKERS=(security-web-gateway-telemetry.service security-web-gateway-source-sync.service security-web-gateway-storage-maintenance.service security-web-gateway-discovery.service security-web-gateway-performance.service security-web-gateway-health-monitor.service)
for unit in security-web-gateway.service "${TIMERS[@]}"; do if systemctl is-active --quiet "$unit"; then RESTART+=("$unit"); fi; done
systemctl stop "${TIMERS[@]}" "${WORKERS[@]}" security-web-gateway.service
for unit in "${WORKERS[@]}" security-web-gateway.service; do if systemctl is-active --quiet "$unit"; then echo "Writer still active: $unit"; exit 1; fi; done
install -d -o root -g root -m 0700 "$BACKUP"
python3 - "$PDB" "$BACKUP/pre-restore.db" "$TMP/swg.db" <<'PY'
import sqlite3,sys
source=sqlite3.connect(sys.argv[1]);backup=sqlite3.connect(sys.argv[2]);source.backup(backup);backup.close()
row=source.execute("SELECT value FROM settings WHERE key='connection_policy'").fetchone();source.close()
c=sqlite3.connect(sys.argv[3])
c.execute('DELETE FROM sessions')
c.execute("UPDATE application_learning_sessions SET status='stopped' WHERE status='active'")
c.execute("UPDATE discovery_runs SET status='discarded',error_text='Cancelled by state restore' WHERE status='running'")
for table in ('health_test_queue','health_delivery_state','health_incidents'):c.execute('DELETE FROM '+table)
c.execute("DELETE FROM settings WHERE key='connection_policy'")
if row:c.execute("INSERT INTO settings(key,value) VALUES('connection_policy',?)",row)
c.commit();c.execute('PRAGMA wal_checkpoint(TRUNCATE)');c.close()
PY
CUTOVER=1
rm -f "$PDB-wal" "$PDB-shm"
python3 - "$TMP/swg.db" "$PDB" <<'PY'
import os,sys,tempfile,shutil,grp,pwd
from pathlib import Path
path=Path(sys.argv[2]);fd,tmp=tempfile.mkstemp(prefix='.restore-',dir=path.parent)
try:
 with os.fdopen(fd,'wb') as out,open(sys.argv[1],'rb') as source:
  shutil.copyfileobj(source,out);out.flush();os.fsync(out.fileno())
 os.chown(tmp,pwd.getpwnam('proxy-mgmt').pw_uid,grp.getgrnam('proxy-mgmt').gr_gid);os.chmod(tmp,0o640);os.replace(tmp,path)
finally:
 if os.path.exists(tmp):os.unlink(tmp)
PY
if [[ " ${RESTART[*]} " == *" security-web-gateway.service "* ]]; then
 systemctl start security-web-gateway.service
 for i in $(seq 1 20); do curl -fsS http://127.0.0.1:8200/healthz >/dev/null && break; sleep 1; done
 curl -fsS http://127.0.0.1:8200/healthz
fi
SUCCESS=1; CUTOVER=0
echo "Policy state restored. Target IP, TLS, PAC and notification credentials remain local. Sessions and queued jobs were revoked. Backup: $BACKUP"
