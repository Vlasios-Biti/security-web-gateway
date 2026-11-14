#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${1:-/root/security-web-gateway-policy-state-$(date +%Y%m%d-%H%M%S).tar.gz}"
[[ $EUID -eq 0 ]] || { echo 'ERROR: run as root'; exit 1; }
DB=/var/lib/security-web-gateway/prod/swg.db
[[ -f "$DB" ]] || { echo 'ERROR: production DB not found'; exit 1; }
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
chmod 0700 "$TMP"
python3 - "$DB" "$TMP/swg.db" <<'PY'
import sqlite3,sys
s=sqlite3.connect(sys.argv[1]);d=sqlite3.connect(sys.argv[2]);s.backup(d)
if d.execute("SELECT 1 FROM sqlite_master WHERE name='api_tokens' AND type='table'").fetchone():d.execute('DELETE FROM api_tokens');d.commit()
d.close();s.close()
PY
cat > "$TMP/metadata.txt" <<META
created_at=$(date -Is)
hostname=$(hostname)
source_release=$(readlink -f /opt/security-web-gateway/current || true)
NOTE=Sensitive backup: contains user password hashes, policy data, audit data and telemetry. Never commit to Git.
META
(cd "$TMP" && sha256sum swg.db > SHA256SUMS.txt)
python3 "$ROOT/tools/export_policy_archive.py" "$TMP" "$OUT"
echo "$OUT"
