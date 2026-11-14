#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VERSION="$(cat "$ROOT/VERSION")"
OUT="${1:-$ROOT/dist}"
NAME="Security-Web-Gateway-v$VERSION"
mkdir -p "$OUT"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
rsync -a --exclude '.git' --exclude '.venv' --exclude '.venv-linux' --exclude 'runtime' --exclude '*.db*' --exclude '*.har' --exclude 'dist' --exclude '__pycache__' --exclude '*.pyc' "$ROOT/" "$TMP/$NAME/"
(
 cd "$TMP/$NAME"
 find . -type f ! -name 'CHECKSUMS.sha256' -print0 | sort -z | xargs -0 sha256sum > CHECKSUMS.sha256
)
tar -C "$TMP" -czf "$OUT/$NAME.tar.gz" "$NAME"
python3 - "$OUT/$NAME.tar.gz" <<'PY'
import hashlib,sys
p=sys.argv[1];h=hashlib.sha256(open(p,'rb').read()).hexdigest();open(p+'.sha256','w').write(f'{h}  {p.split("/")[-1]}\n')
print(h,p)
PY
