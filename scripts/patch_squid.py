#!/usr/bin/env python3
import argparse
import re
import shutil
import subprocess
import sys
from pathlib import Path

BEGIN = '# BEGIN SECURITY-WEB-GATEWAY-MANAGED'
END = '# END SECURITY-WEB-GATEWAY-MANAGED'
PREFIX = '# LEGACY-DISABLED-BY-SECURITY-WEB-GATEWAY '

TARGET_START = re.compile(
    r'''^\s*(?:
        acl\s+(?:google_search|google_maps|business_domains)\s+dstdomain\b
      | acl\s+(?:allowed_http_ips|allowed_https_ips)\s+dst\b
      | http_access\s+allow\s+allowed_clients\s+CONNECT\s+port_https\s+(?:google_search|google_maps|business_domains|allowed_https_ips)\s*$
      | http_access\s+allow\s+allowed_clients\s+port_http\s+(?:google_search|google_maps|business_domains|allowed_http_ips)\s*$
    )''',
    re.IGNORECASE | re.VERBOSE,
)


def run(cmd):
    return subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=30)


def _continued(line: str) -> bool:
    return line.rstrip('\r\n').rstrip().endswith('\\')


def disable_legacy_statements(text: str) -> str:
    lines = text.splitlines(keepends=True)
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.lstrip()
        if not stripped.startswith('#') and TARGET_START.match(line):
            out.append(PREFIX + stripped)
            cont = _continued(line)
            i += 1
            while cont and i < len(lines):
                nxt = lines[i]
                if nxt.lstrip().startswith('#'):
                    out.append(nxt)
                else:
                    out.append(PREFIX + nxt.lstrip())
                cont = _continued(nxt)
                i += 1
            continue
        out.append(line)
        i += 1
    return ''.join(out)


def transform(text: str, managed: Path) -> str:
    text = re.sub(re.escape(BEGIN) + r'.*?' + re.escape(END) + r'\n?', '', text, flags=re.S)
    text = re.sub(
        r'# BEGIN HQ PROXY MANAGER MANAGED POLICY.*?# END HQ PROXY MANAGER MANAGED POLICY\n?',
        '', text, flags=re.S,
    )
    text = disable_legacy_statements(text)
    matches = list(re.finditer(r'^\s*http_access\s+deny\s+all\s*$', text, re.M))
    if not matches:
        raise RuntimeError('Final http_access deny all not found.')
    pos = matches[-1].start()
    return text[:pos] + f'{BEGIN}\ninclude {managed}\n{END}\n\n' + text[pos:]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--conf', default='/etc/squid/squid.conf')
    parser.add_argument('--managed', default='/etc/squid/managed/security-web-gateway.conf')
    parser.add_argument('--backup-dir', required=True)
    args = parser.parse_args()

    conf = Path(args.conf)
    managed = Path(args.managed)
    backup_dir = Path(args.backup_dir)
    backup_dir.mkdir(parents=True, exist_ok=True)

    if not managed.is_file() or managed.is_symlink():
        raise SystemExit('Managed policy missing or unsafe.')

    original = conf.read_text(encoding='utf-8')
    backup = backup_dir / 'squid.conf.before-swg'
    shutil.copy2(conf, backup)

    conf.write_text(transform(original, managed), encoding='utf-8')

    result = run(['/usr/sbin/squid', '-k', 'parse'])
    if result.returncode:
        shutil.copy2(backup, conf)
        print(result.stderr[-3000:], file=sys.stderr)
        raise SystemExit('Squid parse failed; squid.conf restored.')

    result = run(['/usr/bin/systemctl', 'reload', 'squid'])
    if result.returncode:
        shutil.copy2(backup, conf)
        run(['/usr/bin/systemctl', 'reload', 'squid'])
        raise SystemExit('Squid reload failed; squid.conf restored.')

    health = run(['/usr/bin/systemctl', 'is-active', 'squid'])
    if health.stdout.strip() != 'active':
        shutil.copy2(backup, conf)
        run(['/usr/bin/systemctl', 'restart', 'squid'])
        raise SystemExit('Squid health failed; squid.conf restored.')

    print('SECURITY_WEB_GATEWAY SWG MANAGED POLICY ACTIVE')


if __name__ == '__main__':
    main()
