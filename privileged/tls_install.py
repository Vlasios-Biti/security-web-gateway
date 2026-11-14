"""Fixed-path TLS renewal; called only by the root deployment helper."""
import base64
import ipaddress
import os
from pathlib import Path
import re
import ssl
import subprocess
import tempfile

TLS = Path('/etc/security-web-gateway/tls')
NGINX = Path('/etc/nginx/sites-available/security-web-gateway')
ENV = Path('/etc/security-web-gateway/production.env')


def command(args):
    return subprocess.run(args, capture_output=True, timeout=8, check=False)


def install(value):
    # No arbitrary destination paths, commands, or nginx directives from the GUI.
    config = NGINX.read_text()
    cert, key = TLS/'management.crt', TLS/'management.key'
    if not re.search(r'(?m)^\s*ssl_certificate\s+'+re.escape(str(cert))+r'\s*;', config) or not re.search(r'(?m)^\s*ssl_certificate_key\s+'+re.escape(str(key))+r'\s*;', config):
        raise ValueError('The nginx TLS paths are customized. Renew using your existing certificate management process.')
    hosts = [line.split('=', 1)[1].strip().strip('"\'') for line in ENV.read_text().splitlines() if line.startswith('SWG_FQDN=')]
    if value.get('hostname'): hosts.append(value['hostname'])
    if not hosts: raise ValueError('Management hostname is missing.')
    TLS.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.renew-', dir=TLS) as td:
        paths = [Path(td)/'chain.pem', Path(td)/'key.pem']
        for field, path in zip(('certificate', 'private_key'), paths):
            raw = base64.b64decode(value.get(field, ''), validate=True)
            if not raw or len(raw)>20000: raise ValueError('Use PEM files of at most 20 KB each.')
            fd=os.open(path, os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as stream: stream.write(raw)
        try:
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            # A callable returning empty prevents an interactive encrypted-key prompt.
            context.load_cert_chain(str(paths[0]), str(paths[1]), password=lambda: '')
        except (ssl.SSLError, OSError):
            raise ValueError('Use a valid full PEM chain and matching unencrypted private key.') from None
        if command(['/usr/bin/openssl', 'x509', '-in', str(paths[0]), '-checkend', '0', '-noout']).returncode:
            raise ValueError('Certificate has expired.')
        from datetime import datetime, timezone
        data=ssl._ssl._test_decode_cert(str(paths[0]))
        if ssl.cert_time_to_seconds(data['notBefore']) > datetime.now(timezone.utc).timestamp():
            raise ValueError('Certificate is not valid yet.')
        # Trust the supplied leaf only for this local identity/date check. This does
        # not assert public/enterprise CA trust; clients must trust their own CA.
        # x509 -checkhost exit codes differ across OpenSSL releases; verify fails closed.
        for host in set(hosts):
            if not isinstance(host, str) or len(host)>253 or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*', host):
                raise ValueError('Invalid gateway hostname.')
            try: ipaddress.ip_address(host); flag='-verify_ip'
            except ValueError: flag='-verify_hostname'
            if command(['/usr/bin/openssl', 'verify', '-no-CAfile', '-no-CApath', '-partial_chain', '-trusted', str(paths[0]), flag, host, str(paths[0])]).returncode:
                raise ValueError('Certificate does not cover the management / HTTPS PAC hostname.')
        # Retain old files in root-only temporary storage until validation and reload succeed.
        old=[]
        for path in (cert, key):
            old.append((path.read_bytes(), path.stat().st_mode & 0o777))
        try:
            for source, destination, mode in zip(paths, (cert, key), (0o644, 0o600)):
                os.chmod(source, mode); os.replace(source, destination)
            if command(['/usr/sbin/nginx', '-t']).returncode:
                raise ValueError('nginx validation failed; previous certificate restored.')
            if command(['/usr/bin/systemctl', 'reload', 'nginx']).returncode:
                raise ValueError('nginx reload failed; previous certificate restored.')
        except Exception:
            for index, (destination, (raw, mode)) in enumerate(zip((cert, key), old)):
                restore=Path(td)/f'restore-{index}'
                fd=os.open(restore, os.O_WRONLY|os.O_CREAT|os.O_EXCL, mode)
                with os.fdopen(fd, 'wb') as stream:stream.write(raw)
                os.chmod(restore,mode);os.replace(restore,destination)
            command(['/usr/bin/systemctl','reload','nginx'])
            raise
    return {'ok':True, 'message':'Certificate installed and nginx reloaded.'}
