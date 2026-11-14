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
MAX_FILE = 65536


def command(args, input_data=None):
    return subprocess.run(args, input=input_data, capture_output=True, timeout=8, check=False)


def private_write(path, raw):
    fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
    with os.fdopen(fd,'wb') as stream:stream.write(raw)


def certificate_blocks(raw):
    blocks=re.findall(br'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----',raw,re.S)
    if not blocks:raise ValueError('No PEM certificate found.')
    return b'\n'.join(blocks)+b'\n'


def install_pfx(value):
    raw=base64.b64decode(value.get('bundle',''),validate=True)
    password=value.get('password','')
    if not raw or len(raw)>MAX_FILE:raise ValueError('Use a PFX file of at most 64 KB.')
    if not isinstance(password,str) or len(password)>1024 or any(c in password for c in '\x00\r\n'):raise ValueError('Invalid PFX password.')
    TLS.mkdir(mode=0o700,parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='.pfx-',dir=TLS) as td:
        folder=Path(td);bundle=folder/'bundle.pfx';private_write(bundle,raw)
        outputs=[folder/'leaf.pem',folder/'ca.pem',folder/'key.pem']
        for target,options in zip(outputs,(['-clcerts','-nokeys'],['-cacerts','-nokeys'],['-nocerts','-nodes'])):
            private_write(target,b'')
            result=command(['/usr/bin/openssl','pkcs12','-in',str(bundle),'-passin','stdin','-out',str(target),*options],input_data=password.encode('utf-8')+b'\n')
            if result.returncode:raise ValueError('Could not open PFX. Check its password and export a modern AES-compatible bundle with its private key.')
            if target.stat().st_size>MAX_FILE*2:raise ValueError('PFX contents are too large.')
        chain=certificate_blocks(outputs[0].read_bytes()+b'\n'+outputs[1].read_bytes());key=outputs[2].read_bytes()
        return install({'certificate':base64.b64encode(chain).decode('ascii'),'private_key':base64.b64encode(key).decode('ascii'),'hostname':value.get('hostname','')})


def renew_self_signed(value):
    if not isinstance(value,dict) or type(value.get('days')) is not int or value['days'] not in (90,365):raise ValueError('Choose 90 or 365 days.')
    cert,key=TLS/'management.crt',TLS/'management.key'
    data=ssl._ssl._test_decode_cert(str(cert))
    if data.get('issuer')!=data.get('subject'):raise ValueError('This certificate was issued by a CA. Import its renewed certificate instead.')
    if command(['/usr/bin/openssl','verify','-no_check_time','-check_ss_sig','-no-CApath','-CAfile',str(cert),str(cert)]).returncode:
        raise ValueError('The current certificate is not a valid self-signed certificate.')
    env={line.split('=',1)[0]:line.split('=',1)[1].strip().strip('"\'') for line in ENV.read_text().splitlines() if '=' in line and not line.lstrip().startswith('#')}
    hosts={env.get('SWG_FQDN',''),env.get('SWG_PROXY_IP','')}
    if value.get('hostname'):hosts.add(value['hostname'])
    names=[]
    for host in sorted(hosts):
        if not isinstance(host,str) or not host or len(host)>253 or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]*',host):raise ValueError('Invalid configured gateway name/IP.')
        try:ipaddress.IPv4Address(host);kind='IP'
        except ValueError:kind='DNS'
        names.append(kind+':'+host)
    if key.stat().st_size>MAX_FILE:raise ValueError('Private key is too large.')
    with tempfile.TemporaryDirectory(prefix='.self-renew-',dir=TLS) as td:
        candidate=Path(td)/'certificate.pem'
        csr=Path(td)/'request.pem';extensions=Path(td)/'extensions.cnf'
        private_write(csr,b'')
        private_write(extensions,('subjectAltName='+','.join(names)+'\nbasicConstraints=critical,CA:FALSE\nextendedKeyUsage=serverAuth\n').encode('ascii'))
        private_write(candidate,b'')
        # Preserve the existing subject without reconstructing a user-controlled DN.
        result=command(['/usr/bin/openssl','x509','-x509toreq','-in',str(cert),'-signkey',str(key),'-passin','pass:','-out',str(csr)])
        if result.returncode:raise ValueError('Could not prepare the self-signed renewal.')
        result=command(['/usr/bin/openssl','x509','-req','-in',str(csr),'-signkey',str(key),'-passin','pass:','-sha256','-days',str(value['days']),'-extfile',str(extensions),'-out',str(candidate)])
        if result.returncode:raise ValueError('Self-signed certificate generation failed.')
        return install({'certificate':base64.b64encode(candidate.read_bytes()).decode('ascii'),'private_key':base64.b64encode(key.read_bytes()).decode('ascii'),'hostname':value.get('hostname','')})


def install(value):
    if not isinstance(value,dict):raise ValueError('Invalid certificate request.')
    kind=value.get('certificate_format','pem')
    if kind=='pfx':return install_pfx(value)
    if kind!='pem':raise ValueError('Choose PEM or PFX.')
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
            if not raw or len(raw)>MAX_FILE: raise ValueError('Use PEM files of at most 64 KB each.')
            if field=='certificate':raw=certificate_blocks(raw)
            private_write(path,raw)
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
