"""Install a fixed public HTTP block page without changing managed allow rules."""
import importlib.util
import ipaddress
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
BEGIN = '# BEGIN SWG BLOCK PAGE'
END = '# END SWG BLOCK PAGE'
PUBLIC_BEGIN = '# BEGIN SWG PUBLIC BLOCK PAGE'
PUBLIC_END = '# END SWG PUBLIC BLOCK PAGE'
LOCATION = '''    location = /blocked {
        alias /etc/security-web-gateway/blocked.html;
        default_type text/html;
        add_header Cache-Control "no-store" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header Content-Security-Policy "default-src 'none'; img-src data:; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'" always;
    }

'''


def patch_squid(text, host):
    host = str(ipaddress.IPv4Address(host))
    for begin, end in ((BEGIN, END), (PUBLIC_BEGIN, PUBLIC_END)):
        text = re.sub(re.escape(begin) + '.*?' + re.escape(end) + r'\n?', '', text, flags=re.S)
    if not re.search(r'^acl\s+CONNECT\s+method\s+CONNECT\s*$', text, re.M):
        raise ValueError('The standard CONNECT ACL is required.')
    access = re.search(r'^http_access\s+', text, re.M)
    if not access: raise ValueError('Squid access policy not found.')
    # Only this exact public local page is allowed, even when internal DIRECT is off.
    public = (PUBLIC_BEGIN + '\nacl swg_block_page_url url_regex ^http://' + host.replace('.', r'\.') + ':8081/blocked$\n'
              'http_access allow !CONNECT swg_block_page_url\n' + PUBLIC_END + '\n')
    text = text[:access.start()] + public + text[access.start():]
    matches = list(re.finditer(r'^http_access\s+deny\s+all\s*$', text, re.M))
    if not matches: raise ValueError('Final deny all is required.')
    pos = matches[-1].start()
    block = (BEGIN + '\n# Keep denied HTTPS CONNECT responses at 403; never redirect a tunnel.\n'
             'http_access deny CONNECT\ndeny_info http://' + host + ':8081/blocked all\n' + END + '\n')
    return text[:pos] + block + text[pos:]


def patch_nginx(text):
    anchor = text.find('    location / { return 404; }')
    if anchor < 0 or not re.search(r'listen\s+[^;]*:8081\s*;', text[:anchor]):
        raise ValueError('Standard HTTP PAC server not found; configure /blocked manually.')
    if 'location = /blocked {' in text: return text
    return text[:anchor] + LOCATION + text[anchor:]


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
    return module


def main():
    env = Path('/etc/security-web-gateway/production.env').read_text()
    found = re.search(r'^SWG_PROXY_IP=(\S+)\s*$', env, re.M)
    if not found: raise ValueError('SWG_PROXY_IP is required.')
    squid = Path('/etc/squid/squid.conf')
    nginx = Path('/etc/nginx/sites-available/security-web-gateway')
    new_squid = patch_squid(squid.read_text(), found[1])
    new_nginx = patch_nginx(nginx.read_text())
    model = load(ROOT / 'app/services/block_page.py', 'swg_brand_model')
    publisher = load(ROOT / 'privileged/block_page_install.py', 'swg_brand_publisher')
    publisher.MODULE = ROOT / 'app/services/block_page.py'
    publisher.install(model.read_settings())
    squid.write_text(new_squid)
    nginx.write_text(new_nginx)


if __name__ == '__main__': main()
