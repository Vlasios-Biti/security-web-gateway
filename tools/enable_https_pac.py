"""Add the static PAC location to an existing standard nginx HTTPS server."""
import re
from pathlib import Path

BLOCK = '''    # SWG HTTPS PAC: no administrator login required.
    location = /proxy.pac {
        alias /etc/security-web-gateway/proxy.pac;
        default_type application/x-ns-proxy-autoconfig;
        add_header Cache-Control "no-cache, no-store, must-revalidate" always;
        add_header Pragma "no-cache" always;
        expires -1;
    }

'''


def patch(text):
    # Operate only on the standard server before its management proxy location.
    anchor = text.find('    location / {')
    if anchor < 0 or not re.search(r'listen\s+[^;]*:443\s+ssl\s*;', text[:anchor]):
        raise ValueError('Custom nginx configuration: add the HTTPS PAC location manually before upgrading.')
    if 'location = /proxy.pac' in text[:anchor]:return text
    return text[:anchor]+BLOCK+text[anchor:]


if __name__ == '__main__':
    target=Path('/etc/nginx/sites-available/security-web-gateway')
    text=target.read_text();updated=patch(text)
    if updated!=text:target.write_text(updated)
