"""One PAC address shared by the GUI and all endpoint deployment downloads."""
import ipaddress
import json
import re
from app.config import PROXY_IP, MANAGEMENT_FQDN
from app.db import connect, audit


def validate_endpoint(scheme, host):
    if scheme not in ('http', 'https'):
        raise ValueError('Choose HTTP or HTTPS.')
    host = host.strip().lower()
    try:
        host = str(ipaddress.IPv4Address(host))
    except ValueError:
        if len(host) > 253 or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', x) for x in host.split('.')):
            raise ValueError('Use a DNS hostname or IPv4 address, without a URL, port or path.')
    return {'scheme': scheme, 'host': host}


def endpoint_settings():
    c = connect()
    try:
        row = c.execute("SELECT value FROM settings WHERE key='pac_endpoint'").fetchone()
    finally:
        c.close()
    return validate_endpoint(**json.loads(row['value'])) if row else {'scheme': 'http', 'host': PROXY_IP}


def pac_address():
    cfg = endpoint_settings()
    return f"{cfg['scheme']}://{cfg['host']}{':8081' if cfg['scheme']=='http' else ''}/proxy.pac"


def save_endpoint(scheme, host, actor, source_ip=None):
    cfg = validate_endpoint(scheme, host)
    c = connect()
    try:
        c.execute("INSERT INTO settings(key,value,updated_at) VALUES('pac_endpoint',?,CURRENT_TIMESTAMP) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=CURRENT_TIMESTAMP", (json.dumps(cfg),))
        c.commit()
    finally:
        c.close()
    audit(actor, 'PAC_ENDPOINT_SAVE', 'SUCCESS', 'settings', 'pac_endpoint', source_ip)
