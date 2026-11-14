"""Current IP labels; never rewrite historical traffic as authenticated device identity."""
import ipaddress
from app.db import connect, audit


def save_label(ip, name, actor):
    ip=str(ipaddress.ip_address(ip));name=name.strip()
    if len(name)>100 or any(ord(c)<32 for c in name):raise ValueError('Use a PC name of at most 100 characters.')
    c=connect()
    try:
        if name:c.execute('INSERT INTO client_labels(ip,name,updated_by) VALUES(?,?,?) ON CONFLICT(ip) DO UPDATE SET name=excluded.name,updated_by=excluded.updated_by,updated_at=CURRENT_TIMESTAMP',(ip,name,actor))
        else:c.execute('DELETE FROM client_labels WHERE ip=?',(ip,))
        c.commit()
    finally:c.close()
    audit(actor,'CLIENT_LABEL_SAVE','SUCCESS','client_ip',ip)


def label(c, ip):
    row=c.execute('SELECT name FROM client_labels WHERE ip=?',(ip,)).fetchone()
    return row['name'] if row else ''
