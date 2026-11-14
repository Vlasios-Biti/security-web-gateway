"""Optional, scoped service profiles; shared destinations stay shared."""
import hashlib
import json
from app.db import connect

SERVICES = [
    {"key":"windows-update", "name":"Windows Update", "description":"Windows update service and content delivery. Some endpoints also serve Microsoft Store content.",
     "source":"https://learn.microsoft.com/windows/privacy/manage-windows-11-endpoints", "reviewed":"2026-11-09",
     "note":"Windows Update/BITS/Delivery Optimization can use system-level proxy settings. A browser PAC alone does not configure every system service. P2P ports and WSUS are managed separately.",
     "endpoints":[("*.windowsupdate.com","BOTH"),("*.update.microsoft.com","BOTH"),("*.delivery.mp.microsoft.com","BOTH"),("*.prod.do.dsp.mp.microsoft.com","BOTH"),("tsfe.trafficshaping.dsp.mp.microsoft.com","BOTH"),("adl.windows.com","HTTPS")]},
    {"key":"defender-updates", "name":"Defender security updates", "description":"Security intelligence downloads through Microsoft Update plus alternate download hosts; does not enable sample uploads or full Defender cloud protection.",
     "source":"https://learn.microsoft.com/en-us/defender-endpoint/configure-network-connections-microsoft-defender-antivirus", "reviewed":"2026-11-09",
     "note":"Shares update destinations with Windows Update. Enabling one service does not silently enable the other service profile. Alternate hosts can carry other Microsoft downloads.",
     "endpoints":[("*.windowsupdate.com","BOTH"),("*.update.microsoft.com","BOTH"),("*.delivery.mp.microsoft.com","BOTH"),("*.download.microsoft.com","BOTH"),("definitionupdates.microsoft.com","HTTPS"),("go.microsoft.com","HTTP")]},
    {"key":"windows-connectivity", "name":"Windows connectivity checks", "description":"Web probes used for the Windows Internet connectivity indicator.",
     "source":"https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/internet-explorer-edge-open-connect-corporate-public-network", "reviewed":"2026-11-09",
     "note":"DNS probes still use the device's configured DNS. This HTTP profile does not change DNS, firewall rules or NCSI policy.",
     "endpoints":[("*.msftconnecttest.com","HTTP"),("*.msftncsi.com","HTTP")]},
]


def service_profiles():
    c = connect()
    try:
        result = []
        for service in SERVICES:
            app = c.execute("SELECT id,status,pending FROM applications WHERE source_ref=? AND system_managed=1 AND status!='deleted'", ('pc-service:'+service['key'],)).fetchone()
            groups = [r['group_id'] for r in c.execute('SELECT group_id FROM policy_group_applications WHERE application_id=?', (app['id'],))] if app else []
            result.append({**service, 'application_id':app['id'] if app else None, 'enabled':bool(app and app['status']=='active'), 'pending':bool(app and app['pending']), 'group_ids':groups})
        return result
    finally:
        c.close()


def save_service(key, enabled, group_ids, actor):
    service = next((x for x in SERVICES if x['key']==key), None)
    if service is None:
        raise ValueError('Unknown PC service.')
    ids = {int(x) for x in group_ids}
    if enabled and not ids:
        raise ValueError('Select at least one Access Profile for this service.')
    c = connect()
    try:
        c.execute('BEGIN IMMEDIATE')
        user = c.execute("SELECT role FROM users WHERE username=? AND enabled=1", (actor,)).fetchone()
        if not user or user['role']!='admin':
            raise ValueError('Administrator access is required.')
        valid = {x['id'] for x in c.execute("SELECT id FROM policy_groups WHERE status='active'")}
        if ids - valid:
            raise ValueError('An Access Profile is inactive or does not exist.')
        source_ref = 'pc-service:'+key
        app = c.execute("SELECT id FROM applications WHERE source_ref=? AND system_managed=1 AND status!='deleted'", (source_ref,)).fetchone()
        if not app and not enabled:
            c.rollback()
            return None
        if not app:
            name = 'PC service: '+service['name']
            if c.execute("SELECT id FROM applications WHERE name=?",(name,)).fetchone():
                raise ValueError('The reserved service name is already used by another application.')
            cur = c.execute("INSERT INTO applications(name,slug,provider,description,source_kind,source_ref,system_managed,status,pending,created_by,updated_by) VALUES(?,?, 'Microsoft',?,'builtin',?,1,'disabled',1,?,?)", (name,'pc-service-'+key,service['description'],source_ref,actor,actor))
            aid = cur.lastrowid
        else:
            aid = app['id']
        if enabled:
            c.execute('UPDATE application_rules SET enabled=0 WHERE application_id=?',(aid,))
            slug = 'pc-service-'+key
            c.execute('INSERT OR IGNORE INTO categories(name,slug,system_managed) VALUES(?,?,1)', ('PC service: '+service['name'],slug))
            cid = c.execute('SELECT id FROM categories WHERE slug=?', (slug,)).fetchone()['id']
            for host, protocol in service['endpoints']:
                existing = c.execute("SELECT id,protocol,status,action FROM rules WHERE rule_type='domain' AND destination=? AND status!='deleted'", (host,)).fetchone()
                if existing:
                    if existing['status']!='active' or existing['action']!='ALLOW':
                        raise ValueError('The shared destination '+host+' is disabled or blocked. Review it before enabling this service.')
                    if existing['protocol'] not in (protocol,'BOTH'):
                        raise ValueError('Shared protocol conflict for '+host+'. Review the existing rule before widening it.')
                    rid = existing['id']
                else:
                    fingerprint = hashlib.sha256(f'domain|{host}|{protocol}|system|{cid}'.encode()).hexdigest()
                    cur = c.execute("INSERT INTO rules(rule_type,action,destination,protocol,category_id,management_type,status,pending,reason,fingerprint,created_by,updated_by,scope_mode) VALUES('domain','ALLOW',?,?,?,'system','active',1,?,?,?,?,'selected')", (host,protocol,cid,service['name']+' official endpoint preset',fingerprint,actor,actor))
                    rid = cur.lastrowid
                c.execute("INSERT INTO application_rules(application_id,rule_id,source,confidence,metadata_json,enabled) VALUES(?,?,'official-preset','high',?,1) ON CONFLICT(application_id,rule_id) DO UPDATE SET enabled=1", (aid,rid,json.dumps({'source_url':service['source'],'reviewed':service['reviewed']})))
        c.execute('DELETE FROM policy_group_applications WHERE application_id=?', (aid,))
        c.execute('DELETE FROM application_networks WHERE application_id=?',(aid,))
        for gid in ids:
            c.execute('INSERT INTO policy_group_applications(group_id,application_id) VALUES(?,?)', (gid,aid))
        # Disable membership, never the shared rule object.
        c.execute("UPDATE applications SET status=?,pending=1,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?", ('active' if enabled else 'disabled',actor,aid))
        c.commit()
        return aid
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()
