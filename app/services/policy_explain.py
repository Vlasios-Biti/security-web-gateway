from __future__ import annotations

import ipaddress

from app.db import connect
from app.services.access_model import effective_network_ids_for_rule


def _domain_match(pattern, host):
    p=(pattern or '').strip().lower().rstrip('.')
    h=(host or '').strip().lower().rstrip('.')
    if not p or not h: return False
    if p.startswith('*.'): p=p[2:]; return h==p or h.endswith('.'+p)
    if p.startswith('.'): p=p[1:]; return h==p or h.endswith('.'+p)
    return h==p


def _protocol_ok(rule_protocol, port, method):
    wanted = 'HTTPS' if str(method or '').upper()=='CONNECT' or int(port or 0)==443 else 'HTTP'
    return rule_protocol in (wanted, 'BOTH')


def _find_network(c, client_ip):
    ip=ipaddress.ip_address(client_ip)
    matches=[]
    for r in c.execute("SELECT * FROM networks WHERE enabled=1 AND proxy_enabled=1"):
        try:
            net=ipaddress.ip_network(r['cidr'], strict=False)
            if ip in net: matches.append((net.prefixlen,dict(r)))
        except Exception: pass
    return sorted(matches,key=lambda x:x[0],reverse=True)[0][1] if matches else None


def _rule_match(rule, host, dest_ip):
    if rule['rule_type']=='domain': return _domain_match(rule['destination'],host)
    if not dest_ip: return False
    try: return ipaddress.ip_address(dest_ip) in ipaddress.ip_network(rule['destination'],strict=False)
    except Exception: return dest_ip==rule['destination']


def explain_policy(client_ip, destination, port=443, method='CONNECT', destination_ip=''):
    client_ip=str(ipaddress.ip_address(client_ip))
    destination=(destination or '').strip().lower().rstrip('.')
    if not destination: raise ValueError('Destination is required.')
    port=int(port or 443)
    c=connect()
    try:
        network=_find_network(c,client_ip)
        profiles=[]
        if network:
            profiles=[dict(r) for r in c.execute("""SELECT pg.id,pg.name FROM policy_groups pg
                JOIN policy_group_networks pgn ON pgn.group_id=pg.id
                WHERE pgn.network_id=? AND pg.status='active' ORDER BY pg.name""",(network['id'],))]
        candidates=[]
        for r in c.execute("SELECT * FROM rules WHERE action='ALLOW' AND status='active' ORDER BY management_type,rule_type,destination"):
            rule=dict(r)
            if not _protocol_ok(rule['protocol'],port,method): continue
            if not _rule_match(rule,destination,destination_ip): continue
            scope=effective_network_ids_for_rule(c,rule['id'],rule.get('scope_mode') or 'selected')
            in_scope=bool(network and network['id'] in scope)
            apps=[dict(x) for x in c.execute("""SELECT a.id,a.name,ar.enabled FROM applications a
                 JOIN application_rules ar ON ar.application_id=a.id
                 WHERE ar.rule_id=? AND a.status='active' ORDER BY a.name""",(rule['id'],))]
            groups=[dict(x) for x in c.execute("""SELECT DISTINCT pg.id,pg.name FROM policy_groups pg
                LEFT JOIN policy_group_rules pgr ON pgr.group_id=pg.id
                LEFT JOIN policy_group_applications pga ON pga.group_id=pg.id
                LEFT JOIN application_rules ar ON ar.application_id=pga.application_id
                WHERE pg.status='active' AND (pgr.rule_id=? OR (ar.rule_id=? AND ar.enabled=1)) ORDER BY pg.name""",(rule['id'],rule['id']))]
            candidates.append({'rule':rule,'in_scope':in_scope,'applications':apps,'groups':groups,'scope_network_ids':sorted(scope)})
        allowed=any(x['in_scope'] for x in candidates)
        reason='Matched an active ALLOW rule for the client network.' if allowed else (
            'Destination matches a rule, but the client network is outside its effective scope.' if candidates else
            'No active ALLOW rule matches this destination/protocol. Default deny applies.'
        )
        return {
            'decision':'ALLOW' if allowed else 'DENY','reason':reason,'client_ip':client_ip,'destination':destination,
            'destination_ip':destination_ip,'port':port,'method':method,'network':network,'profiles':profiles,'matches':candidates,
        }
    finally: c.close()


def explain_event(event_id):
    c=connect()
    try:
        r=c.execute('SELECT * FROM telemetry_events WHERE id=?',(event_id,)).fetchone()
        if not r: return None
        event=dict(r)
    finally: c.close()
    result=explain_policy(event['client_ip'],event.get('destination_host') or event.get('destination') or '',event.get('destination_port') or 443,event.get('method') or 'CONNECT',event.get('destination_ip') or '')
    result['event']=event
    return result
