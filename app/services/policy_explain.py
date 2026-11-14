from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit
from app.security import normalize_domain
from app.services.connectivity import connection_policy
from app.services.pac_policy import explain_routing

from app.config import PROXY_IP
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
    # Match the base Squid Safe_ports/CONNECT guards and generated rule methods.
    method=str(method).upper()
    if method=='CONNECT':return port==443 and rule_protocol in ('HTTPS','BOTH')
    return port==80 and rule_protocol in ('HTTP','BOTH')


def _find_networks(c, client_ip):
    ip=ipaddress.ip_address(client_ip);matches=[]
    for row in c.execute("SELECT * FROM networks WHERE enabled=1 AND proxy_enabled=1"):
        if ip in ipaddress.ip_network(row['cidr'],strict=False):matches.append(dict(row))
    return sorted(matches,key=lambda row:(-ipaddress.ip_network(row['cidr']).prefixlen,row['id']))


def _target(destination, port, method, destination_ip):
    value=(destination or '').strip()
    if '://' in value:
        parsed=urlsplit(value)
        if parsed.scheme not in ('http','https') or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError('Use an HTTP/HTTPS website URL or hostname, without credentials.')
        value=parsed.hostname;port=parsed.port or (443 if parsed.scheme=='https' else 80)
        method='CONNECT' if parsed.scheme=='https' else 'GET'
    port=int(port)
    if not 1<=port<=65535:raise ValueError('Port must be between 1 and 65535.')
    method=str(method).strip().upper()
    if method not in ('CONNECT','GET','POST','PUT','HEAD','OPTIONS','DELETE','PATCH'):raise ValueError('Unsupported HTTP method.')
    try:
        address=ipaddress.ip_address(value);value=str(address)
        if address.version!=4:raise ValueError('The gateway source/destination policy supports IPv4 only.')
        destination_ip=value
    except ValueError:
        # A colon is never valid in a DNS name and also excludes IPv6 literals.
        if ':' in value:raise ValueError('Use a hostname or IPv4 address.') from None
        value=value.lower() if re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',value.lower()) else normalize_domain(value)
        if value.startswith(('*','.')):raise ValueError('Test one hostname, without a wildcard.')
    if destination_ip:
        address=ipaddress.ip_address(destination_ip)
        if address.version!=4:raise ValueError('Destination IP must be IPv4.')
        destination_ip=str(address)
    return value,port,method,destination_ip


def _rule_match(rule, host, dest_ip):
    if rule['rule_type']=='domain': return _domain_match(rule['destination'],host)
    if not dest_ip: return False
    try: return ipaddress.ip_address(dest_ip) in ipaddress.ip_network(rule['destination'],strict=False)
    except Exception: return dest_ip==rule['destination']


def explain_policy(client_ip, destination, port=443, method='CONNECT', destination_ip=''):
    client_ip=str(ipaddress.ip_address(client_ip))
    if ipaddress.ip_address(client_ip).version!=4:raise ValueError('Client IP must be IPv4.')
    destination,port,method,destination_ip=_target(destination,port,method,destination_ip)
    c=connect()
    try:
        networks=_find_networks(c,client_ip)
        network=networks[0] if networks else None
        network_ids={row['id'] for row in networks}
        diagnostic_client=client_ip in ('127.0.0.1',PROXY_IP)
        active_network_ids={row['id'] for row in c.execute('SELECT id FROM networks WHERE enabled=1 AND proxy_enabled=1')}
        profiles=[]
        if network:
            profiles=[dict(r) for r in c.execute("""SELECT DISTINCT pg.id,pg.name FROM policy_groups pg
                JOIN policy_group_networks pgn ON pgn.group_id=pg.id
                WHERE pgn.network_id IN ("""+','.join('?' for _ in network_ids)+""") AND pg.status='active' ORDER BY pg.name""",tuple(sorted(network_ids)))]
        candidates=[]
        for r in c.execute("SELECT * FROM rules WHERE action='ALLOW' AND status='active' AND (expires_at IS NULL OR expires_at='' OR julianday(expires_at)>julianday('now')) ORDER BY management_type,rule_type,destination"):
            rule=dict(r)
            if not _protocol_ok(rule['protocol'],port,method): continue
            if not _rule_match(rule,destination,destination_ip): continue
            scope=effective_network_ids_for_rule(c,rule['id'],rule.get('scope_mode') or 'selected')
            in_scope=bool((active_network_ids if diagnostic_client else network_ids) & scope)
            apps=[dict(x) for x in c.execute("""SELECT a.id,a.name,ar.enabled FROM applications a
                 JOIN application_rules ar ON ar.application_id=a.id
                 WHERE ar.rule_id=? AND ar.enabled=1 AND a.status='active' ORDER BY a.name""",(rule['id'],))]
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
        if port not in (80,443) or (method=='CONNECT' and port!=443):reason='The Squid base configuration blocks this port/method before ALLOW rules are checked.'
        elif method!='CONNECT' and port!=80:reason='Plain HTTP requests use port 80; HTTPS access uses CONNECT on port 443.'
        elif diagnostic_client:reason='Gateway diagnostic source: checks the union of allowed destinations across enabled proxy networks.'
        elif not networks:reason='No enabled proxy network contains this client IP.'
        routing=explain_routing(connection_policy(),destination,destination_ip)
        pending=bool(c.execute("SELECT 1 FROM rules WHERE pending=1 UNION ALL SELECT 1 FROM networks WHERE pending=1 UNION ALL SELECT 1 FROM applications WHERE pending=1 UNION ALL SELECT 1 FROM policy_groups WHERE pending=1 LIMIT 1").fetchone())
        return {
            'diagnostic_client':diagnostic_client,'basis':'saved_policy','pending_changes':pending,'routing':routing,'networks':networks,
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
    result['historical_note']='The logged Squid result is the historical evidence. This explanation uses current saved policy, which may have changed since the request.'
    return result
