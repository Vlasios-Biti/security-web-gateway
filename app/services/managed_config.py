"""Narrow grammar accepted by the root Squid managed-policy helper."""
import ipaddress
import re

NAME=re.compile(r'^swg_(?:diag(?:_(?:dom|ip)_(?:http|https))?|(?:net|dom_http|dom_https|ip_http|ip_https)_n[1-9][0-9]*)$')
DOMAIN=re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$')


def validate_managed_config(content):
    if len(content.encode())>2*1024*1024:raise ValueError('Managed policy too large.')
    for raw in content.splitlines():
        line=raw.strip()
        if not line or line.startswith('#'):continue
        tokens=line.split()
        if len(tokens)==4 and tokens[0]=='acl' and NAME.fullmatch(tokens[1]):
            if tokens[2] in ('src','dst'):ipaddress.ip_network(tokens[3],strict=False)
            elif tokens[2]=='dstdomain':
                host=tokens[3].lstrip('.')
                if len(host)>253 or not DOMAIN.fullmatch(host):raise ValueError('Invalid managed domain.')
            else:raise ValueError('Unsupported managed ACL type.')
            continue
        if tokens[:2]==['http_access','allow'] and len(tokens) in (5,6):
            source=tokens[2];destination=tokens[-1]
            if not re.fullmatch(r'swg_(?:diag|net_n[1-9][0-9]*)',source) or not NAME.fullmatch(destination):raise ValueError('Invalid managed access scope.')
            if len(tokens)==6 and tokens[3:5]==['CONNECT','port_https']:continue
            if len(tokens)==5 and tokens[3]=='port_http':continue
        raise ValueError('Managed policy contains an unsupported directive.')
    return True
