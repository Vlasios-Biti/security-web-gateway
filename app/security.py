import ipaddress,re,socket
DOMAIN_RE=re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$")

def normalize_domain(value, allow_wildcard=True):
    value=value.strip().lower().rstrip(".")
    wildcard=False
    if value.startswith("*."):
        if not allow_wildcard:
            raise ValueError("Wildcard domains are not allowed here.")
        wildcard=True
        value=value[2:]
    if not value or "://" in value or "/" in value or ":" in value or "*" in value:
        raise ValueError("Use a hostname only. A controlled left-most wildcard such as *.example.com is supported.")
    try: value=value.encode("idna").decode("ascii")
    except Exception as exc: raise ValueError("Invalid internationalized domain.") from exc
    if len(value)>253 or not DOMAIN_RE.fullmatch(value): raise ValueError("Invalid fully-qualified domain name.")
    return ("*."+value) if wildcard else value

def squid_domain_token(value):
    """Convert the UI wildcard form to Squid dstdomain suffix syntax."""
    value=normalize_domain(value,allow_wildcard=True)
    return "."+value[2:] if value.startswith("*.") else value

def normalize_ip(value):
    try: net=ipaddress.ip_network(value.strip(),strict=False)
    except ValueError as exc: raise ValueError("Invalid IP address or CIDR.") from exc
    if net.version!=4: raise ValueError("Only IPv4 destinations are supported.")
    return str(net)

def resolve_domain(domain):
    if domain.startswith("*."):
        domain=domain[2:]
    out=set()
    try:
        for r in socket.getaddrinfo(domain,None,type=socket.SOCK_STREAM): out.add(r[4][0])
    except socket.gaierror: return []
    return sorted(out)


def normalize_expiration(value):
    from datetime import datetime,timezone
    if not value or not str(value).strip():return None
    try:
        date=datetime.fromisoformat(str(value).strip().replace('Z','+00:00'))
        if date.tzinfo is None:date=date.replace(tzinfo=timezone.utc)
        return date.astimezone(timezone.utc).isoformat()
    except (ValueError,TypeError) as exc:raise ValueError('Use a valid expiration date/time in UTC.') from exc


def expiration_input(value):
    if not value:return ''
    from datetime import datetime
    try:return datetime.fromisoformat(normalize_expiration(value)).strftime('%Y-%m-%dT%H:%M')
    except ValueError:return ''


def csv_cell(value):
    """Keep untrusted export text from starting a spreadsheet formula."""
    if not isinstance(value,str) or not value:return value
    import unicodedata
    probe=unicodedata.normalize('NFKC',value).lstrip()
    if value[0] in '\t\r\n' or (probe and probe[0] in '=+-@'):
        return "'"+value
    return value
