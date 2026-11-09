"""Validated PAC rendering. No database, network or framework dependencies."""
import ipaddress
import json
import re


def validate_policy(value):
    if not isinstance(value, dict):
        raise ValueError("Invalid connection policy.")
    result = {}
    for key in ("fail_open", "internal_direct"):
        if type(value.get(key)) is not bool:
            raise ValueError("Connection switches must be boolean values.")
        result[key] = value[key]
    entries = value.get("bypass", [])
    if not isinstance(entries, list) or len(entries) > 200:
        raise ValueError("Use at most 200 direct destinations.")
    clean = []
    for entry in entries:
        if not isinstance(entry, str):
            raise ValueError("Each direct destination must be a domain, IPv4 address or IPv4 CIDR.")
        entry = entry.strip().lower().rstrip(".")
        if not entry:
            continue
        try:
            net = ipaddress.ip_network(entry, strict=False)
        except ValueError:
            wildcard = entry.startswith("*.")
            host = entry[2:] if wildcard else entry
            try:
                host = host.encode("idna").decode("ascii")
            except UnicodeError as exc:
                raise ValueError("Invalid direct domain.") from exc
            if len(host) > 253 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+", host):
                raise ValueError("Use a domain such as app.example.com, *.example.com, or an IPv4/CIDR; omit URLs and ports.")
            entry = ("*." if wildcard else "") + host
        else:
            if net.version != 4:
                raise ValueError("Direct network rules currently support IPv4/CIDR only.")
            entry = str(net.network_address) if net.prefixlen == 32 else str(net)
        if entry not in clean:
            clean.append(entry)
    result["bypass"] = clean
    return result


def render_pac(policy, proxy_ip, proxy_port):
    policy = validate_policy(policy)
    address = ipaddress.ip_address(proxy_ip)
    if address.version != 4 or not 1 <= int(proxy_port) <= 65535:
        raise ValueError("Invalid proxy endpoint.")
    domains, networks = [], []
    for entry in policy["bypass"]:
        try:
            net = ipaddress.ip_network(entry, strict=False)
            networks.append([str(net.network_address), str(net.netmask)])
        except ValueError:
            domains.append(entry)
    fallback = f"PROXY {address}:{int(proxy_port)}" + ("; DIRECT" if policy["fail_open"] else "")
    # JSON is used only inside JavaScript, never to construct a shell command.
    return """// Managed by Security Web Gateway. Edit Connection in the console.
function FindProxyForURL(url, host) {
    host = host.toLowerCase().replace(/\\.$/, "");
    var domains = %s;
    var networks = %s;
    var internalDirect = %s;
    if (internalDirect && isPlainHostName(host)) return "DIRECT";
    for (var i = 0; i < domains.length; i++) {
        var rule = domains[i];
        if (rule.substring(0, 2) === "*.") {
            var suffix = rule.substring(1);
            if (host === rule.substring(2) || dnsDomainIs(host, suffix)) return "DIRECT";
        } else if (host === rule) return "DIRECT";
    }
    var literal = /^\\d+\\.\\d+\\.\\d+\\.\\d+$/.test(host);
    if (internalDirect && literal && (isInNet(host, "10.0.0.0", "255.0.0.0") ||
        isInNet(host, "172.16.0.0", "255.240.0.0") || isInNet(host, "192.168.0.0", "255.255.0.0") ||
        isInNet(host, "127.0.0.0", "255.0.0.0"))) return "DIRECT";
    // Resolve only when explicit IP/CIDR bypasses need to be matched.
    var ip = networks.length ? (literal ? host : dnsResolve(host)) : null;
    if (ip) for (var j = 0; j < networks.length; j++) {
        if (isInNet(ip, networks[j][0], networks[j][1])) return "DIRECT";
    }
    return %s;
}
""" % (json.dumps(domains), json.dumps(networks), json.dumps(policy["internal_direct"]), json.dumps(fallback))
