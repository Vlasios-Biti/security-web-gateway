function FindProxyForURL(url, host) {
    var proxy = "PROXY __PROXY_IP__:__PROXY_PORT__; DIRECT";

    // Internal/simple names always stay local/direct.
    var internalSuffix = "__INTERNAL_DOMAIN_SUFFIX__";
    if (isPlainHostName(host) || (internalSuffix && dnsDomainIs(host, internalSuffix))) {
        return "DIRECT";
    }

    // RFC1918 IP literals stay direct.
    if (shExpMatch(host, "10.*") || shExpMatch(host, "192.168.*") ||
        shExpMatch(host, "172.16.*") || shExpMatch(host, "172.17.*") ||
        shExpMatch(host, "172.18.*") || shExpMatch(host, "172.19.*") ||
        shExpMatch(host, "172.2?.*") || shExpMatch(host, "172.30.*") ||
        shExpMatch(host, "172.31.*")) {
        return "DIRECT";
    }

    // Fresh installations have no customer-specific bypasses.
    // Manage direct domains/IPs/networks in Connection after installation.
    var directIPs = {};

    if (directIPs[host]) {
        return "DIRECT";
    }

    var resolved = dnsResolve(host);
    if (resolved && directIPs[resolved]) {
        return "DIRECT";
    }

    // Fail-open by design: if the proxy cannot be reached, browser/system may
    // continue DIRECT. Endpoint users cannot edit this policy when Proxy Control
    // is installed; network-side enforcement/failover can be added separately.
    return proxy;
}
