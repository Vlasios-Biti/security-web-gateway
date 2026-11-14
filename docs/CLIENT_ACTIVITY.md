# PC activity and Active Directory — 3.12.5

Open **Monitoring → PC activity**. Search by current cached PC name, source IP, network or VLAN. Select the retained time period and choose **View activity**. Inventory is paginated; search applies to all matching source IPs, not just the currently displayed rows.

A source-IP page shows requests, allowed/blocked decisions, transferred bytes, first/last matching event, destination/application rankings and paginated request history. Filter by domain, decision or custom dates. CSV/XLSX links retain the selected source IP and filters. Exports include at most the newest 250,000 matching events; narrow a large period when necessary. Use Refresh for a new snapshot; telemetry may lag by the collector interval.

Request records contain timestamp, source IP, method, requested host, upstream IP when available, destination port, Squid result/HTTP status, bytes, duration and configured application/profile attribution. ALLOW describes the proxy decision, not proof of a successful website action. HTTPS CONNECT records do not reveal encrypted URL paths, searches, page contents or which person clicked a button. Times use the gateway server timezone.

## Identity boundaries

The authoritative source evidence is the IP recorded by Squid at the request time. A cached reverse-DNS name is current metadata, not a historical device identifier or an authenticated username. The list may show multiple observed network/VLAN labels for an IP; the detail header uses the latest request matching its selected filters.

- Preserve client source IPs on the routed path to the proxy. NAT or VPN aggregation before Squid may combine several PCs under one IP.
- DHCP may assign the same IP to different computers over time. Correlate DHCP lease/DNS history or use reservations when stable historical identification matters.
- Use the enterprise/AD DNS resolver in the VM's OS configuration and maintain PTR records if readable PC names are required. Missing reverse DNS does not stop request logging; the IP remains visible.
- PAC DIRECT bypass and outage fallback do not traverse Squid. They need independent router/firewall flow logging to observe.
- A destination matching a configured application is policy attribution, not evidence of the originating Windows process or person.

## AD: optional, separate purposes

AD domain membership is not required for IP/VLAN proxy policy or traffic logging. This project does not impose an AD-specific device/user quota; practical capacity depends on VM and traffic load, not membership. Display pagination is not a device limit.

AD/GPO can deploy the PAC URL or Edge ProxySettings. The Connection page provides the URL, Windows package and Edge JSON. Keep fail-open policy consistent and test on a pilot PC. The VM does not need to join AD merely to host PAC or receive explicit proxy requests.

Authenticating proxy users against AD/Kerberos, enforcing rules by AD user group and signing into this management GUI with an AD account are distinct integrations. They are **not implemented** in 3.12.5. DNS names do not supply this authentication. No domain-controller credentials, LDAP queries, domain join or authentication setting are silently configured by this update.

References: [Microsoft Edge ProxySettings](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/proxysettings), [PAC URL Group Policy](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/proxypacurl), and [Squid authentication](https://wiki.squid-cache.org/Features/Authentication).
