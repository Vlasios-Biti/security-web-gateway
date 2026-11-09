# Connection and application learning

## Central connection policy

Administrators use **Connection** for PAC behaviour, direct destinations, the Windows package and its installation guide. Operators and viewers cannot change or download endpoint policy packages.

- **Continue if the proxy is unavailable** enables `PROXY host:port; DIRECT`. Turning it off removes the fallback. A Squid policy denial is not proxy unavailability.
- **Keep local traffic direct** handles single-label names, private IPv4 literals and loopback. Internal FQDN suffixes should be entered explicitly, for example `*.office.internal`.
- **Always go direct** accepts exact domains, `*.domain` suffixes, IPv4 addresses and IPv4 CIDRs, one per line. Wildcards include the parent domain. An exact domain matches that domain only. IPv6 network bypass rules are not currently supported.
- DIRECT uses the endpoint's routing table and configured DNS, including enterprise/AD DNS. The console does not reconfigure a router or change the endpoint's DNS servers. Explicit IP/CIDR rules can require a client-side DNS lookup to decide whether the resolved destination is direct.
- Direct and fallback traffic is outside Squid telemetry. Network firewall rules must permit the intended direct path. Applications with independent proxy stacks require their own configuration.

Save validates structured input twice: in the management application and in the privileged helper. The helper renders PAC from trusted installed code, backs up the previous file and atomically replaces `/etc/security-web-gateway/proxy.pac`. It accepts no arbitrary JavaScript or file paths. Nginx continues to serve this static file independently of the management process; no Nginx/Squid reload is needed for a PAC update. Clients pick up changes according to PAC caching and timeout behaviour; open connections can outlive a PAC change. Candidate mode saves a preview only.

On upgrade, the existing static PAC remains untouched. The Connection page imports legacy direct IP entries and the internal suffix until the first save. Fresh installations do not contain customer-specific bypass IPs. On restore to a different VM, target-host connection settings and PAC remain local and active learning sessions are stopped.

## Windows

Download **Connection → Download Windows package** and extract it completely. Its `START-HERE.txt` and `Install-Managed-Proxy.ps1` use this gateway's PAC address. Run the installer from an elevated Windows PowerShell session using your organisation's approved script execution policy. The script reuses the existing endpoint controller and initial-settings backup mechanism. It does not require the optional GUI to be compiled first.

For a GUI installer, run the included `Build-For-This-Gateway.ps1` on Windows and distribute the generated EXE. Standard users can inspect endpoint state; changing or uninstalling the configuration requires administrator elevation. Uninstall restores the initial Windows settings. No endpoint scripts are executed by downloading the package from the console.

## Automatic discovery

Adding an application opens its public website in the isolated server browser. Requests observed while loading and traversing public pages provide first-party, API, authentication, CDN and other dependency evidence. Automatic approval now respects the selected candidates and excludes classified analytics/background endpoints. It does not grant ignored endpoints just because they were captured.

A server browser cannot observe all requests behind a real user's login or guarantee discovery of every application workflow. Its discovery must finish and the application must be assigned to an access profile/network before learning can help a client.

## Learn during use

1. Open the application in the console, enter the test device's source IPv4 address and start **10-minute learning** as an Administrator.
2. On that device, close unrelated tabs and applications. Open the selected application and exercise the authenticated workflow.
3. The discovery timer consumes that client's blocked requests. A candidate requires an allowed request attributed to this application alone within the previous 60 seconds. Known analytics and non-public destinations are excluded.
4. The worker links new domains to this application, marks the evidence `live-learning` with medium confidence and performs one Save & Apply per batch. Retry a blocked action after the next worker cycle. Newly allowed requests can reveal further dependencies.
5. Stop learning when finished. The session also ends after 10 minutes or at its 50-destination guardrail. Learned dependencies remain visible in the application and can be removed there. Pending policy changes, failed apply, inactive applications and revoked administrator access stop automatic learning.

Only one session can be active per source IP. The worker processes at most ten active sessions and a bounded event batch each cycle. Sessions, learned destinations, source events and audit records retain provenance. A source IP shared by multiple users/NAT is not a suitable learning device identity.

Correlation is evidence, not a guarantee of application ownership. Unrelated traffic from the same test device can enter a learning session; use an isolated test device and review the resulting dependencies. Ordinary traffic outside an explicit learning session remains review-only. HTTPS CONNECT exposes destination hostnames, not URLs or encrypted application content; already-open multiplexed tunnels may hide later requests. HAR import remains available for workflows not observable through proxy telemetry. No TLS interception or user credentials are introduced by this feature.

## Verification and deployment boundary

`tests/smoke_v3100.py` covers role/CSRF restrictions, structured PAC validation, source-package generation, failed publishing, atomic privileged publication, ignored discovery candidates, bounded learning and batch Save & Apply integration. Its transport test substitutes the privileged Squid transport; it does not start or validate a real Squid instance. `tests/pac_contract.cjs` executes generated JavaScript to verify destination routing and fallback.

Before upgrading production, use the VM acceptance checklist to validate actual Squid parsing/reload, Nginx PAC serving, Windows installation, firewall/direct routing, DNS, authenticated application workflows and browser failover timing. These behaviours require a real deployment and cannot be established from Python smoke tests alone.
