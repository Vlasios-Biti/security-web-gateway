# Connection and application learning

## Simple network and profile setup (3.11.1)

Open **Policy & tools → Networks & VLANs → Add network**. Enter a name and IPv4 subnet (or `/32` for one computer). VLAN ID is an optional label; access is matched by the source IP/subnet. Choose access profiles if available and save. Proxy policy membership defaults to enabled. Notes, a ticket reference and the metadata-only mode remain under **More options**; routine changes receive an automatic audit note.

Use **Copy** on an existing network to prepare another with the same access. Give it a new name/subnet and optional unique VLAN ID, adjust profiles if needed, then **Create copy**. Opening the copy screen changes nothing. Copying includes direct rule/application scopes as well as the selected profiles; it does not configure the physical router or Windows clients.

Profile editors show applications and networks first. Application editors show identity and profiles first. Optional integration settings and custom exceptions remain in **More options** and retain their saved values. Email/Slack and optional Windows-service settings expand when enabled; disabling a channel does not erase its configuration. Success messages can be dismissed. Failure and pending-change messages remain visible; review them in **Activity**.

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

A server browser cannot observe all requests behind a real user's login or guarantee discovery of every application workflow. Use workflow capture for those interactions and assign the intended application access to a profile/network.

## Capture the actual browser workflow

IP address and timing correlation do not prove which application initiated a request. IP-based automatic learning is disabled, including the legacy Start endpoint. The background worker stops active sessions left by earlier review builds without adding rules or applying policy. Ordinary correlated telemetry candidates remain suggestions for manual review.

The optional **SWG Selected Tab Capture** extension uses Chromium's webRequest tab ID to retain destination hosts from the explicitly selected tab. Download it from the application detail page. Extract it and Load unpacked in Chrome/Edge Extensions, subject to your organisation's developer/extension policy. This source build is not a signed store distribution.

1. Open the application's seed domain and start capture from the extension popup.
2. Sign in and exercise the relevant buttons in that same tab. Attempted requests triggered by those interactions are recorded, including requests that fail.
3. Stop and export the JSON. Upload it using **Import & review domains** in that application.
4. Review candidates and approve intended changes through the existing role-aware Save & Apply workflow. Import alone never publishes policy.
5. Retry workflows blocked at an earlier dependency; subsequent domains may only become visible after that dependency is allowed. Capture again if needed. HAR import remains an alternative without an extension. Both controls appear side by side on the existing application detail page.

Other tabs, native Windows services and requests with no tab ID are excluded. New popup windows/tabs need a separate capture. Some background/service-worker requests have no attributable tab. Subframes and embedded third-party resources are included; tab association does not prove every endpoint is essential. Navigating that tab to another website records its activity until Stop. This build excludes IP literals and non-standard ports.

No cookies, headers, request/response bodies, full URLs or query strings are retained. Data stays in browser session storage until exported. Clear removes it; browser closure clears session storage. Capture stops after ten minutes, tab close or 500 destinations. The importer requires a matching seed, bounds input to 1 MiB/500 destinations and stores normalized host/protocol/count/type evidence only. Both imported formats are untrusted evidence, not cryptographic proof of provenance. HAR imports retain only host/protocol/method/count evidence, not paths, queries, headers or bodies; upload middleware may use temporary spooling while processing the file. No TLS interception or endpoint agent is introduced.

Chrome reference: https://developer.chrome.com/docs/extensions/reference/api/webRequest

## Optional PC services

**Connection → Optional PC services** provides opt-in Windows Update, Defender security updates and Windows connectivity-check profiles. Each requires selected active Access Profiles; none is enabled by default. Saves use policy validation and Save & Apply. A pending/failed apply means desired settings are not yet effective.

Profiles share atomic rules. Disabling one does not disable endpoints still needed by another active profile or manually allowed elsewhere. These are proxy ALLOW rules, separate from DIRECT bypasses, and not deny overrides. No profile grants all of *.microsoft.com. Some permitted update hosts also distribute Microsoft Store or other Microsoft downloads; hostname policy cannot distinguish URL paths or the process requesting them.

Presets are reviewed starting sets, not exhaustive/self-updating Microsoft feeds. Requirements vary by Windows version, WSUS/Intune/Configuration Manager and update source. Source guidance and endpoint patterns are visible in each card (reviewed 2026-11-09). The Defender preset covers update downloads, not all Defender cloud protection or sample uploads.

Windows services may use WinHTTP, BITS and Delivery Optimization settings rather than the browser PAC. Allowing destinations in Squid does not configure those components, the router or DNS. Validate SYSTEM-context proxy settings, HTTP range requests, downloads and P2P/firewall requirements on a test PC. Enabling a card changes no Windows system settings by itself.

Microsoft sources:
- https://learn.microsoft.com/windows/privacy/manage-windows-11-endpoints
- https://learn.microsoft.com/en-us/defender-endpoint/configure-network-connections-microsoft-defender-antivirus
- https://learn.microsoft.com/en-us/troubleshoot/windows-client/networking/internet-explorer-edge-open-connect-corporate-public-network
- https://learn.microsoft.com/en-us/troubleshoot/windows-client/installing-updates-features-roles/windows-update-issues-troubleshooting

## Verification and deployment boundary

Python regressions cover roles/CSRF, PAC publication, review-only capture import, data minimization, retirement of IP-based grants, optional service scope, shared rules and transactional protocol conflicts. tests/tab_capture_contract.cjs verifies scoping, expiry and privacy. tests/browser_capture_e2e.py exercises a real extension with a button-triggered request and unrelated second-tab traffic, using synthetic hosts resolved to loopback and a disposable Chromium profile.

VM acceptance still requires actual Squid/Nginx behaviour, Windows installation, authenticated business workflows, firewall/DNS routing and failover timing. The extension test proves the synthetic workflow; it cannot establish complete coverage of every browser/application/network scenario.
