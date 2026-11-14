# Access and connection guide — 3.12.8

## Company block page and allowed-only access

Open **Connection → Blocked page**. Enter the company name, title, message and optional IT contact. Upload a PNG logo up to 128 KB and 2048 × 2048; saving without an upload keeps the current logo. **Preview saved page** opens the saved result. Only administrators can view or save these settings.

Install/upgrade publishes the fixed public HTTP page at `http://<gateway-IP>:8081/blocked`. Denied HTTP requests redirect there. Denied HTTPS CONNECT requests retain status 403; browsers normally show their own proxy/connection error rather than the response HTML. A branded page inside HTTPS requires managed TLS inspection and client CA trust; this release does not enable that. See [Squid deny_info](https://www.squid-cache.org/Doc/config/deny_info/) and [Squid custom error limitations](https://wiki.squid-cache.org/Features/CustomErrors).

Branding is stored in `/etc/security-web-gateway/block-page.json`, with rendered public HTML in `blocked.html`. The JSON stays private, while the public page contains the company text/logo only. Existing branding survives an upgrade. Portable policy exports/imports do not move this VM-local setting; provision it separately on a replacement appliance. The public page uses the appliance's configured IPv4, independently of the optional HTTPS PAC address.

The proxy base policy is default deny: allowed profile/application/domain/IP rules take priority and everything else is denied. If a forbidden platform partly opens, inspect its actual host and source IP in **Monitoring → Traffic**, the matching access profile, direct bypasses and the active deployed policy. An IP/subnet allow rule can permit multiple sites on shared infrastructure. Deleting a membership from one profile does not revoke an allow inherited from another matching scope. Do not treat missing styles/images as proof the main site is blocked.

PAC affects clients that honor its proxy settings. Direct bypasses, local-traffic exceptions and outage fallback deliberately permit traffic outside Squid; direct traffic is not covered by its allow list or telemetry. Enforce managed browser/endpoint settings where required. A network firewall policy is needed to prevent arbitrary direct connections; configure its outage behavior to match the intended fail-open requirement. The GUI does not change router rules automatically.

## Profile and VLAN in one save

Open **Profiles & VLANs → Create profile & VLAN**. Enter the profile name, select existing VLANs or expand **Create a VLAN here** and enter its subnet plus optional VLAN ID. Select the allowed applications/domains/IPs in the same form and save once. The network name is filled from the profile name; no separate network name, change reason or ticket is required.

A new VLAN and its profile/memberships are saved in one database transaction and followed by one validated apply. Invalid/duplicate profile names, overlapping subnets or invalid memberships roll the entire desired-state save back. Failed forms keep entered fields. An apply failure retains the desired change as pending while the previous live policy remains active. Operators can select existing VLANs and propose custom profiles; creating a new VLAN remains administrator-only.

Editing a profile can add a new VLAN while retaining checked existing VLANs. **Copy** prepares the same access selections with a new profile name and no preselected VLANs; opening it makes no changes. VLANs left after a profile is deleted appear under **VLANs without a profile**, with a shortcut that prefills the creation form. The separate Networks menu has been removed from primary navigation; legacy routes remain compatible.

VLAN ID is a descriptive identifier. The source subnet/IP determines proxy matching; saving here does not create physical VLAN interfaces or change router configuration.

## One place to grant access

Open **Access → Add access**. Enter a website/domain or an IPv4 address/subnet and select **Access profile** or **VLAN / network**. Only the selected method's controls are displayed. A website/domain starts public browser dependency discovery; an IP/subnet becomes an explicit HTTP/HTTPS destination rule without a website scan. All applications and standalone rules appear in Access. A successful public scan is evidence from visited pages, not a guarantee of every login/button workflow; selected-tab and HAR capture remain available inside the application's page.

Existing entries with both profile and direct-network assignments show **Keep existing access**. Saving that choice preserves the existing union. Selecting a new method intentionally replaces the previous assignments. Old API/import payloads remain compatible. New GUI forms cannot accidentally submit hidden selections from the other method.

**Proxy bypass** is separate: destinations there always use DIRECT, following endpoint routing/DNS. Connection saves preserve the bypass list. **Monitoring** groups traffic, health, and Alerts & SNMP. **Connection** contains deployment, fail-open behavior and optional Windows services. Profile deletion is confirmed and audited; it archives the profile and removes only its memberships, preserving shared networks, applications and rules. Admin approval/pending-change rules still apply.

## Generic Google starter

Install/upgrade runs a transactional, one-time default initializer after schema migration, first against the upgrade shadow DB. Fresh installs expose Google Search with a small exact-host HTTPS starter (google.com, www.google.com, consent.google.com, www.gstatic.com, ssl.gstatic.com). There are no customer-specific applications. The empty old Maps placeholder is retired; configured applications are retained. Existing configured Google access is not replaced. A newly filled/created starter is unassigned, so adding it never silently grants access to an existing VLAN or profile. Assign it through the same Access editor.

The starter is intentionally narrow, has no *.google.com wildcard and is not a complete vendor-maintained endpoint feed. Test actual searches/consent in your environment and review captures for missing dependencies. Hostname policy cannot restrict HTTPS to the /search path or prove that every other feature on the same allowed hostname is inaccessible.


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


## Windows rollout and availability preference

The Windows package installs machine-wide system PAC configuration. For a small fleet install the package on each PC; for a domain fleet distribute the same approved/signed package with an elevated GPO startup or Intune install process. A GPO deployment note is included in the ZIP. Browser/application proxy stacks remain distinct; do not assume a Windows system proxy setting configures every native service.

Connection also offers gateway-specific Microsoft Edge ProxySettings JSON. Deploy it with your Edge policy tooling; ProxyPacMandatory follows the inverse of the central fail-open switch. With fail-open enabled, Edge is permitted to use DIRECT if PAC loading fails, while a loaded PAC returns PROXY host:port; DIRECT when the proxy is unreachable. Policy JSON must be redeployed if these browser-policy settings change. This is an optional Edge-specific deployment, not automatic configuration of all browsers/services. [Microsoft Edge ProxySettings](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/proxysettings) and [Windows proxy deployment](https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/configure-proxy-server-settings) document the supported policy paths.

Availability-first operation requires independent DNS/routing and firewall permission for direct web egress. During fallback traffic has none of this gateway's filtering/telemetry. A policy denial is not treated as a proxy outage. Client timeouts, cached PAC state and existing connections affect transition timing; this is not an instantaneous universal failover guarantee. The existing Windows controller has no background reachability watchdog; clients that mandate remote PAC or ignore normal PAC fallback require their own tested deployment policy. Test both proxy-only failure and complete VM/PAC-server loss on a pilot PC before rollout. Strict firewall prevention of all direct egress conflicts with fail-open internet access unless the network itself also switches policy during an outage.


### PAC address and HTTPS (3.12.4)

Open **Connection**. Copy the PAC address into Windows Settings → Network & Internet → Proxy → Use setup script. The Windows ZIP and Edge policy JSON use this same saved address. Existing installations keep their installed address until the package/GPO is redeployed. The script URL is not the path of the PowerShell installer.

Expand **Address & HTTPS certificate** to choose HTTP (port 8081) or HTTPS (443) and the gateway hostname. The server serves `/proxy.pac` without a login on both listeners. DNS must resolve the hostname on PCs. Before HTTPS rollout, install a matching trusted certificate and deploy its CA chain to PCs; do not bypass TLS verification. HTTPS protects PAC distribution and does not turn the explicit Squid proxy into an HTTPS proxy.

The same section accepts a PEM full chain and unencrypted matching PEM private key, up to 20 KB each. Production Admin only, CSRF protected. The helper checks key pairing, dates, the configured management FQDN and any selected HTTPS PAC hostname. It writes only the standard management.crt/key paths, tests nginx, reloads and restores old files if validation/reload fails. Customized nginx TLS paths require your existing external renewal process. It does not issue certificates, change DNS or install client CA trust. Prefer your existing automated renewal process if certificates are managed by an ACME client. Private keys are not shown or exported.
