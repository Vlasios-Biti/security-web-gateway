# Security Web Gateway v3.12.13 Acceptance Test

Integration/correction checks: upgrade an existing schema 018 database to 019 and confirm VLAN/profile/approved rules stay intact. Timing-only pending scores become Low/review. Move a pending candidate without adding access; move an enabled application domain and verify the source/target membership and publication result. Other memberships must stay intact, and protected targets require Admin. Test per-PC label save/clear/search with DNS fallback. Create an expiring read-only token in System → Integrations API; verify correct scope, rejected cookie/query-token/HTTP access, revoked/expired/disabled-owner refusal and 120/minute limit. Portable restore must revoke imported tokens and retain target-local PC labels. No real Slack/email/SNMP delivery is required for these tests.

Dependency review: choose an application and optionally a domain substring, status or confidence, then press Filter. Counts/pagination must cover all matching stored candidates, including rows beyond the old 500-result cutoff. Approve/Ignore must return to the same filter selection; completed rows show their status without review buttons. Reset returns to all applications with pending status. Filtering/history views must not change access policy. Verify the filter controls remain readable on mobile and desktop.

1. `readlink -f /opt/security-web-gateway/current` returns `/opt/security-web-gateway/releases/3.12.13`.
2. `/healthz` on `127.0.0.1:8200` and management HTTPS returns version `3.12.13`, mode `production`.
3. `SELECT MAX(version) FROM schema_migrations` returns `019`; `PRAGMA integrity_check` returns `ok`; `PRAGMA foreign_key_check` returns no rows.
4. `squid -k parse` and `nginx -t` succeed.
5. `security-web-gateway.service`, `squid.service`, `nginx.service`, and `security-web-gateway-deploy-helper.socket` are active.
6. Telemetry, storage-maintenance, discovery, source-sync and **performance** timers are enabled/active.
7. Squid priority drop-in exists and background workers use lower CPU/I/O priority.
8. PAC is reachable on `http://<SWG-IP>:8081/proxy.pac` and contains `PROXY <SWG-IP>:3128; DIRECT`.
9. Existing DIRECT bypasses remain effective after upgrade and are visible in Connection. Fresh installations contain no customer-specific bypass IPs.
10. A standard Windows user with Proxy Control installed cannot change proxy/PAC settings without administrator credentials.
11. Traffic Explorer updates via the telemetry timer; GUI requests do not parse `access.log` synchronously.
12. Overview uses cached health/traffic data and does not synchronously call systemd/DNS probes.
13. `System → Performance` receives samples after the performance timer runs.
14. If local DNS cache is enabled, Unbound answers on loopback and forwards successfully to enterprise DNS.
15. `System → Storage / Telemetry` shows age/storage/free-space guardrails.
16. Normal Admin application onboarding completes through the discovery timer and automatically validates/applies discovered public dependencies without a separate Deploy step.
17. HAR discovery does not persist the uploaded raw HAR and classifies obvious analytics/background endpoints as IGNORE.
18. `Policy Simulator` returns an explainable ALLOW/DENY result without changing policy.
19. `Why Blocked?` explains a denied event from effective network/profile/rule/application scope.
20. A correlated new blocked application dependency appears only as a review candidate; it is not auto-allowed.
21. Admin Save/approval validates and applies an effective policy diff immediately; Operator changes remain pending for Admin approval.
22. Existing production Squid policy is not auto-deployed merely by upgrading application code.
23. On failed upgrade cutover, DB/release/units and all worker timers can be restored by the rollback path.

24. Deleting an Application removes it from active policy management, preserves audit/discovery history, and allows the same application name to be recreated.
25. Legacy category names such as Google Maps do not break discovery approval.
26. Metadata-only pending changes are reconciled without creating a meaningless deployment.

27. While an Application discovery run is active, the Application page polls activity automatically and refreshes itself when the run completes; no manual browser refresh is required.
28. Access Profile choices in Add Application use the light-theme control styling and remain readable.

29. Admin Save on Applications, Domains, IP rules, Access Profiles and Network Scopes invokes the transactional Save & Apply path with validation, audit and rollback.
30. A metadata-only Save does not create a deployment record.
31. Operator Save never publishes production policy.
32. If effective pending policy existed before a new Save, the new Save does not silently publish it; Activity shows an exceptional approval queue.
33. Automatic application discovery started by an Admin applies only after discovery completes, and UI polling shows the final result without manual refresh.

34. System navigation contains Health & Performance, Storage, Backups and Administrators; Storage/Administrators are not duplicated under Policy & Tools.
35. System console shows cached CPU/memory/disk/proxy latency/connections/telemetry lag plus DNS, TLS certificate expiry, NTP, worker health, storage and recovery posture.
36. Live Traffic auto-refreshes every 10 seconds only while the user is not actively editing a filter control.
37. Access Profile selectors, profile statistics and the Include System Traffic filter use the light workspace visual system; no legacy black control blocks remain.
38. Overview policy coverage reports actual Application objects rather than system-domain rule count.
39. Applications provides summary metrics, card search and recent dependency health.
40. Activity provides approvals, drift, apply failures, backups, audit timeline and rollback readiness.

41. Connection is Administrator-only; Operators/viewers cannot change connection policy or download the Windows package. POSTs require valid CSRF.
42. Save & publish atomically replaces the static PAC and backs it up. Invalid input/failing publication does not overwrite stored settings. Test exact domain, wildcard boundary, IP and CIDR routing on Windows.
43. Unreachable proxy falls back DIRECT when enabled; disabled fallback returns only PROXY. A policy-denied request remains denied. Measure actual client recovery time and confirm router/firewall permits intended fallback.
44. Windows ZIP contains the target gateway's PAC address, installation guide, controller and optional GUI build helper. On a test PC, verify admin install, standard-user restrictions, PAC refresh, Stop/Start and initial-settings restore on uninstall.
45. Load the optional recorder in a test Chrome/Edge profile. Start on the application seed domain, sign in and click actions in the same tab. Confirm a button-triggered destination is captured and traffic from another tab/PC service is excluded.
46. Confirm recorder Stop, expiry, tab close and destination limit. Verify exports contain no URL paths/queries, headers, credentials or bodies. Import must create review candidates only; IP-based sessions must never grant access.
47. Restore policy state to another VM: sessions are revoked, active learning is stopped, and target-host connection settings/PAC are preserved.
48. Desktop and mobile navigation remain usable and Connection/Application pages do not overflow the viewport.
49. PC services are off by default, Administrator-only and scoped to chosen Access Profiles. Test Windows Update/Defender in SYSTEM context with appropriate WinHTTP/BITS/DO configuration. Turning off one profile must not disable shared endpoints used elsewhere.
50. Verify new-tab/pop-up and service-worker limitations on real business applications. Review candidates before applying; tab attribution does not prove endpoint necessity.

51. Health notifications are Administrator-only; password/webhook values never appear in HTML, polling, audit, delivery history or policy-state exports.
52. Configure real SMTP TLS and Slack on the VM. Explicit tests must reach intended recipients/channel and show results without holding the GUI request open.
53. Repeated failed checks produce one incident digest, confirmed recovery produces a recovery message, and email failure does not duplicate successful Slack alerts. Verify retry and optional repeat intervals.
54. Turn global notifications off and verify no automatic messages. Confirm candidate mode sends no messages, including test requests.
55. Expire a deployed test rule while an unrelated policy is pending. Verify new requests are denied for the expired destination and pending work remains unpublished; account for existing CONNECT tunnels.
56. Exercise concurrent edits during a slow apply. The recorded snapshot must match the sent configuration and newer work must remain pending.
57. Restore a portable/legacy export into a test VM of this release. Verify writer quiescence, archive/hash checks, migration, rollback-on-failure, target credentials/PAC preservation and queued-job revocation.
58. Verify the new helper RuntimeDirectory and health-monitor timer permissions on Ubuntu. Confirm an external monitor covers full-VM/network/monitor outages.


## 3.12 consolidated access acceptance

- Open Access, add a public website and select either an Access Profile or a VLAN. Only the chosen method is visible/submitted. Confirm discovery and resulting policy, then exercise a login/button workflow using capture as needed.
- Add an IPv4 destination in the same flow; confirm its explicit destination rule appears in Access. No website discovery is implied for IP/subnet entries.
- Delete a mistaken profile. Confirm it disappears, the name can be reused, the network/application objects remain and another profile's shared access still works. Confirm unauthorized/invalid-CSRF deletion fails.
- On fresh install confirm only the unassigned Google Search starter appears. Upgrade must not replace configured Google dependencies or grant it to existing networks automatically.
- Save multiple proxy bypass destinations, change connection behavior and confirm the bypass list survives unchanged. Verify DIRECT paths with actual clients/router/DNS.
- Enable SNMP read-only polling with an explicit management IP, high UDP port, long private community and manager source list. Verify authorized GET/GETNEXT/GETBULK, wrong-community/source rejection, SET denial and actual firewall isolation.
- Enable SNMP traps and queue a test; independently confirm receiver receipt. Local SENT records UDP submission only. Exercise confirmed incident/recovery and test total VM loss using NMS polling failure detection.
- Pilot Windows package/GPO deployment and Edge JSON. Verify fail-open with both Squid-only loss and full VM/PAC loss, independent DNS/routing and direct egress. Do not infer universal behavior for independent application proxy stacks.


## 3.12.4 combined profile/VLAN acceptance

- Create a profile, enter a new subnet/VLAN and select Google Search on one page; verify both records and their membership are saved and applied with one operation.
- Repeat with an existing VLAN using the prefilled shortcut; confirm no duplicate network is created.
- Try a duplicate profile name, overlapping subnet and invalid membership; confirm no orphan VLAN/profile is inserted and entered data stays visible.
- Add a VLAN while editing a profile and keep an existing VLAN checked; verify both memberships remain.
- Verify operator/viewer and CSRF boundaries, Copy preview without mutation, and a new copy requires its own selected/new VLAN.


## 3.12.4 navigation regression

- Verify Profiles & VLANs, Proxy bypass and Alerts & SNMP fit on one line on desktop and in the mobile drawer, including browser zoom.
- Verify Alerts & SNMP appears exactly once as a direct primary entry for Admin, with channel links that scroll to the correct Email/Slack/SNMP cards.
- Run `python -m playwright install --with-deps chromium` and `python tests/browser_navigation_layout.py` for the real-browser layout regression included in CI.


## 3.12.4 PAC / TLS / Slack acceptance

- Connection: copy PAC into a pilot PC's automatic proxy script setting. Verify the Windows ZIP and Edge JSON contain that same saved URL. Changing the URL requires redeployment to existing PCs.
- HTTPS: resolve the selected hostname from that PC, install the issuing CA, install a full PEM chain/matching key via Connection, and open the PAC anonymously with normal TLS verification. Verify management login still works. Confirm wrong key/hostname and expired certificates fail without replacing the old certificate.
- Slack: select a single event category, critical-only severity, no repeats and recovery on/off. Use mocked local tests first; then explicitly send a channel test using your own webhook and confirm receiver delivery. Test messages/recovery must not mention people. Verify member/group mentions with authorized IDs and Slack notification preferences. Email/SNMP settings must remain independent.
- Disconnect the VM on a pilot PC with independent DNS/router/direct egress and verify the chosen PAC fail-open behavior. Target systemd/nginx behavior, client CA trust and actual Slack push delivery require environment testing.


## 3.12.4 system review acceptance

- Simulator: enter a PC IP and website URL. Compare proxy decision with the saved policy; verify DIRECT bypass is clearly separate. Pending policy must not be described as live/historical policy. Unknown PC-side DNS for a CIDR bypass must not be guessed.
- Validate unsupported ports, CONNECT on 80, non-CONNECT on 443, literal IP grants and legacy source overlap handling against generated Squid policy. Existing overlap prevention remains enabled.
- Change Health thresholds in Alerts & SNMP with outbound channels disabled. The Health page should reflect the new values without sending notifications. Stale sampling must put the overview into attention state.
- Open Clients with slow/unavailable DNS. The page must show IPs promptly; worker lookups are bounded and unsuccessful names remain optional.
- Inspect original CSV export formula-like notes/network names and XLSX text typing. Use XLSX for spreadsheet review; edited/re-saved CSVs require inspection before re-import.
- On the real VM, verify live nginx/Squid/systemd behavior, installed certificate/CA trust and remote NMS/Slack/email receipt. On a pilot PC verify PAC refresh, direct bypass and full VM outage with independent DNS/router egress. These are not proven by isolated source tests.


## 3.12.5 PC activity acceptance

- Monitoring → PC activity: search current cached names, source IPs, VLANs/networks across all pages. Open one PC and filter by domain/decision/date; pagination, rankings and exports must retain that source IP.
- Verify first/last matching timestamps and the latest network/VLAN agree with the selected filters. Compare requests to actual Squid logs for two different PCs.
- Keep client source IPs visible to the proxy; document NAT/VPN aggregation. Validate DHCP history or reservations for historical device ownership and PTR records for current readable names.
- Confirm HTTPS shows domain/port rather than encrypted contents. DIRECT bypass/fallback does not appear in proxy telemetry. AD/GPO deployment is distinct from unimplemented user authentication/group policies.

## 3.12.6 detailed review acceptance

- Activity must display pending state without clearing it. Viewer/auditor can read it; only an administrator can approve production changes. A failed attempt must not become the successful baseline.
- Invalid traffic IDs, dates, IPs and ports must return HTTP 400. Oversized HAR must fail before creating an application. Archived profile status cannot be reactivated.
- Verify fresh installation contains `current/privileged/tls_install.py` before testing certificate renewal on a pilot VM.
- See `docs/DETAILED_FUNCTION_AUDIT.md` for automated results, function coverage and the outstanding real VM/PC/NMS checks. Do not equate that report with a completed independent security audit.

## 3.12.7 security and recovery acceptance

- Upgrade to schema 018 with the shipped upgrade script; confirm saved profiles/VLANs/users and PAC endpoint remain intact. Existing queued browser jobs continue and source-sync work is not claimed by the GUI queue.
- Confirm protected applications/profile membership require Admin through discovery, dependency review and ordinary editors. Operator proposals remain pending for publication; disabled/downgraded actors cannot auto-approve queued work.
- Use only a dummy pilot account to check login/reset behavior. A password reset must retain the new credential and cancel an older in-flight login.
- Inspect a custom exported archive as 0600 from creation through publication. Cross-host restore must keep the target PAC URL in Connection, Windows package and Edge JSON.
- Pilot the Windows controller separately; legacy untrusted owners/write ACLs or reparse paths must be inspected by an administrator. Pure backup validation tests do not prove real machine ACL behavior.
- See `docs/SECURITY_CORRECTIONS.md` for verified corrections, source-only concerns and remaining deployment checks. The Cloudflare skill was disabled at the user's request.

## 3.12.8 PAC setup acceptance

- As Admin, Overview → Connect a PC must open Connection at the visible PAC URL field. Copy address and Open PAC use the configured endpoint; the PAC address editor remains collapsed and the HTTPS certificate card is visible separately.
- From a client without an administrator session, the configured /proxy.pac must return the PAC script instead of nginx 403. Install/upgrade grants only parent-directory search permission; production.env, notifications.json and TLS keys retain their private modes.
- `sudo python3 tests/pac_permissions_contract.py` verifies a disposable public PAC is readable by an unprivileged UID while dummy private files remain unreadable. It never changes installed configuration.

- As Admin, expand Connection → Blocked page. Save company name/message/contact and a PNG logo (at most 128 KB, 2048 × 2048). Preview must show escaped text; saving without a new file retains the logo, and Remove clears it. Invalid uploads must preserve the previous settings. Other roles cannot preview or change branding.
- `sudo python3 tests/squid_block_page_contract.py` starts a disposable native Squid with loopback origins: allowed HTTP/CONNECT must return 200; denied HTTP redirects to the fixed branding page; denied CONNECT must return 403 without a redirect. Requires installed Squid and unused local port 8081; use a test runner, not the production appliance.
- On a pilot PC test a fresh denied HTTP URL and denied HTTPS host, an allowed host, a direct bypass and proxy outage separately. Verify the source IP in Squid logs belongs to the intended VLAN/profile. PAC alone does not enforce applications that ignore system proxy settings or prevent users changing their routing.
