# Platform review — 3.12.4

Reviewed 2026-11-14. Scope: repository code, isolated databases, generated configuration, workflow tests and rendered GUI. The production VM, router, client GPO and external notification receivers were not accessed. This is an engineering review, not a penetration-test certification or a throughput benchmark.

## Findings resolved

| Area | Finding | Result |
|---|---|---|
| Dependencies | Runtime inventory matched published advisories for python-multipart 0.0.20 and Starlette 0.47.3; the local pip bootstrap was also outdated | Pins FastAPI 0.162.7, Starlette 1.3.1, python-multipart 0.0.33 and installer pip 26.3; adds dependency auditing to CI. Inventory matches do not establish that every advisory was exploitable in this gateway configuration. |
| Policy diagnosis | Simulator could allow unsupported ports/methods, miss literal-IP rules and consider only one legacy overlapping network | Matches standard base Squid ports and generated methods; literal IPv4 and the union of applicable source grants are evaluated. Gateway diagnostic sources are identified separately. New overlapping scopes remain rejected by existing creation/edit validation. |
| Policy diagnosis | Saved rules could be mistaken for deployed policy or for the policy at a historical log timestamp | Saved-policy/pending labels are explicit. Historical Squid log results remain the evidence of what happened then. |
| Endpoint routing | Proxy decision alone did not explain a PAC DIRECT bypass | Existing simulator also previews PAC routing and fail-open configuration. DNS-dependent subnet rules show uncertainty until the PC-resolved IP is supplied; the server performs no destination DNS lookup. |
| Health alerts | GUI thresholds differed from configured notification thresholds | Both use the same condition evaluator. Delivery severity/confirmation remain channel controls, distinct from immediate displayed health conditions. |
| Health posture | A stale cached sample could still produce a healthy overview | Stale sampling displays attention rather than a healthy claim. Health API also uses the sampler cache instead of synchronous DNS/service probes. |
| Client performance | Client pages performed synchronous reverse DNS for every device | GUI reads a persistent name cache. The low-priority performance worker examines at most 2,000 recent events and queries at most eight IPs per run, each capped at 0.5 seconds. Positive cache: one hour; failed lookup: ten minutes. Missing names fall back to IPs. |
| Slack routing | Scheduled policy-expiry failure fell into the general service category | Expiry failure belongs to the policy category. |
| Client filters | Inline range-change handler was blocked by the management CSP | Uses an external script event listener; browser regression verifies the range query changes. |
| Navigation | Non-admin roles saw an empty System group | The empty administrator group is hidden; endpoint permissions remain enforced server-side. |
| Data export | User-controlled CSV fields could begin spreadsheet formulas | Formula-like text receives an apostrophe prefix and CSV quoting, including whitespace/full-width prefix checks. Stored values are unchanged. XLSX uses explicit string cells. This protects original exports; spreadsheet re-save/re-import behavior varies. Prefer XLSX for human spreadsheet use and inspect modified CSVs before importing. |

## Review coverage

| Subsystem | Evidence / boundary |
|---|---|
| Profiles, VLANs and access | Combined save transaction, validation rollback, protected copies/deletes, admin/operator approval, scope selectors and Google starter regressions. |
| Squid publication | Generated grammar checks, base-hash checks, concurrent-edit preservation, deployed-only expiry and rollback regression tests. Live Squid/systemd reload still needs VM acceptance. |
| Application discovery | Public-target/pinned-egress restrictions, selected-tab isolation, secret-free evidence, explicit review and capture contracts. Unvisited user actions or future vendor changes cannot be fully discovered from one seed domain. |
| PAC / endpoint deployment | Generated JavaScript routing tests, preview agreement, Windows/Edge URL parity, bypass and fail-open settings. Real PAC caching/timeouts, GPO/Intune and independent router/DNS egress require pilot-PC testing. |
| TLS | Bounded PEM upload, matching key, date/hostname checks across OpenSSL versions, fixed root paths, reload failure rollback and permissions tests. Certificate issuance, CA trust rollout and real nginx/systemd behavior remain environment responsibilities. |
| Health / channels | Shared thresholds, severity/categories/recovery/reminders, masking, independent retries, queued tests and deduplication. Outbound delivery is mocked; no actual email or Slack recipient is contacted by the tests. |
| SNMP | Read-only/source/community/packet/bulk limits and loopback trap tests. Actual NMS receipt/polling must be verified remotely. SNMPv2c is unencrypted and belongs on a restricted management network. |
| Identity / GUI | Authentication, local roles, CSRF-protected changes, protected secrets and browser layout regressions. MFA/SSO is not implemented. |
| Telemetry / recovery | Retention guardrails, source attribution, cached sampling, CSV/XLSX export, portable state manifests and staged restore tests. No actual off-box backup target was configured. |
| Release | Migration compatibility, Python 3.12/3.14 CI, imports, template/JS/shell syntax, browser layout and release checksums. Capacity recommendations are starting estimates, not measured guarantees. |

## Feature decisions

| Decision | Feature | Reason |
|---|---|---|
| Keep | One Profiles & VLANs editor; unified Access inventory; separate Proxy bypass | Matches daily tasks without duplicate rule entry. |
| Keep | Both selected-tab recording and HAR import | Covers interactive/authenticated workflows the initial browser visit misses; unrelated PC traffic must not automatically grant access. |
| Extend in place | Policy Simulator with PAC diagnosis and URL input | Explains why access is allowed, blocked or direct without another configuration page. |
| Keep optional | Windows services, email, Slack, SNMP, fail-open and HTTPS PAC | Different environments need different deployment/availability choices. No destination or service is silently enabled. |
| Remove from routine UI | Empty admin navigation and advanced simulator fields until expanded | Reduces distraction while preserving controls. |
| Next priority | MFA or SSO for administration | Most useful identity improvement before broader exposure or more administrators. Requires a deliberate identity/recovery design; not silently enabled. |
| Next priority | Scheduled, encrypted off-VM configuration backup | Local rollback files do not survive loss of the VM/disk. Requires a selected destination, credentials and tested restoration. |
| Conditional | SNMPv3 and SIEM/syslog export | Valuable when network privacy or central event retention is required. Existing private-network v2c and local audit remain available. |
| Use existing external monitoring | Detect total VM/router/network failure | Poll from the NMS outside the VM using existing SNMP or a service check. The VM cannot send its own outage alert after total loss. |
| Defer | TLS interception, DLP, antivirus/content inspection, user-identity enforcement, HA clustering | These materially change architecture, client trust and support requirements. This gateway currently enforces explicit domain/IP allow policy; it is not a full cloud threat-inspection service. |

## Dependency security check

The initial complete runtime resolution was checked with pip-audit against public advisories, followed by an installed-environment audit after upgrading. The latter also covers development/audit tooling and pip, beyond the HTTP runtime. Results describe known advisories at the time of this review; they are not proof that no vulnerabilities exist. OS nginx/Squid/OpenSSL packages must still receive Ubuntu security maintenance on the VM.

## Comparison sources

- [Squid http_access](https://www.squid-cache.org/Doc/config/http_access/) and [security pitfalls](https://wiki.squid-cache.org/SquidFaq/SecurityPitfalls): base access guards and explicit ACL ordering inform the corrected simulator.
- [Cloudflare Gateway activity logs](https://developers.cloudflare.com/cloudflare-one/insights/logs/dashboard-logs/gateway-logs/): traffic evidence and filterable logs are useful operational tools. Existing traffic search/export remains; no cloud feature parity is claimed.
- [Zscaler alerts](https://help.zscaler.com/zia/about-alerts) and [policy troubleshooting](https://help.zscaler.com/troubleshooting-runbooks/zia-security-policies-troubleshooting-runbook): configurable event delivery and evidence-based policy diagnosis inform the consolidated local workflows.
- [python-multipart advisories](https://github.com/Kludex/python-multipart/security/advisories) and [Starlette advisories](https://github.com/Kludex/starlette/security/advisories): patched runtime pins and CI inventory audit.
- [OWASP CSV injection](https://community.owasp.org/attacks/CSV_Injection): formula-prefix protection, quoting and spreadsheet round-trip limitations inform export handling.

Sources checked 2026-11-14. No new cloud account, endpoint agent, external message or network integration is enabled by this review.
