# Changelog

## 3.12.7

- Prevents an in-flight login from overwriting a newer password reset; session insertion checks the verified credential under a write transaction. Failed-login counters update atomically without overwriting a changed credential.
- Enforces protected application/profile membership permissions across name-based discovery, dependency review, service helpers and deferred approval; queued work rechecks current enabled actor authority. Candidate review joins the policy edit lock.
- Fixes Add access passing FastAPI Form objects into real SQLite discovery creation. GUI source discovery is explicitly queued outside the request/edit lock, with migration 018 preserving old queued browser runs and separating synchronous source-sync ownership.
- Normalizes HAR/discovery destinations before storage and again at approval. Generic hostname tokenization avoids repeated suffix matching; HTTP response work has a shared redirect deadline and closes timed-out connections.
- Creates portable exports privately from the first write and atomically replaces their destination. Restore retains target pac_endpoint alongside connection_policy, including absence/default semantics.
- Upgrade rollback uses a new snapshot after writers stop, preserves late credential changes and clears sessions. Fresh install gives the appliance data parent root ownership.
- Windows controller validates backup identity and fixed registry targets, rejects untrusted/reparse storage and replaces directory ACLs explicitly. No live Windows registry/ACL or VM changes were made during review.
- Disables the Cloudflare security-audit skill at the user's request and records ordinary review results and remaining operational checks separately.

## 3.12.6

- Adds a detailed functional review and catalog of 405 application functions, with measured execution coverage and explicit deployment-validation limits.
- Adds a 116-endpoint role/CSRF/anonymous matrix plus login/logout, malformed-hash, lockout, session-revocation and concurrent-last-admin regressions.
- Makes Activity GET read-only and accessible to viewers/auditors; separates failed apply attempts from successful deployment baselines.
- Serializes administrator changes before the last-enabled-admin check; rejects malformed stored hashes without a server error and prevents reactivation of archived profiles.
- Rejects malformed/out-of-range traffic filters with HTTP 400, removes blocking DNS from domain saves and sanitizes XML-invalid XLSX text characters.
- Bounds new HAR uploads before creating application state and includes the privileged TLS module in fresh-install release payloads.
- Records the user's security-audit skill preference in AGENTS.md. A reconnaissance-only security run remains explicitly incomplete; functional tests are not a clean-audit claim.

## 3.12.5

- Makes Monitoring → PC activity the entry point for identifying recorded source IPs, current DNS names, observed networks/VLANs, request/decision/byte totals and distinct destinations.
- Adds server-side PC search and inventory pagination. Per-PC domain/decision/date filters, paginated request history and scoped exports preserve the selected IP and traffic context.
- Corrects per-PC first/last matching timestamps and latest network/VLAN metadata to use the same filtered window, rather than all retained events or lexicographic MAX labels.
- Explains NAT/DHCP, current-DNS vs historical identity, HTTPS CONNECT visibility and DIRECT logging boundaries. Documents optional AD/GPO deployment and explicitly distinguishes unimplemented AD authentication/group-policy mapping.
- Adds request-isolation, export, pagination, name-search and historical-metadata regressions plus browser checks for PC views.

## 3.12.4

- Updates the audited HTTP/upload stack to FastAPI 0.162.7, Starlette 1.3.1 and python-multipart 0.0.33. Install/upgrade updates pip to 26.3; CI checks known installed-package advisories.
- Reviewed access/VLAN onboarding, discovery/capture isolation, policy publication/expiry/rollback, PAC/HTTPS deployment, alerts/SNMP, authentication, telemetry/storage/export and release checks.
- Corrects saved-policy simulation for Squid safe ports/methods, literal IPv4 rules, diagnostic sources and legacy overlapping source scopes. Adds PAC bypass/fallback diagnosis without server DNS calls; full website URLs are accepted and invalid inputs retained.
- Clearly separates saved-policy preview from deployed behavior and historical Squid log evidence. No extra primary menu or duplicated policy editor.
- Uses shared configured alert thresholds on Health, places expiry failures in Slack's policy category, hides empty administrator navigation from other roles and avoids a healthy overview with stale samples.
- Fixes the client time-range selector blocked by CSP by using an external event handler.
- Removes blocking reverse-DNS requests from client pages. A bounded worker resolves up to eight recent clients per run with per-query timeout and persistent positive/negative caches. Health API reads cached samples.
- Protects formula-like CSV text cells in policy/traffic exports, including leading whitespace and full-width prefixes; XLSX remains explicit text. Stored policy/telemetry values are unchanged.
- Updates the platform review with feature decisions, source comparisons and the remaining VM/client/NMS acceptance checks.

## 3.12.3

- Connection shows a copyable PAC setup-script URL and one HTTP/HTTPS hostname setting shared by Windows package, installer build and Edge GPO downloads. Existing PCs need the changed address redeployed.
- HTTPS PAC is served as a static anonymous nginx location; upgrades preserve the existing nginx configuration and restore it on cutover failure.
- Admin/CSRF-protected PEM certificate renewal validates key pairing, validity and management/HTTPS PAC hostname coverage. Fixed root-managed destinations, nginx validation, reload and rollback; custom nginx TLS paths remain managed externally. CA trust and DNS must be deployed to PCs separately.
- Slack has independent event categories, urgency, recovery, repeat interval, compact/detailed messages and explicit member/user-group mentions. Tests and recovery never mention people; changing a channel label does not reroute its webhook.
- Adds workflow tests for endpoint parity, permissions, Slack filters/mention handling and TLS rollback. Notification tests mock remote delivery.

## 3.12.2 — readable navigation and discoverable SNMP

- Corrects the legacy fixed icon width being applied to menu text. Primary labels stay on one line and inherit the correct active color; numeric badges retain their own sizing.
- Profile header status badges stay compact instead of stretching to the description height.
- Alerts & SNMP is a direct primary menu entry, with channel jump links inside the settings page. Admin-only permissions and opt-in settings remain unchanged.
- All shared stylesheet URLs are versioned to avoid stale cached navigation styles.


## 3.12.1 — profile and VLAN in one save

- One Profiles & VLANs entry and combined editor for profile name, existing/new VLAN and allowed applications/domains/IPs. New network names are automatic; notes remain optional.
- Atomic combined save rolls back network/profile/membership creation together on validation failure, preserves failed input and invokes one normal Save & Apply. Existing role/CSRF/pending-approval controls remain.
- Profile Copy prepares access selections without silently copying production network assignments. Unassigned existing VLANs have a prefilled Create profile shortcut and reference-protected cleanup. The combined page is a primary menu entry; secondary labels/icons and long option lists were checked for readability.
- Existing standalone network routes remain compatible; no database migration beyond 017.


## 3.12.0 — unified access and monitoring

- One Access inventory/add flow for websites, domains and IPs; one profile-or-VLAN selector across application discovery/editing, standalone rules and bulk defaults. Existing mixed assignments can be preserved explicitly.
- Dedicated proxy bypass page, grouped Monitoring menu, confirmed/audited profile deletion and readable responsive login.
- Transactional unassigned Google Search starter on install/upgrade; configured applications remain untouched. No organization-specific starter data.
- Optional SNMPv2c read-only polling and incident/recovery traps, configured alongside email/Slack; source/community checks, bounded responses and loopback transport tests. SNMPv3 and INFORM acknowledgements are not included.
- Optional Edge PAC policy JSON and GPO deployment guidance; no new schema migration beyond 017.


## 3.11.1 — simpler administration and readable surfaces

- Network creation needs only a name and subnet; VLAN ID and access profiles are optional. Proxy membership defaults to enabled. Optional notes/reference live under More options; audit notes are generated when omitted.
- A Copy action prepares a network with the source profiles/direct application and rule scopes. New subnet/VLAN identifiers are required where applicable; the original is unchanged. Explicit profile deselection is respected, and failed network forms retain input.
- Simplified profile/application/rule editors, shorter save feedback and dismissible success messages. Optional channel/service configuration expands on demand. Error and pending-approval feedback stays visible.
- Unified legacy light surfaces, readable VLAN badges, checkbox sizing, secondary text/link contrast and responsive action layouts. Versioned UI asset URLs avoid stale stylesheet/script caches.
- No database migration beyond 017; existing policy, credentials and audit history remain compatible.


## 3.11.0

- Added Administrator-only GUI configuration for health email/Slack notifications, protected credential storage, explicit channel tests and live delivery status.
- Added an independent monitor with incident confirmation/recovery, digesting, repeat control, per-channel retry/backoff and resource/service/backup-age checks.
- Enforced expired grants in generation/simulation and added deployed-snapshot expiry without publishing pending changes.
- Serialized GUI/background policy editing, froze publication snapshots, retained concurrent pending work and added base-hash/managed-grammar validation in the privileged helper.
- Hardened browser discovery with blocked Service Workers and an authenticated, public-IP-pinned loopback proxy.
- Fixed portable backup manifests, added safe legacy archive staging, quiesced restore writers, atomic database cutover and rollback.
- Added migration 017, health-monitor systemd units and regression tests.

## 3.10.0

- Refined console spacing, typography, cards and responsive layouts; combined live/search traffic navigation and kept audit access under Activity.
- Added Administrator-only Connection settings for fail-open, local routing and exact/wildcard domain plus IPv4/CIDR DIRECT bypasses.
- Added structured, validated, atomic static PAC publishing with backup through the restricted helper. Fresh installs omit legacy customer-specific bypass IPs; upgrades preserve existing PAC.
- Added gateway-configured Windows source/controller packages with setup instructions and an optional GUI build helper.
- Replaced IP-based automatic grants with an optional selected-tab Chrome/Edge recorder and privacy-preserving, review-only import. Legacy active sessions are stopped without changing policy.
- Added optional Windows Update, Defender security updates and connectivity-check presets, scoped to Access Profiles with source guidance and shared-rule safeguards.
- Browser auto-approval now honours selected/ignored candidates; classified analytics are excluded.
- Added schema migration 016, regression tests and deployment acceptance checks. Policy rollback and cross-host restore stop learning; cross-host restore retains target PAC settings.

## 3.9.0

- Rebuilt the management experience around a professional enterprise operations-console design created in Figma.
- Reorganized navigation: System now owns Health & Performance, Storage, Backups and Administrators; Policy & Tools contains policy, investigation, import/export and audit workflows only.
- Added a unified System operations console with CPU, memory, disk, proxy latency, connections, telemetry lag, performance trends, service/worker status, DNS health, TLS certificate expiry, NTP synchronization, uptime, storage/retention posture, backup/rollback state and operational alerts.
- Added cached system-health signals for swap pressure, host uptime, NTP synchronization, management certificate expiry and worker/service status.
- Redesigned Overview with real application counts, performance/telemetry state, recovery posture and corrected policy coverage semantics.
- Redesigned Applications into a managed-service workspace with summary metrics, search, dependency health and exception-driven discovery status.
- Redesigned Activity into an audit/recovery console with approval queue, configuration drift, apply failures, backups and rollback readiness.
- Added safe 10-second auto-refresh to Live Traffic while avoiding refresh during active form editing.
- Removed legacy dark controls from the light workspace, including Access Profile selectors, profile statistics, system-traffic filter, telemetry and policy cards.
- Simplified Access Profiles and Administrators terminology.
- Added v3.9 design/IA CI contracts while preserving v3.8 Save & Apply, default-deny enforcement and schema 015.

## 3.8.0

- Replaced the normal two-step Pending/Deploy operator workflow with transactional **Save & Apply** for Administrators.
- Admin Save now renders the effective Squid candidate, validates it through the restricted privileged helper, applies atomically, reloads/verifies Squid, audits the action and automatically rolls back on validation/reload failure.
- Applications, automatic discovery, standalone Domain/IP rules, Access Profiles, Network Scopes, protected System Rules, approved dependency candidates and successful Bulk Imports use the same Save & Apply service.
- Automatic application discovery started by an Admin applies only after discovery completes; Operator-initiated changes remain pending for Admin approval.
- Added a global apply lock so concurrent apply operations are serialized.
- Added a pre-existing-diff guard: a new Save cannot silently publish unrelated older pending changes.
- Metadata-only saves reconcile without creating meaningless deployment history.
- Renamed the primary Changes workflow to **Activity**. Activity is now primarily history, drift, audit and rollback; manual approval appears only for Operator or legacy pending changes.
- Kept full deployment/audit history and rollback capability while removing routine deployment friction from the GUI.
- Added migration 015 and v3.8 regression coverage for Admin auto-apply, Operator approval, legacy-pending guard, no-op saves and apply failure behavior.
- Default-deny policy semantics and the restricted privileged deployment boundary remain unchanged.

## 3.7.1

- Application detail now polls lightweight discovery activity only while a browser discovery run is active.
- The page automatically refreshes once discovery completes or fails, so newly discovered dependencies and final status appear without manual browser refresh.
- Added a lightweight read-only application activity endpoint for polling; no policy mutation occurs through this endpoint.
- Fixed Access Profile checkbox/card styling in the light theme so onboarding no longer renders a dark legacy control.
- No schema or enforcement-policy changes from v3.7.0.

## 3.7.0

- Reworked the product around a simple application-first workflow: Add application → automatic dependency discovery → pending policy → one reviewed deployment.
- Automatic isolated-browser discovery now stages observed public runtime dependencies without requiring per-endpoint checkbox approval in the normal workflow.
- Advanced HAR/manual discovery remains available for authenticated or edge-case workflows.
- Added safe Application deletion with audit/history retention and clean recreation of the same application name.
- Fixed discovery approval collisions with legacy/system categories such as Google Maps and Google Search.
- Added native Select All support to manual Discovery Review.
- Consolidated change control into one Changes workspace and automatically clears metadata-only pending flags when no effective Squid policy diff exists.
- Simplified primary navigation to Overview, Applications, Traffic, Changes and System; low-level rule/import/intelligence tools moved under Advanced.
- Added a light neutral management workspace with a restrained dark sidebar for lower visual fatigue.
- Added a consistent product favicon/brand mark for the browser tab, sidebar and login.
- Added migration 014 and regression tests for application deletion/recreation and legacy category collision handling.
- Default-deny enforcement, privileged deployment validation and rollback behavior remain unchanged.

## 3.6.1

- Replaced the active self-connect proxy health probe with a passive TCP listener check so gateway health monitoring no longer creates Squid access-log artifacts.
- Treats the configured proxy IP plus loopback addresses as appliance system identities for telemetry analytics.
- Excludes appliance self-traffic from client counts, dashboard KPIs, timelines, network breakdowns, top destinations/clients, exports and dependency-candidate generation by default.
- Added an explicit `Include system traffic` Traffic Explorer option so diagnostic events remain available for troubleshooting.
- Existing historical self-traffic is preserved but no longer pollutes normal business traffic views.
- Added regression coverage proving system traffic is excluded by default and remains queryable on demand.
- No policy, schema, or enforcement behavior changes from v3.6.0.

## 3.6.0

- Reworked information architecture around task-oriented enterprise security workflows: Overview, Monitor, Configure, Investigate, Changes, and Platform.
- Added a global navigation command palette with Ctrl+K search.
- Increased typography, spacing, contrast, and visual hierarchy across the management console.
- Introduced a richer restrained enterprise palette using indigo/cyan for navigation and monitoring, green for healthy state, amber for change state, and red only for deny/error.
- Rebuilt the Overview as a command-center style dashboard with a single primary traffic visualization, gateway posture, quick actions, compact KPIs, network activity, blocked destinations, and recent audit activity.
- Empty analytics no longer render meaningless flat charts; they show contextual next-step states.
- Simplified permanent navigation by removing secondary traffic views such as Allowed Requests from the sidebar while preserving their routes.
- Added a redesigned administrator login experience and responsive navigation/search behavior.
- No Squid policy, schema, telemetry model, or enforcement behavior changes from v3.5.0.

## 3.5.0

- Redesigned the management console navigation around five human-readable task groups instead of exposing every route at once.
- Simplified the Dashboard to prioritize gateway health, traffic, quick actions, policy coverage and change status.
- Replaced hard-coded proxy endpoint text with the configured proxy IP and port.
- Added a flat, restrained visual system with less decorative gradient/uppercase noise and clearer hierarchy.
- Added a functional mobile navigation drawer instead of hiding the sidebar entirely on smaller screens.
- Added template syntax validation to CI.
- No Squid policy, schema, telemetry model, or enforcement behavior changes from v3.4.5.

## 3.4.5

- Fixed telemetry cleanup on an empty/fresh telemetry database where `after_count` was referenced before assignment.
- Telemetry event count is now recalculated directly from SQLite after cleanup before updating telemetry state.
- Added regression coverage for cleanup/collector execution with zero indexed events.
- No Squid policy, schema, management UI, or application-intelligence behavior changes from v3.4.4.

## 3.4.4

- Fixed background worker imports when systemd launches scripts by absolute path.
- Added explicit `PYTHONPATH=/opt/security-web-gateway/current` to performance, telemetry, discovery, source-sync and storage-maintenance units.
- Made performance and telemetry collectors self-bootstrap the release root in `sys.path` for direct execution resilience.
- Added CI coverage for direct execution/importability of background workers from the release layout.
- No Squid policy, schema, telemetry model, or application-intelligence behavior changes from v3.4.3.

## 3.4.3

- Fixed a fresh-install version collision where sourcing `/etc/os-release` overwrote the Security Web Gateway release `VERSION` variable on Ubuntu 26.04.
- Application version is now loaded from the deployed release `VERSION` file instead of a hard-coded constant.
- Fresh install and upgrade now copy the `VERSION` file into each immutable release directory.
- Upgrade/install health checks validate against the release version without relying on OS metadata.
- Added CI validation that application-reported version matches the repository `VERSION`.
- No Squid policy, schema, telemetry model, or application-intelligence behavior changes from v3.4.2.

## 3.4.2

- Added Ubuntu Server 26.04 LTS compatibility for fresh deployments.
- Replaced the legacy/virtual `dnsutils` package dependency with the real `bind9-dnsutils` provider.
- Upgraded Playwright from 1.55.0 to 1.61.0, the first release with Ubuntu 26.04 support and Python 3.14 compatibility.
- Added Python 3.14 dependency/import validation to CI.
- No Squid policy, schema, telemetry model, or application-intelligence behavior changes from v3.4.1.

## 3.4.1

- Fixed release checksum generation for Windows PS1/CMD files managed as CRLF by .gitattributes, so a normal Git checkout passes `sha256sum -c CHECKSUMS.sha256`.
- Changed fresh-install health version validation to use the release VERSION dynamically instead of hard-coding 3.4.0.
- No data-plane, policy-model, schema, or application-intelligence behavior changes from v3.4.0.

## 3.4.0

- Re-focused the product as a **single-VM, on-prem Security Web Gateway appliance**.
- Added data-plane resource priority for Squid and low-priority cgroup/I/O scheduling for telemetry, discovery, storage and performance workers.
- Added optional/default fresh-install local DNS caching with Unbound, forwarding to enterprise DNS servers; Squid can use the loopback cache without changing the host resolver.
- Disabled Squid content caching by policy; modern HTTPS CONNECT traffic is not cacheable without TLS inspection, so the design avoids unnecessary disk I/O.
- Added SQLite runtime tuning (`WAL`, `synchronous=NORMAL`, memory temp store/cache, mmap) and session touch throttling to reduce write contention.
- Removed live `systemctl`/DNS checks from the Overview request path; health is sampled in the background and read from cache.
- Added background dashboard precomputation so Overview does not perform expensive telemetry aggregation on every page load.
- Added VM/data-plane performance sampling: CPU, I/O wait, memory, disk, telemetry lag, proxy P50/P95/P99 and established proxy connections.
- Added `System -> Performance` GUI.
- Added response timing headers (`Server-Timing`, `X-Response-Time-Ms`) for management-plane diagnostics.
- Added **Policy Simulator** and **Why Blocked?** explainability.
- Added conservative **Application Dependency Candidates**: blocked destinations can be correlated with a recently active single application, classified/scored, and presented for approval/ignore. Candidates never auto-allow.
- Added supporting schema migration 013, indexes and background caches.
- Added new v3.4 smoke tests and CI migration checks.

## 3.3.1

- Full product rebrand to **Security Web Gateway**.
- Linux service names and filesystem paths standardized on `security-web-gateway`.
- Windows endpoint application remains **Proxy Control** with generic registry/filesystem naming.
- Deployment examples are vendor-neutral and portable between environments.
- No organization-specific product branding is stored in the repository.

## 3.3.0

- Added portable GitHub-ready repository and fresh-server installer.
- Added server-side isolated Chromium application discovery and HAR workflow discovery.
- Moved Observed Squid discovery to troubleshooting use.
- Removed Squid log ingestion from web requests to reduce GUI stall/504 risk.
- Added telemetry/storage guardrails and hourly maintenance.
- Fixed metadata-only Access Profile/Application pending behavior and added safe stale-pending reconciliation.
- Added policy-state export/restore tooling for server migration.
- Bundled Windows Proxy Control source/builder.

# Security Web Gateway Manager — Changelog

## 3.2.0 — Traffic Intelligence & Reporting

- Added persistent Squid telemetry index in SQLite (migration 011).
- Added incremental, rotation-aware `access.log` collector with inode/offset checkpointing and a 30-second systemd timer.
- Added Traffic Explorer with time, VLAN/network, client IP, destination host/IP, action, application, method and port filters.
- Added pagination (50/100/250/500 rows) and retained filtered state across pages.
- Added CSV and dependency-free XLSX exports that respect the active filters.
- Added destination-IP, upstream-IP, port, bytes, request duration, HTTP/Squid result and matched-policy fields.
- Added Application Policy attribution from configured application dependencies.
- Added Access Profile attribution scoped to the client Network Policy.
- Added Network/VLAN enrichment from source CIDR mapping.
- Added persistent client inventory and client drill-down with top applications, domains, destination IPs and recent requests.
- Updated Overview charts and metrics to use the telemetry database rather than a short raw-log tail.
- Added configurable searchable telemetry retention (default 30 days, admin-controlled, maximum 365 days).
- Added telemetry health details to System Health.
- Added explicit visibility notice: PAC `DIRECT` traffic is outside Squid telemetry and will require router/IPFIX integration in the network-observability phase.
- Upgrade remains direct-to-production on HTTPS/443 using shadow DB migration, offline Squid policy validation, rollback archive and automatic rollback.

## 3.1.0

- Application Policies, Access Profiles / Policy Groups and inherited Network Policies.
- Application discovery and official-source synchronization framework.
- Direct transactional production upgrade workflow with automatic rollback.
