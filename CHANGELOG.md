# Changelog

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
