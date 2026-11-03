# Changelog

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
