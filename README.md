# Security Web Gateway

Create the Access Profile, select/create its VLAN and choose allowed access on **one page with one save**: Profiles & VLANs.

Version 3.12 consolidates websites/domains/IPs under **Access**, separates **Proxy bypass**, groups traffic/health under **Monitoring**, exposes **Alerts & SNMP** directly, and uses one profile-or-VLAN selector. Install/upgrade provides an unassigned Google Search starter and no customer-specific application data. Optional read-only SNMPv2c polling/traps are configured with email/Slack; SNMPv3 is not included. See [the access/deployment guide](docs/CONNECTION_AND_LEARNING.md) and [notification/SNMP setup](docs/HEALTH_NOTIFICATIONS.md).


**Version:** 3.12.6

**Target:** single-VM, on-prem enterprise appliance  
**Target OS:** Ubuntu Server 24.04 LTS / 26.04 LTS  
**Architecture:** Squid explicit proxy + FastAPI management plane + Nginx TLS + SQLite/WAL policy and telemetry store + isolated background workers + restricted privileged deployment helper.

This repository is the source-of-truth for Security Web Gateway. Runtime databases, TLS private keys, production certificates, passwords, HAR captures, logs and backups are deliberately **not** part of Git.

## Product objective

Deploy one local VM, connect managed endpoints/VLANs/VPN clients through PAC/Proxy Control, and manage web access centrally without making Internet access dependent on a public SaaS control plane.

The design priority is:

1. Data-plane security and performance
2. Stability and fail-open continuity
3. Maintainability and recoverability
4. Observability
5. Management-plane responsiveness
6. Application intelligence

## Recommended VM profile

Standard deployment for roughly 50–250 normal office users:

```text
OS:        Ubuntu Server 24.04 LTS or 26.04 LTS
vCPU:      4
RAM:       8 GiB
Disk:      100 GiB SSD/NVMe
NIC:       VirtIO, 1 Gbps+
Disk bus:  VirtIO SCSI
CPU type:  host where live-migration compatibility permits
I/O thread: enabled
TRIM:      enabled
Swap:      2 GiB safety net
Headroom:  keep 20–25% CPU/RAM/disk capacity available
```

Sizing should ultimately follow concurrent CONNECT sessions, requests/sec, WAN throughput, telemetry events/day and discovery workload rather than user count alone.

## Security and trust model

- Squid is **default deny** with explicit ALLOW policy.
- Squid is the data plane and remains operational independently from GUI, telemetry and discovery workers.
- Access Profiles and Network Policies provide scoped source authorization.
- Management GUI binds to loopback and is published by Nginx over HTTPS.
- GUI runs unprivileged as `proxy-mgmt`.
- Squid deployment uses a narrow Unix-socket privileged helper; there is no web shell or unrestricted sudo path.
- Normal application onboarding is automatic: isolated browser discovery discovers public dependencies and Admin-initiated runs use transactional Save & Apply.
- Production remains protected by explicit change control: only an Administrator can publish policy. Admin Save performs validation, atomic apply, health verification, audit and automatic rollback on failure.
- Operator changes remain pending for Admin approval. Advanced manual/HAR discovery remains available for authenticated or unusual workflows.
- Browser discovery rejects private/reserved targets and DNS-rebinding/SSRF-style pivots.
- PAC supports explicit DIRECT bypasses plus fail-open `PROXY ...; DIRECT` behavior.

## v3.12.6 — detailed functional review

Includes role/CSRF route checks, authentication and concurrent-admin regressions, bounded HAR import, reliable traffic-filter errors, valid XLSX exports and a fresh-install TLS module fix. Activity distinguishes failed attempts from successful baselines. See the [detailed functional review](docs/DETAILED_FUNCTION_AUDIT.md) and [complete application function inventory](docs/FUNCTION_CATALOG.md) for measured coverage and remaining deployment checks. The Cloudflare security-audit skill is a project instruction; this functional review is not a completed independent security audit.

## v3.12.5 — PC activity

**Monitoring → PC activity** provides searchable, paginated source-IP inventory and per-PC request history, domain/decision/date filters, destination rankings and scoped CSV/XLSX export. Current DNS names are hints; DHCP/NAT and AD user-identity limits are explicit. AD is optional for IP/VLAN policy; GPO deployment is distinct from AD user authentication. See [PC activity and AD](docs/CLIENT_ACTIVITY.md).

## v3.12.4 — system review and reliable diagnosis

- The existing Policy Simulator checks saved proxy policy and PAC routing together, including direct bypasses, optional client-resolved destination IPs and clear pending/historical-policy labels.
- Health alerts share the notification thresholds; stale samples do not present the gateway as healthy. Dashboard health uses cached sampling.
- Client reverse DNS runs in a bounded background worker rather than delaying client pages. CSV export text receives formula-prefix protection; XLSX retains explicit text cells.
- See the [platform review and feature decisions](docs/PLATFORM_REVIEW.md) for findings, validation boundaries and prioritized future work.

## Health notifications and operational safety

- **Alerts & SNMP** configures optional SMTP email and Slack Incoming Webhooks entirely from the GUI, with test buttons and live delivery history.
- Confirmed incidents, recovery, grouped messages, repeat control and independent retry/backoff run in a low-priority background worker.
- Secrets are stored in a protected VM-local configuration file and never returned by the GUI or exported with policy state.
- Policy expiry, concurrent publication, portable backup/restore staging and browser discovery isolation have dedicated regression coverage.
- Migration `017` stores health incident/delivery metadata. No real email/Slack destination is enabled by default.

See [Health notifications and safety](docs/HEALTH_NOTIFICATIONS.md) for configuration, guarantees and deployment checks.

## v3.10.0 — simpler console, connection policy and workflow capture

- Refined desktop/mobile interface with clearer typography, quieter cards and fewer duplicate navigation entries.
- **Connection** manages fail-open, direct domain/IP/CIDR bypasses and a configured Windows package with installation instructions.
- **Applications → Capture the actual workflow** provides an optional selected-tab Chrome/Edge recorder and a side-by-side HAR import for authenticated/button-driven dependencies. Both imports require review. IP-based automatic grants are disabled.
- **Connection → Optional PC services** adds scoped, opt-in Windows Update, Defender security updates and connectivity checks.
- Browser auto-approval honours candidate selection and excludes ignored analytics/background requests.
- Schema migration `016` retains earlier session history. Legacy active IP-learning sessions are stopped; existing PAC is preserved during upgrade.

Read [Connection and application learning](docs/CONNECTION_AND_LEARNING.md) for workflow, limits and production verification.

## v3.9.0 — enterprise operations console

- **System** is the operational hub for health/performance, storage, backups and administrators.
- **Policy & Tools** contains access profiles, network scopes, explicit rules, simulation, dependency review, import/export and audit.
- Overview, Applications, Traffic and Activity share one light enterprise visual system with a restrained graphite navigation plane.
- System monitoring includes performance history, DNS/TLS/NTP state, worker health, storage/retention, recovery posture and actionable alerts.
- Live Traffic refreshes automatically while preserving safe interaction with active filters.
- The routine policy workflow remains v3.8 **Save & Apply** with validation, audit and rollback.

## v3.4.0 — performance and application intelligence

### Fast single-VM data plane

- Squid receives high CPU/I/O cgroup weight and a higher file-descriptor ceiling.
- Telemetry, discovery, storage maintenance and performance sampling run at deliberately lower CPU/I/O priority.
- Squid content cache is disabled by design. Modern HTTPS `CONNECT` traffic cannot be content-cached without TLS inspection, so unnecessary proxy disk I/O is avoided.
- Fresh installations can use local **Unbound DNS cache** on loopback, forwarding to enterprise DNS servers. Internal DNS authority remains with the configured enterprise resolvers.
- Persistent proxy connections remain enabled.

### Management-plane responsiveness

- SQLite uses WAL and runtime tuning for concurrent read/write workloads.
- Session `last_seen` writes are throttled instead of writing on every authenticated page request.
- Overview no longer performs synchronous `systemctl` or DNS probes.
- Health is sampled in the background and read from cache.
- Expensive Traffic Overview aggregation is precomputed by the telemetry worker.
- Static assets receive short browser cache headers.
- Management responses expose `Server-Timing` and `X-Response-Time-Ms` for diagnostics.

### Performance telemetry

`System → Performance` exposes VM/data-plane health including:

- CPU and I/O wait
- load average
- memory and swap pressure
- disk utilization/free space
- telemetry lag
- proxy request P50/P95/P99
- established proxy connections

### Application-aware troubleshooting

- **Policy Simulator** explains what would happen for a client IP + destination + protocol/port without changing policy.
- **Why Blocked?** explains a denied telemetry event using effective Network/Profile/Application/Rule scope.
- **Application Dependency Candidates** correlate new blocked destinations with a recently active single application, classify them and score confidence.
- Blocked-traffic dependency candidates remain review-only until approved. Admin approval and Admin-initiated onboarding use the same validated Save & Apply pipeline.

### Application discovery

Primary discovery is application-scoped rather than workstation-scoped:

1. Server Browser Discovery — isolated Chromium/Playwright for JavaScript/XHR/fetch/API/CDN/WebSocket dependencies.
2. HAR workflow discovery — for authenticated/click-driven application workflows; raw HAR is processed in memory and not persisted.
3. Official source/catalog evidence where available.
4. Observed Squid traffic — retained only under Advanced/Troubleshooting because it can contain unrelated workstation traffic.

## Repository layout

```text
app/                 FastAPI management application
bin/                 telemetry/performance/discovery workers and CLI tools
migrations/          ordered SQLite schema migrations
static/              CSS / JavaScript
templates/           Jinja GUI templates
privileged/          restricted root deployment helper
systemd/             app and low-priority worker units + Squid priority drop-in
deploy/              fresh install, upgrade, state export/restore
deploy/templates/    Nginx, Squid and Unbound templates
pac/                 PAC template
config/              production environment example
tools/windows/       Proxy Control Windows endpoint package source
docs/                architecture, deployment, performance and operations docs
.github/workflows/   CI
```

## Fresh server installation

Prepare a supported Ubuntu 24.04 LTS or 26.04 LTS VM with static IP/routing/NTP and the intended certificate. Do **not** commit TLS keys to Git.

```bash
sudo ./deploy/install.sh \
  --fqdn proxy.example.internal \
  --bind-ip 192.0.2.10 \
  --dns-servers 192.0.2.53,192.0.2.54 \
  --tls-cert /root/proxy.example.internal.crt \
  --tls-key /root/proxy.example.internal.key \
  --admin-user admin
```

Local DNS cache is enabled by default for fresh installs when TCP/UDP 53 on loopback is available. To deliberately skip it:

```bash
sudo ./deploy/install.sh ... --no-local-dns-cache
```

For a temporary lab bootstrap only:

```bash
sudo ./deploy/install.sh \
  --fqdn proxy.example.internal \
  --bind-ip 192.0.2.10 \
  --self-signed
```

The installer deliberately does **not** create firewall/UFW policy because management-source ACLs and upstream bypass enforcement depend on the target network design.

## Upgrade

Servers already using the generic `security-web-gateway` filesystem/service layout can use:

```bash
sudo ./deploy/upgrade.sh --confirm
```

The upgrade creates a database/release/unit backup, performs shadow migration and validation, then cuts over transactionally. A failed cutover restores the prior DB/release/units/timers. The upgrade itself never publishes pre-existing pending policy; subsequent Admin Saves use transactional Save & Apply.

A legacy installation using a different product/service/path namespace needs a controlled one-time migration or a fresh install plus policy-state restore.

## Move policy state to another VM

On the source VM:

```bash
sudo ./deploy/export_policy_state.sh
```

Transfer the root-only archive over a protected channel. On the already-installed target VM:

```bash
sudo ./deploy/restore_policy_state.sh /secure/path/security-web-gateway-policy-state-....tar.gz
```

Runtime sessions are revoked after restore. Target IP/FQDN/TLS/PAC remain local to the target host.

## PAC / fail-open

Default behavior:

```text
DIRECT: internal/simple names, RFC1918 destinations and configured business bypass IPs
PROXY:  <server-ip>:3128
FAIL:   DIRECT fallback
```

Manage exact domains, wildcard domains, IPv4 addresses and IPv4 CIDRs under **Connection → Always go direct**. Existing business bypasses are imported from legacy PAC on upgrade; fresh installations have none.

Proxy return path:

```text
PROXY <SWG-IP>:3128; DIRECT
```

PAC cannot force a browser TCP timeout. Sub-second fail-open belongs to the network layer (for example router health-check + fast reject) if strict fast failover is required.

## GitHub workflow

Keep the repository private unless publication is intentional.

```bash
git add -A
git status
git diff --cached
git commit -m "Security Web Gateway v3.12.4"
git push

git tag -a v3.12.4 -m "Security Web Gateway v3.12.4"
git push origin v3.12.4
```

Never stage `.db`, `.sqlite*`, `.env`, TLS/private-key material, HAR files, logs or backups.

## Validation

```bash
python3 -m compileall -q app bin tools privileged tests
bash -n deploy/*.sh scripts/*.sh
python3 tools/migrate.py --db /tmp/swg-test.db --root .
python3 tests/smoke_v340.py
python3 tests/smoke_v370.py
python3 tests/smoke_v380.py
python3 tests/smoke_v3121.py
```

See `docs/ARCHITECTURE.md`, `docs/DEPLOYMENT.md`, `docs/PERFORMANCE.md`, `docs/OPERATIONS.md`, and `SECURITY_MODEL.md`.
