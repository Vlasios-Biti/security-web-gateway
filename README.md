# Security Web Gateway

**Version:** 3.4.5  
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
- Discovery can only create evidence/candidates. `Discovery → Review → Pending → Diff → Deploy` remains mandatory.
- Browser discovery rejects private/reserved targets and DNS-rebinding/SSRF-style pivots.
- PAC supports explicit DIRECT bypasses plus fail-open `PROXY ...; DIRECT` behavior.

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
- Candidates are **never auto-allowed**. Approving a candidate creates a normal pending Application dependency that still requires Diff/Deploy.

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

The upgrade creates a database/release/unit backup, performs shadow migration and validation, then cuts over transactionally. A failed cutover restores the prior DB/release/units/timers. Pending Squid policy is **not** auto-deployed.

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

Explicit DIRECT business destinations retained in `pac/proxy.pac.tpl`:

```text
49.12.132.214
65.108.9.79
178.63.88.53
```

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
git commit -m "Security Web Gateway v3.4.5"
git push

git tag -a v3.4.5 -m "Security Web Gateway v3.4.5"
git push origin v3.4.5
```

Never stage `.db`, `.sqlite*`, `.env`, TLS/private-key material, HAR files, logs or backups.

## Validation

```bash
python3 -m compileall -q app bin tools privileged tests
bash -n deploy/*.sh scripts/*.sh
python3 tools/migrate.py --db /tmp/swg-test.db --root .
python3 tests/smoke_v340.py
```

See `docs/ARCHITECTURE.md`, `docs/DEPLOYMENT.md`, `docs/PERFORMANCE.md`, `docs/OPERATIONS.md`, and `SECURITY_MODEL.md`.
