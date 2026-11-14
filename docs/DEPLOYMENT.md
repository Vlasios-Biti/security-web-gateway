# Deployment Runbook â€” Security Web Gateway 3.8

## Recommended VM baseline

For a normal 50â€“250 user office deployment:

- Ubuntu Server 24.04 LTS or 26.04 LTS
- 4 vCPU
- 8 GiB RAM
- 100 GiB SSD/NVMe-backed virtual disk
- VirtIO NIC, 1 Gbps+
- VirtIO SCSI + I/O thread + discard/TRIM
- 2 GiB swap as emergency safety net, not steady-state working memory
- 20â€“25% normal resource headroom

Do not size only by user count. Monitor requests/sec, concurrent CONNECT sessions, WAN throughput, telemetry events/day and Chromium discovery bursts.

## Fresh server

### PRE-CHECK

- supported Ubuntu release
- static management/proxy address
- correct routing, DNS and NTP
- TLS certificate/key available outside Git
- intended DNS forwarders known
- TCP 3128/443/8081 path understood
- VM snapshot/backup capability
- enough SSD/NVMe IOPS and free disk

### IMPLEMENTATION

```bash
sudo ./deploy/install.sh \
  --fqdn <fqdn> \
  --bind-ip <ip> \
  --dns-servers <dns1,dns2> \
  --tls-cert <crt> \
  --tls-key <key> \
  --admin-user admin
```

The installer attempts a loopback Unbound cache by default. Use `--no-local-dns-cache` only when the host already has a deliberate DNS service/conflict or another resolver design is required.

### VALIDATION

```bash
systemctl --failed
systemctl is-active security-web-gateway squid nginx security-web-gateway-deploy-helper.socket
systemctl is-active \
  security-web-gateway-telemetry.timer \
  security-web-gateway-storage-maintenance.timer \
  security-web-gateway-discovery.timer \
  security-web-gateway-source-sync.timer \
  security-web-gateway-performance.timer

curl -fsS http://127.0.0.1:8200/healthz
curl -kfsS --resolve '<fqdn>:443:<ip>' https://<fqdn>/healthz
curl -fsS http://<ip>:8081/proxy.pac
squid -k parse
nginx -t
```

If local DNS cache is enabled:

```bash
dig @127.0.0.1 example.com
systemctl is-active unbound
```

### MONITORING

Validate `System â†’ Performance` after several collection intervals. Establish a site baseline for proxy P95/P99, CPU I/O wait, telemetry lag, disk free space and concurrent proxy connections.

### ROLLBACK

For a new deployment, revert/delete the VM from the pre-cutover snapshot. Do not promote a partially configured host to production.

## Generic in-place upgrade

Applies only to installations already using the generic `security-web-gateway` layout.

### PRE-CHECK

- no unresolved disk/database incident
- `/healthz` healthy
- Squid/Nginx active
- enough free disk for DB/release backup
- VM snapshot taken

### IMPLEMENTATION

```bash
sudo ./deploy/upgrade.sh --confirm
```

### VALIDATION

- `/healthz` reports version `3.12.2`
- schema migration is `017`
- `PRAGMA integrity_check` returns `ok`
- all expected timers including `security-web-gateway-performance.timer` and `security-web-gateway-health-monitor.timer` are active
- `squid -k parse` and current client traffic remain healthy
- the upgrade itself did not auto-publish pre-existing pending policy; subsequent Admin Saves use transactional Save & Apply

### ROLLBACK

The upgrade script restores DB, previous release, systemd units and worker timers on a failed cutover. The VM snapshot remains the outer recovery boundary.

## State migration to another VM

Install the target first. Then use `deploy/export_policy_state.sh` and `deploy/restore_policy_state.sh` over a protected transfer channel.

Do not copy target-specific `production.env`, TLS keys or bind configuration from the source unless the target intentionally assumes the same identity/IP.
