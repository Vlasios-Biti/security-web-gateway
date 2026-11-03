# Deployment Runbook

## Fresh server

PRE-CHECK: supported Ubuntu, static IP/routing/DNS/NTP, trusted TLS certificate, backup/VM snapshot capability, required ports available.

BACKUP: not applicable to a new host; snapshot immediately after OS baseline if desired.

IMPLEMENTATION:

```bash
sudo ./deploy/install.sh --fqdn <fqdn> --bind-ip <ip> --dns-servers <dns1,dns2> --tls-cert <crt> --tls-key <key>
```

VALIDATION:

```bash
systemctl --failed
systemctl is-active security-web-gateway squid nginx security-web-gateway-deploy-helper.socket
systemctl is-active security-web-gateway-telemetry.timer security-web-gateway-storage-maintenance.timer security-web-gateway-discovery.timer
curl -fsS http://127.0.0.1:8200/healthz
curl -kfsS --resolve '<fqdn>:443:<ip>' https://<fqdn>/healthz
curl -fsS http://<ip>:8081/proxy.pac
squid -k parse
nginx -t
```

ROLLBACK: revert VM snapshot or remove the newly provisioned VM. Do not use a partially configured host as production.

## Existing v3.2 upgrade

PRE-CHECK: no unresolved disk/database incident, current GUI healthy, Squid/Nginx active.

BACKUP: take VM snapshot and use the automatic release-upgrade backup.

IMPLEMENTATION:

```bash
sudo ./deploy/upgrade.sh --confirm
```

VALIDATION: healthz version 3.3.1, schema migration 012, timers active, current Squid traffic unaffected.

ROLLBACK: upgrade script restores DB/release/unit state automatically on a cutover failure; VM snapshot is the outer recovery boundary.

## State migration to a new host

Install target first, then restore only the policy/database state using the dedicated export/restore scripts. Do not copy target-specific `production.env`, TLS keys or bind configuration from the old host unless intentionally reusing the same identity/IP.
