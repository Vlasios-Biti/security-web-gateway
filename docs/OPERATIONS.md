# Operations

## Services

- `security-web-gateway.service` — management plane
- `security-web-gateway-deploy-helper.socket` — restricted privileged deployment interface
- `security-web-gateway-telemetry.timer` — Squid telemetry ingestion
- `security-web-gateway-source-sync.timer` — official application-source monitoring
- `security-web-gateway-storage-maintenance.timer` — telemetry/raw-log guardrails
- `security-web-gateway-discovery.timer` — isolated browser discovery queue
- `squid.service` — data plane
- `nginx.service` — management TLS + PAC listener

## Storage defaults

- Telemetry age: 30 days
- Logical telemetry DB hard cap: 8 GiB
- Cleanup target: 6.5 GiB
- Minimum disk free floor: 10 GiB
- Rotated Squid logs: 14 days
- Rotated Squid logs cap: 4 GiB

Automatic cleanup deletes oldest telemetry only. Users, applications, policies, deployments and audit records are not deleted by telemetry cleanup.

## Browser discovery

Primary discovery uses the server-side Chromium runtime. Authenticated/click-driven workflows should use the HAR workflow. Observed Squid mode is troubleshooting-only because it can collect unrelated workstation traffic.
