# Operations — Security Web Gateway 3.9

## Services

- `squid.service` — priority data plane
- `nginx.service` — management TLS + PAC listener
- `security-web-gateway.service` — management plane
- `security-web-gateway-deploy-helper.socket` — restricted privileged deployment interface
- `security-web-gateway-telemetry.timer` — bounded Squid telemetry ingestion and dashboard-cache refresh
- `security-web-gateway-performance.timer` — VM/data-plane performance sampling + cached health refresh
- `security-web-gateway-source-sync.timer` — official application-source monitoring
- `security-web-gateway-storage-maintenance.timer` — telemetry/raw-log guardrails
- `security-web-gateway-discovery.timer` — isolated browser discovery queue
- `unbound.service` — optional/recommended local DNS cache for fresh installs

## Data-plane priority

`systemd/squid-priority.conf` gives Squid higher CPU/I/O weight and larger file descriptor limits. Background workers use lower nice/cgroup/I/O priority and bounded memory.

Do not remove these controls merely to make a worker complete faster; diagnose the worker instead.

## Storage defaults

- telemetry age: 30 days
- logical telemetry DB hard cap: 8 GiB
- cleanup target: 6.5 GiB
- minimum disk free floor: 10 GiB
- rotated Squid logs: 14 days
- rotated Squid logs cap: 4 GiB

Automatic cleanup deletes oldest telemetry only. Users, applications, policies, deployments and audit records are not telemetry-retention data.

## Performance triage

Use the troubleshooting flow:

`Observation → Evidence → Hypothesis → Test → Root Cause → Remediation → Validation`

Useful host evidence:

```bash
uptime
free -h
vmstat 1
iostat -xz 1
ss -s
systemctl --failed
journalctl -u squid --since '15 minutes ago'
journalctl -u security-web-gateway --since '15 minutes ago'
```

Do not tune multiple sysctl/Squid parameters simultaneously without evidence.

## Login/GUI latency

The login POST is intentionally narrow: indexed user lookup, Argon2 verification, session creation and redirect. Overview reads cached health/traffic summaries instead of calling `systemctl`, `dig` or parsing Squid logs synchronously.

Inspect `Server-Timing` / `X-Response-Time-Ms`, background timer status, database health and `System → Performance` before changing Argon2 security parameters.

## Application dependency candidates

A blocked destination may appear as a candidate only when the collector can conservatively correlate it with a recently active single application and the endpoint is not classified as obvious noise.

Candidate states remain review workflow:

- review/approve → saves the dependency
- ignore → leaves production policy unchanged
- Admin approval validates and applies immediately through Save & Apply
- Operator approval remains pending for Admin approval

## Browser discovery

Primary onboarding uses isolated server-side Chromium. For an Admin-initiated run, discovered public dependencies are saved and transactionally applied when discovery completes. Authenticated/click-driven workflows use HAR evidence under Advanced. Observed Squid mode remains troubleshooting-only because it can collect unrelated workstation traffic.


## Save & Apply operations

Normal Admin changes do not require a second Deploy screen. The control plane executes:

`Save → effective-diff check → candidate render → privileged Squid validation → atomic apply → reload/health verification → audit`.

If validation or reload fails, the privileged helper restores the previous managed policy. The desired state remains visible for troubleshooting while the previous production policy continues to run.

If effective unapplied policy already existed before a new Save, automatic apply is blocked so the new Save cannot silently publish unrelated older work. The exceptional queue is visible under **Activity** and requires one-time Admin approval.



## System operations console

The System workspace is an operations console rather than a collection of unrelated settings pages.

Cached background health collection includes:

- Squid, Nginx and Manager state
- proxy listener state
- telemetry/performance/discovery/source-sync/storage worker state
- CPU, I/O wait, memory, swap, load and disk
- proxy P50/P95/P99 latency and established connections
- telemetry ingestion lag
- enterprise/local DNS latency
- management TLS certificate expiry
- NTP synchronization and host uptime
- configuration drift
- backup and rollback posture

GUI requests read cached health/performance data. External/system probes remain in the low-priority performance worker so management page loads do not compete with Squid.

System events are exception-oriented: healthy controls stay compact while service, DNS, certificate, NTP, disk/memory, telemetry-lag or drift issues produce actionable alerts.

