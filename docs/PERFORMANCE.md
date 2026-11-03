# Performance and Capacity

## Primary rule

Protect the Squid data plane first. Management/reporting work must never be allowed to monopolize CPU, I/O or database locks needed for user traffic.

## Recommended VM profiles

| Profile | vCPU | RAM | Disk | Typical starting point |
|---|---:|---:|---:|---|
| Small | 2–4 | 4–8 GiB | 60–80 GiB SSD | <= ~50 normal office users |
| Standard | 4 | 8 GiB | 100 GiB SSD/NVMe | ~50–250 users |
| Large single VM | 6–8 | 12–16 GiB | 120–160 GiB SSD/NVMe | ~250–500 users |
| High volume | 8+ | 16–32 GiB | workload-sized NVMe | size by measured traffic |

These are starting profiles, not licensing limits.

## Metrics that matter

Capacity decisions should use:

- requests/sec
- concurrent CONNECT sessions
- WAN Mbps/Gbps
- proxy P50/P95/P99 elapsed time
- CPU utilization and steal time
- I/O wait and disk latency
- memory/swap pressure
- telemetry events/day
- telemetry lag
- SQLite busy/lock incidence
- browser discovery concurrency

## Caching strategy

### DNS

Local Unbound is the primary traffic-path cache. It forwards to configured enterprise DNS and reduces repeated lookup latency. Internal DNS policy/authority remains upstream.

### GUI/analytics

Overview/system health use background precomputation. GUI requests should perform small indexed reads rather than scanning raw logs or aggregating large telemetry tables.

### Proxy content

Squid content caching is disabled. Without TLS interception, modern HTTPS CONNECT contents are opaque. Disk cache would increase I/O while providing little benefit.

## SQLite

Runtime connections use WAL-compatible tuning, busy timeout, `synchronous=NORMAL`, memory temp store/cache and mmap where available. Migrations/backups use safer durability settings.

Keep transactions short and batch telemetry inserts. If sustained `SQLITE_BUSY`, high write concurrency or multi-node management becomes a requirement, evaluate PostgreSQL rather than continually increasing SQLite complexity.

## Response targets

Targets are operational objectives, not hard guarantees:

- management login POST/auth path: P95 under 500 ms on healthy VM
- normal management page: P95 under 300 ms where no deliberate external probe occurs
- cached Overview: P95 under 1 second
- telemetry lag: normally under 60 seconds
- disk free: never below configured minimum floor
- persistent swap use: investigate; normal workload should not depend on swap

Use the actual site baseline to set alerts.
