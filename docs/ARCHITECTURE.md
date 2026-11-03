# Architecture — Security Web Gateway 3.4

## Deployment model

Security Web Gateway is designed primarily as a **single local VM appliance**. Internet access enforcement must not depend on a public SaaS control plane.

```text
Managed clients / VLANs / VPN
            |
      PAC / Proxy Control
            |
            v
+------------------------------------+
| Security Web Gateway VM            |
|                                    |
|  DATA PLANE                        |
|  Squid :3128 ---------------------> Internet
|      |                             |
|      +--> access log               |
|                                    |
|  LOCAL SERVICES                    |
|  Unbound cache -> enterprise DNS   |
|  Nginx :443 / PAC :8081            |
|  FastAPI :8200 loopback            |
|  SQLite/WAL                        |
|  telemetry/performance workers     |
|  browser discovery worker          |
|  restricted deploy helper          |
+------------------------------------+
```

## Design priority

1. Squid data-plane continuity and latency
2. Default-deny security
3. Failure isolation
4. Recoverability and deterministic deployment
5. Observability
6. GUI/reporting performance
7. Application intelligence

## Trust boundaries

1. **Client endpoints** are untrusted policy consumers. PAC/Proxy Control controls the expected path but endpoint configuration alone is not a complete anti-bypass control.
2. **Squid data plane** enforces default-deny/explicit-allow policy and is independent from management GUI availability.
3. **FastAPI management plane** runs unprivileged as `proxy-mgmt`.
4. **Privileged helper** accepts only typed local actions, validates candidate hash/configuration, atomically replaces the managed Squid include, reloads and can roll back.
5. **SQLite** is the authoritative policy/audit store and a searchable telemetry index.
6. **Nginx** terminates management TLS; PAC is exposed separately on TCP/8081.
7. **Discovery browser** is public-web evidence collection only; private/reserved pivots are rejected.
8. **Threat/discovery evidence is untrusted** until reviewed by an administrator.

## Data-plane isolation

The data plane must continue when any of the following fail:

- GUI/FastAPI
- telemetry collector
- performance collector
- browser discovery
- dashboard cache refresh
- source synchronization

Squid receives higher CPU/I/O cgroup weight. Background workers run with lower CPU/I/O priority and bounded memory.

## Caching model

Security Web Gateway intentionally separates three different concepts:

- **HTTPS content cache:** disabled. CONNECT tunnels are opaque without TLS interception and disk cache would add I/O without useful benefit.
- **DNS cache:** local Unbound cache is recommended; enterprise DNS remains authoritative/upstream.
- **Management analytics cache:** expensive dashboard/system-health data is precomputed in background and served from SQLite cache tables.

## Policy path

`GUI/DB → candidate policy → Diff → privileged validation → atomic Squid include → reload → health check`

## Application intelligence path

`Browser/HAR/vendor evidence → classify → candidate/dependency → admin review → Pending → Diff → Deploy`

For ongoing application use:

`DENY event → same-client recent single-application correlation → noise filtering → confidence → Dependency Candidate`

A candidate never changes production policy automatically.

## Visibility boundary

Traffic Explorer shows traffic that traverses Squid. PAC `DIRECT` traffic is invisible to Squid by definition. Whole-network direct-path visibility requires router/IPFIX/Traffic Flow integration.
