# Security Web Gateway Manager — Security Model 3.2

## Trust boundaries

**Squid** is the independent data plane. The GUI may fail without removing the already-deployed Squid policy.

**Security Web Gateway Manager** is the control plane. It binds to localhost behind Nginx/TLS and uses a database desired-state model.

**Privileged deploy helper** is root-owned/socket-activated and accepts only typed deployment operations. The application has no arbitrary shell primitive.

**Discovery Engine** is untrusted-input processing. Provider data, HTML, DNS-derived/observed endpoints and vendor feeds are evidence that must pass normalization and administrator review before becoming policy.

## Least privilege policy semantics

- Global baseline is `DEFAULT DENY`.
- Exceptions are `ALLOW` only.
- Source eligibility requires an enabled `Network Policy` (`CIDR`).
- Effective scope can be direct, `All Proxy Networks`, inherited from an Application Policy, or inherited through an Access Profile.
- Migration bootstrap must preserve or reduce existing reach; it must never silently widen a legacy source scope.

## Application dependency isolation

Atomic destinations can be reused. Application membership therefore has its own enable/disable state. Disabling/removing a dependency from Application A does not globally disable a shared rule used by Application B or a standalone/profile scope.

Because protocol is currently an atomic destination property, discovery/manual attachment is not allowed to silently widen an existing shared destination from HTTP or HTTPS to a broader protocol. A protocol conflict is rejected for explicit administrator review.

## Discovery controls

- Official provider adapters are preferred when machine-readable sources exist.
- Generic official sources require HTTPS/443 and no embedded credentials.
- Destination DNS must resolve exclusively to public/global addresses; private/reserved targets are rejected.
- The outbound TCP connection is pinned to a validated public IP while TLS validates the original hostname, reducing DNS-rebinding risk.
- Redirects are revalidated, response size is capped at 2 MiB, and request timeout is bounded.
- HTML/document extraction is lower-confidence than structured provider data.
- Observed discovery is restricted to one administrator-selected client IP and a bounded 1–120 minute window.
- Application services use the Squid runtime group only for log-read visibility; no root capability is granted.
- Discovery never invokes the privileged deploy helper.

## Change control

GUI edit/discovery approval → desired state → Pending → generated Diff → Admin Deploy → checksum → privileged helper → `squid -k parse` → atomic managed-config replacement → reload/health verification → rollback on failure.

## RBAC

- Viewer — operational read-only.
- Auditor — traffic/audit/security read-only.
- Operator — custom application/rule/profile change preparation; no protected system-application or protected system-profile mutation and no production deployment.
- Admin — networks, protected application bundles, users, deployment, rollback and controlled maintenance.

## Prohibited GUI capabilities

No arbitrary terminal, shell, raw SQL console, arbitrary Python execution, unrestricted file manager, unrestricted `systemctl`, or raw `squid.conf` editor.

## Release safety

The direct-final deployment does not expose a parallel management listener. Before downtime, the installer clones the production database into a root-controlled staging area, applies every migration to the clone, runs integrity and foreign-key checks, imports the complete application, generates the resulting Squid policy, and validates that policy offline. Only after all pre-production checks pass does it stop production writers briefly, re-clone the authoritative database, repeat migration/validation, atomically switch the release/database, deploy policy through the typed helper, and verify HTTPS/443. Any cutover failure automatically restores the previous release pointer, database and managed Squid policy.

## v3.2 Traffic telemetry boundary

The telemetry subsystem indexes only requests that traverse Squid. PAC `DIRECT` traffic never reaches Squid, so the manager does not infer or fabricate those events. Whole-VLAN direct-path visibility requires an independent router data source such as MikroTik Traffic-Flow/IPFIX.

Telemetry ingestion runs as the unprivileged `proxy-mgmt` account with read-only Squid-log visibility through the `proxy` supplementary group. The collector uses a file lock to serialize ingestion across Uvicorn workers and the systemd timer, persists inode/offset state to handle log rotation, and writes only to the managed SQLite data root. Search filters are parameterized and exports are bounded.
