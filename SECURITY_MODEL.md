# Security Web Gateway — Security Model 3.8

## Operating model

Security Web Gateway is primarily a **single-VM on-prem appliance**. Squid is the independent enforcement data plane. Management, telemetry, discovery and reporting are supporting control-plane functions and must not be able to stop already-deployed web policy.

## Trust boundaries

**Client endpoints** are untrusted policy consumers. PAC/Proxy Control establishes the intended proxy path, but endpoint policy alone is not complete anti-bypass enforcement.

**Squid** is the data plane. It is default-deny and receives higher CPU/I/O scheduling priority than background workers.

**Security Web Gateway Manager** is the control plane. It binds to loopback behind Nginx/TLS and uses a desired-state SQLite database.

**Privileged deploy helper** is root-owned/socket-activated and accepts only typed deployment operations. The management application has no arbitrary shell primitive.

**Discovery Engine** processes untrusted external evidence. Provider data, HTML, browser requests, HAR data, DNS-derived endpoints and observed traffic are untrusted. Normal Admin-initiated onboarding may automatically stage isolated-browser evidence and, after the run completes, submit the resulting desired state through the same validated Save & Apply pipeline used by the GUI.

**Local DNS cache** is a performance layer only. Enterprise DNS servers remain the configured upstream authority.

## Least privilege policy semantics

- Global baseline is `DEFAULT DENY`.
- Exceptions are explicit `ALLOW` only.
- Source eligibility requires an enabled Network Policy/CIDR.
- Effective scope can be direct, all proxy networks, inherited from an Application, or inherited through an Access Profile.
- Migration/bootstrap must preserve or reduce existing reach; it must never silently widen source scope.

## Application dependency isolation

Atomic destinations can be shared by multiple Applications. Application membership therefore has its own state. Removing a dependency from Application A does not globally disable a shared rule still required by Application B or another valid scope.

Protocol is an atomic destination property. Discovery/manual attachment cannot silently broaden an existing shared destination from HTTP/HTTPS to a wider protocol; conflicts require explicit administrator resolution.

## Application intelligence controls

- Isolated server-side browser discovery is preferred over whole-workstation observation.
- HAR workflow discovery processes raw upload content in memory and persists endpoint evidence only.
- Observed Squid discovery is troubleshooting-only because workstation traffic can contain unrelated browser/OS/application requests.
- Ongoing dependency candidates are created only from conservative same-client correlation with a recently active **single** Application.
- Obvious analytics/OS/background noise is filtered before candidate creation.
- Ongoing blocked-traffic candidates carry evidence/confidence and remain review-only.
- Initial isolated-browser onboarding may auto-stage observed public dependencies as desired state.
- An Admin-initiated automatic discovery may request production apply only through the normal transactional Save & Apply service; it cannot bypass validation, the restricted privileged helper, health verification, audit, or rollback.
- Operator-initiated discovery remains pending until Admin approval.

## Discovery network controls

- Official provider adapters are preferred where machine-readable sources exist.
- Generic official sources require HTTPS/443 and no embedded credentials.
- Destination DNS must resolve exclusively to public/global addresses; private/reserved targets are rejected.
- Outbound connections are pinned to validated public IPs while TLS validates the original hostname to reduce DNS-rebinding risk.
- Redirects are revalidated, response sizes and execution times are bounded.
- Discovery never invokes arbitrary privileged operations. Admin-authorized automatic apply uses only the typed Save & Apply path and the restricted deploy helper.

## Change control

`Admin Save / approved automatic discovery → desired state → effective-diff check → candidate checksum → privileged helper → squid -k parse → atomic managed-config replacement → reload/health verification → audit → rollback on failure`

`Operator Save → desired state → pending Admin approval → the same validated apply path`

## RBAC

- **Viewer** — operational read-only.
- **Auditor** — traffic/audit/security read-only.
- **Operator** — prepares custom Application/rule/profile changes; cannot publish production policy.
- **Admin** — Save applies effective policy changes transactionally; Admin also controls networks, protected bundles, users, rollback and controlled maintenance.

## Authentication and session controls

- Argon2 password hashing.
- Constant-work dummy verification for unknown usernames to reduce timing enumeration.
- Failed-login lockout.
- Secure/HttpOnly/SameSite=Strict session cookie.
- CSRF token validation on state-changing forms.
- Session activity writes are throttled to reduce database contention without weakening expiry/revocation checks.

## Performance isolation as a security property

Availability is part of the security model. Resource starvation of the proxy can become an availability incident.

- Squid receives high systemd CPU/I/O weight and increased file-descriptor limit.
- Telemetry, discovery, storage maintenance and performance collection run at lower CPU/I/O priority with bounded memory.
- GUI requests never parse raw Squid logs.
- Overview does not synchronously execute systemd/DNS probes or large telemetry aggregation.
- Dashboard/health summaries are produced in background caches.
- SQLite uses WAL-compatible runtime tuning and short/batched writes.

## Caching boundaries

- **HTTPS content cache:** deliberately disabled without TLS inspection.
- **DNS cache:** local loopback cache may be enabled, forwarding to enterprise DNS.
- **Management cache:** health/analytics summaries only; policy authority remains SQLite desired state and deployed Squid configuration.

## Telemetry boundary

IP-based automatic learning is disabled. Correlation candidates are review-only; legacy active sessions are stopped without applying policy. The optional selected-tab recorder uses Chromium tab IDs to exclude unrelated tabs/native PC traffic, retains hostname-level evidence locally and imports it for explicit review. Captures are untrusted evidence; embedded third-party resources may be unnecessary. Import alone never publishes ALLOW rules. Optional PC service profiles require Administrator access and selected Access Profiles and share atomic destination rules without globally disabling them when a service is turned off. See `docs/CONNECTION_AND_LEARNING.md`.

Connection policy publishing accepts structured domain/IP/CIDR and boolean settings only. The privileged helper revalidates input and renders a fixed PAC program from root-owned release code; callers cannot supply arbitrary PAC JavaScript, shell commands or paths. Static PAC remains available through Nginx independently of the management process.

Telemetry indexes only requests that traverse Squid. PAC `DIRECT` traffic never reaches Squid and must not be inferred. Whole-network direct-path visibility requires an independent router source such as Traffic Flow/IPFIX.

Telemetry ingestion runs unprivileged with read-only Squid log visibility, uses bounded batches, persists rotation-aware checkpoints and writes only to the managed data root.

## Prohibited GUI capabilities

No arbitrary terminal, shell, raw SQL console, arbitrary Python execution, unrestricted file manager, unrestricted `systemctl`, or raw `squid.conf` editor.

## Release safety

Fresh installation and upgrades are deterministic and versioned. Generic in-place upgrade performs a shadow database migration/validation, creates rollback state, then cuts over application code transactionally. A failed cutover restores the previous database/release/unit state and worker timers. Pending Squid policy is never auto-deployed merely by an application upgrade.
