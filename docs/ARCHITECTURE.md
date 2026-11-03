# Architecture

## Trust boundaries

1. **Client endpoints** are untrusted policy consumers. PAC/Proxy Control configures their path but endpoint configuration alone is not a complete anti-bypass control.
2. **Squid data plane** enforces default-deny/explicit-allow policy and remains operational independently from the GUI.
3. **FastAPI management plane** runs as unprivileged `proxy-mgmt` and cannot write arbitrary system configuration.
4. **Privileged helper** accepts a small typed action set over a local Unix socket, validates candidate hash/configuration, atomically replaces the managed Squid include, reloads Squid and rolls back on failure.
5. **SQLite** is the authoritative application/policy/audit store. Telemetry is searchable operational data, not a substitute for raw network telemetry.
6. **Nginx** terminates management TLS and serves PAC separately on TCP/8081.
7. **Browser discovery** is an outbound-only public-web evidence collector. Private/reserved destinations are rejected.

## Policy path

`GUI/DB → generated candidate → diff → privileged validation → atomic managed Squid include → reload → health check`

## Discovery path

`URL/vendor source/HAR → evidence → classification → admin review → Application Policy relationship → Pending → Diff → Deploy`

Discovery never writes production Squid policy directly.

## Visibility boundary

Traffic Explorer contains traffic that traversed Squid. PAC `DIRECT` traffic is invisible to Squid by definition. Whole-network direct-path observability requires router/IPFIX/Traffic-Flow integration.
