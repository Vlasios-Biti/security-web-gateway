# Security Web Gateway v3.4.4 Acceptance Test

1. `readlink -f /opt/security-web-gateway/current` returns `/opt/security-web-gateway/releases/3.4.4`.
2. `/healthz` on `127.0.0.1:8200` and management HTTPS returns version `3.4.4`, mode `production`.
3. `SELECT MAX(version) FROM schema_migrations` returns `013`; `PRAGMA integrity_check` returns `ok`; `PRAGMA foreign_key_check` returns no rows.
4. `squid -k parse` and `nginx -t` succeed.
5. `security-web-gateway.service`, `squid.service`, `nginx.service`, and `security-web-gateway-deploy-helper.socket` are active.
6. Telemetry, storage-maintenance, discovery, source-sync and **performance** timers are enabled/active.
7. Squid priority drop-in exists and background workers use lower CPU/I/O priority.
8. PAC is reachable on `http://<SWG-IP>:8081/proxy.pac` and contains `PROXY <SWG-IP>:3128; DIRECT`.
9. DIRECT bypass IPs remain present: `49.12.132.214`, `65.108.9.79`, `178.63.88.53`.
10. A standard Windows user with Proxy Control installed cannot change proxy/PAC settings without administrator credentials.
11. Traffic Explorer updates via the telemetry timer; GUI requests do not parse `access.log` synchronously.
12. Overview uses cached health/traffic data and does not synchronously call systemd/DNS probes.
13. `System → Performance` receives samples after the performance timer runs.
14. If local DNS cache is enabled, Unbound answers on loopback and forwards successfully to enterprise DNS.
15. `System → Storage / Telemetry` shows age/storage/free-space guardrails.
16. Browser discovery completes through the discovery timer and requires explicit Review/Approve/Deploy.
17. HAR discovery does not persist the uploaded raw HAR and classifies obvious analytics/background endpoints as IGNORE.
18. `Policy Simulator` returns an explainable ALLOW/DENY result without changing policy.
19. `Why Blocked?` explains a denied event from effective network/profile/rule/application scope.
20. A correlated new blocked application dependency appears only as a review candidate; it is not auto-allowed.
21. Approving a candidate creates normal pending policy and still requires Diff/Deploy.
22. Existing production Squid policy is not auto-deployed merely by upgrading application code.
23. On failed upgrade cutover, DB/release/units and all worker timers can be restored by the rollback path.
