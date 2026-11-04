# Security Web Gateway v3.8.0 Acceptance Test

1. `readlink -f /opt/security-web-gateway/current` returns `/opt/security-web-gateway/releases/3.8.0`.
2. `/healthz` on `127.0.0.1:8200` and management HTTPS returns version `3.8.0`, mode `production`.
3. `SELECT MAX(version) FROM schema_migrations` returns `015`; `PRAGMA integrity_check` returns `ok`; `PRAGMA foreign_key_check` returns no rows.
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
16. Normal Admin application onboarding completes through the discovery timer and automatically validates/applies discovered public dependencies without a separate Deploy step.
17. HAR discovery does not persist the uploaded raw HAR and classifies obvious analytics/background endpoints as IGNORE.
18. `Policy Simulator` returns an explainable ALLOW/DENY result without changing policy.
19. `Why Blocked?` explains a denied event from effective network/profile/rule/application scope.
20. A correlated new blocked application dependency appears only as a review candidate; it is not auto-allowed.
21. Admin Save/approval validates and applies an effective policy diff immediately; Operator changes remain pending for Admin approval.
22. Existing production Squid policy is not auto-deployed merely by upgrading application code.
23. On failed upgrade cutover, DB/release/units and all worker timers can be restored by the rollback path.

24. Deleting an Application removes it from active policy management, preserves audit/discovery history, and allows the same application name to be recreated.
25. Legacy category names such as Google Maps do not break discovery approval.
26. Metadata-only pending changes are reconciled without creating a meaningless deployment.

27. While an Application discovery run is active, the Application page polls activity automatically and refreshes itself when the run completes; no manual browser refresh is required.
28. Access Profile choices in Add Application use the light-theme control styling and remain readable.

29. Admin Save on Applications, Domains, IP rules, Access Profiles and Network Scopes invokes the transactional Save & Apply path with validation, audit and rollback.
30. A metadata-only Save does not create a deployment record.
31. Operator Save never publishes production policy.
32. If effective pending policy existed before a new Save, the new Save does not silently publish it; Activity shows an exceptional approval queue.
33. Automatic application discovery started by an Admin applies only after discovery completes, and UI polling shows the final result without manual refresh.
