# Security Web Gateway v3.11.0 Acceptance Test

1. `readlink -f /opt/security-web-gateway/current` returns `/opt/security-web-gateway/releases/3.11.0`.
2. `/healthz` on `127.0.0.1:8200` and management HTTPS returns version `3.11.0`, mode `production`.
3. `SELECT MAX(version) FROM schema_migrations` returns `017`; `PRAGMA integrity_check` returns `ok`; `PRAGMA foreign_key_check` returns no rows.
4. `squid -k parse` and `nginx -t` succeed.
5. `security-web-gateway.service`, `squid.service`, `nginx.service`, and `security-web-gateway-deploy-helper.socket` are active.
6. Telemetry, storage-maintenance, discovery, source-sync and **performance** timers are enabled/active.
7. Squid priority drop-in exists and background workers use lower CPU/I/O priority.
8. PAC is reachable on `http://<SWG-IP>:8081/proxy.pac` and contains `PROXY <SWG-IP>:3128; DIRECT`.
9. Existing DIRECT bypasses remain effective after upgrade and are visible in Connection. Fresh installations contain no customer-specific bypass IPs.
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

34. System navigation contains Health & Performance, Storage, Backups and Administrators; Storage/Administrators are not duplicated under Policy & Tools.
35. System console shows cached CPU/memory/disk/proxy latency/connections/telemetry lag plus DNS, TLS certificate expiry, NTP, worker health, storage and recovery posture.
36. Live Traffic auto-refreshes every 10 seconds only while the user is not actively editing a filter control.
37. Access Profile selectors, profile statistics and the Include System Traffic filter use the light workspace visual system; no legacy black control blocks remain.
38. Overview policy coverage reports actual Application objects rather than system-domain rule count.
39. Applications provides summary metrics, card search and recent dependency health.
40. Activity provides approvals, drift, apply failures, backups, audit timeline and rollback readiness.

41. Connection is Administrator-only; Operators/viewers cannot change connection policy or download the Windows package. POSTs require valid CSRF.
42. Save & publish atomically replaces the static PAC and backs it up. Invalid input/failing publication does not overwrite stored settings. Test exact domain, wildcard boundary, IP and CIDR routing on Windows.
43. Unreachable proxy falls back DIRECT when enabled; disabled fallback returns only PROXY. A policy-denied request remains denied. Measure actual client recovery time and confirm router/firewall permits intended fallback.
44. Windows ZIP contains the target gateway's PAC address, installation guide, controller and optional GUI build helper. On a test PC, verify admin install, standard-user restrictions, PAC refresh, Stop/Start and initial-settings restore on uninstall.
45. Load the optional recorder in a test Chrome/Edge profile. Start on the application seed domain, sign in and click actions in the same tab. Confirm a button-triggered destination is captured and traffic from another tab/PC service is excluded.
46. Confirm recorder Stop, expiry, tab close and destination limit. Verify exports contain no URL paths/queries, headers, credentials or bodies. Import must create review candidates only; IP-based sessions must never grant access.
47. Restore policy state to another VM: sessions are revoked, active learning is stopped, and target-host connection settings/PAC are preserved.
48. Desktop and mobile navigation remain usable and Connection/Application pages do not overflow the viewport.
49. PC services are off by default, Administrator-only and scoped to chosen Access Profiles. Test Windows Update/Defender in SYSTEM context with appropriate WinHTTP/BITS/DO configuration. Turning off one profile must not disable shared endpoints used elsewhere.
50. Verify new-tab/pop-up and service-worker limitations on real business applications. Review candidates before applying; tab attribution does not prove endpoint necessity.

51. Health notifications are Administrator-only; password/webhook values never appear in HTML, polling, audit, delivery history or policy-state exports.
52. Configure real SMTP TLS and Slack on the VM. Explicit tests must reach intended recipients/channel and show results without holding the GUI request open.
53. Repeated failed checks produce one incident digest, confirmed recovery produces a recovery message, and email failure does not duplicate successful Slack alerts. Verify retry and optional repeat intervals.
54. Turn global notifications off and verify no automatic messages. Confirm candidate mode sends no messages, including test requests.
55. Expire a deployed test rule while an unrelated policy is pending. Verify new requests are denied for the expired destination and pending work remains unpublished; account for existing CONNECT tunnels.
56. Exercise concurrent edits during a slow apply. The recorded snapshot must match the sent configuration and newer work must remain pending.
57. Restore a portable/legacy export into a test VM of this release. Verify writer quiescence, archive/hash checks, migration, rollback-on-failure, target credentials/PAC preservation and queued-job revocation.
58. Verify the new helper RuntimeDirectory and health-monitor timer permissions on Ubuntu. Confirm an external monitor covers full-VM/network/monitor outages.
