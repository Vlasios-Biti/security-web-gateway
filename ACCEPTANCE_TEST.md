# Security Web Gateway v3.3.1 Acceptance Test

1. `readlink -f /opt/security-web-gateway/current` returns `/opt/security-web-gateway/releases/3.3.1`.
2. `/healthz` on `127.0.0.1:8200` and management HTTPS returns version `3.3.1`, mode `production`.
3. `SELECT MAX(version) FROM schema_migrations` returns `012`; `PRAGMA integrity_check` returns `ok`; `PRAGMA foreign_key_check` returns no rows.
4. `squid -k parse` and `nginx -t` succeed.
5. `security-web-gateway.service`, `squid.service`, `nginx.service`, and `security-web-gateway-deploy-helper.socket` are active.
6. `security-web-gateway-telemetry.timer`, `security-web-gateway-storage-maintenance.timer`, `security-web-gateway-discovery.timer`, and `security-web-gateway-source-sync.timer` are enabled/active.
7. PAC is reachable on `http://<SWG-IP>:8081/proxy.pac` and contains `PROXY <SWG-IP>:3128; DIRECT`.
8. DIRECT bypass IPs remain present: `49.12.132.214`, `65.108.9.79`, `178.63.88.53`.
9. A standard Windows user with Proxy Control installed cannot change proxy/PAC settings without administrator credentials.
10. Traffic Explorer updates via the telemetry timer; GUI requests do not parse `access.log` synchronously.
11. System → Storage / Telemetry shows age/storage/free-space guardrails.
12. Browser discovery creates a `running` run, completes through the discovery timer, and requires explicit Review/Approve/Deploy.
13. HAR discovery does not persist the uploaded raw HAR and classifies obvious analytics/background endpoints as IGNORE.
14. Existing production policy is not auto-deployed merely by upgrading application code.
