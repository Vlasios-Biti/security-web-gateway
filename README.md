# Security Web Gateway

**Version:** 3.3.1  
**Target OS:** Ubuntu 24.04 LTS  
**Architecture:** Squid explicit proxy + FastAPI management plane + Nginx TLS + SQLite policy/telemetry store + restricted privileged deployment helper.

This repository is the source-of-truth for the Security Web Gateway. Runtime databases, TLS private keys, production certificates, passwords, logs and backups are deliberately **not** part of Git.

## Core security model

- Default deny at Squid.
- Explicit ALLOW policies only.
- Access Profiles and Network Policies provide scoped source authorization.
- Management GUI binds to loopback backend and is published by Nginx over HTTPS.
- GUI runs unprivileged as `proxy-mgmt`.
- Squid deployment is performed through a narrow Unix-socket privileged helper; there is no web shell or unrestricted sudo path.
- Application discovery cannot directly deploy policy. Discovery → Review → Pending → Diff → Deploy remains mandatory.
- Public discovery protects against private/reserved destinations and DNS-rebinding/SSRF-style pivots.
- PAC supports explicit DIRECT bypasses plus fail-open `PROXY ...; DIRECT` behavior.

## v3.3.1 update

v3.3.1 includes the v3.3 application-discovery and operational updates, plus a complete vendor-neutral rebrand:

- **Server Browser Discovery** using isolated Chromium/Playwright for JavaScript/XHR/API/CDN/WebSocket dependencies.
- **HAR workflow discovery** for authenticated/click-driven workflows without learning all workstation traffic. Raw HAR is processed in memory and is not persisted.
- `Observed Squid traffic` retained only as an Advanced/Troubleshooting discovery mode.
- Browser discovery is processed by a systemd worker so Chromium activity cannot block GUI requests and cause Nginx `504` timeouts.
- Web requests no longer parse Squid `access.log`; telemetry ingestion belongs to the collector timer.
- Dual telemetry guardrails: age retention + logical DB storage cap + cleanup target + minimum free disk.
- Raw rotated Squid log age/size guardrails.
- Metadata-only Access Profile/Application edits no longer create false policy-pending state.
- Safe stale-pending reconciliation when effective Squid directives are identical to production.
- Portable fresh-server installation and controlled v3.2→v3.3 upgrade scripts.
- Latest Windows **Proxy Control** source/builder included under `tools/windows/`.

## Repository layout

```text
app/                 FastAPI application
bin/                 operational workers / CLI tools
migrations/          ordered SQLite schema migrations
static/               CSS / JavaScript
templates/            Jinja GUI templates
privileged/           restricted root deployment helper
systemd/              application and worker units
deploy/               fresh install, upgrade, state export/restore
deploy/templates/     Nginx and Squid portable templates
pac/                  PAC template
config/               environment examples
tools/windows/         Proxy Control Windows endpoint package source
docs/                 architecture, deployment and operations documentation
.github/workflows/     GitHub CI
```

## Fresh server installation

Prepare an Ubuntu 24.04 LTS VM with the intended management/proxy IP already configured. Do **not** commit TLS keys to the repository.

With an internal/public trusted certificate:

```bash
sudo ./deploy/install.sh \
  --fqdn proxy.example.internal \
  --bind-ip 192.0.2.10 \
  --dns-servers 192.0.2.53,192.0.2.54 \
  --tls-cert /root/proxy.example.internal.crt \
  --tls-key /root/proxy.example.internal.key \
  --admin-user admin
```

For a temporary lab bootstrap only:

```bash
sudo ./deploy/install.sh \
  --fqdn proxy.example.internal \
  --bind-ip 192.0.2.10 \
  --self-signed
```

The installer deliberately does **not** change UFW/firewall policy because management-source ACLs and upstream network enforcement must be decided for the target environment.

## Future in-place upgrades

After a server is installed with the generic `security-web-gateway` filesystem/service layout, future releases can use:

```bash
sudo ./deploy/upgrade.sh --confirm
```

The upgrade performs a shadow database migration/validation first, creates a rollback backup, then changes the application release. It **does not automatically deploy pending Squid policy**. Existing traffic policy remains untouched until an administrator reviews Pending/Diff and deploys normally.

A pre-existing installation that used a different product/service/path namespace requires a controlled one-time migration or a fresh install plus policy-state restore; do not run this generic upgrade script blindly against a differently named legacy installation.

## Move current policy state to another server

Runtime state is sensitive and must stay outside Git.

On the source server:

```bash
sudo ./deploy/export_policy_state.sh
```

Copy the resulting root-only archive over a protected channel to the target server. After installing Security Web Gateway on the target:

```bash
sudo ./deploy/restore_policy_state.sh /secure/path/security-web-gateway-policy-state-....tar.gz
```

The restore migrates the DB to the target schema and revokes existing web sessions. Target IP/FQDN/TLS/PAC remain local to the new server.

## PAC behavior

Default template:

```text
DIRECT: internal/simple names, RFC1918 destinations, configured business bypass IPs
PROXY:  <server-ip>:3128
FAIL:   DIRECT fallback
```

Current explicit DIRECT business IPs in `pac/proxy.pac.tpl`:

```text
49.12.132.214
65.108.9.79
178.63.88.53
```

The return path is:

```text
PROXY <SWG-IP>:3128; DIRECT
```

PAC itself cannot force a sub-second TCP failure timeout. Fast fail-open enforcement belongs to the network layer (for example MikroTik health-check/reject logic) when that phase is enabled.

## GitHub

Use a **Private** repository unless you intentionally want the source public.

```bash
git init
git add .
git commit -m "Security Web Gateway v3.3.1"
git branch -M main
git remote add origin git@github.com:<ORG>/<REPO>.git
git push -u origin main
```

Before every push:

```bash
git status
git diff --cached
```

Verify that no `.db`, `.env`, certificate/private-key, log, backup or HAR file is staged.

## Validation

```bash
python3 -m compileall -q app bin tools privileged
bash -n deploy/*.sh
python3 tools/migrate.py --db /tmp/swg-test.db --root .
```

See `docs/DEPLOYMENT.md`, `docs/ARCHITECTURE.md`, and `docs/OPERATIONS.md` for production procedures.
