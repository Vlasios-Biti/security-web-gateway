# Health notifications and operational safety — 3.11

## Configure everything from the GUI

Open **System → Health notifications** as an Administrator. Email and Slack are independent options; both and the global notification switch are off by default. No credentials are supplied with the source code.

1. For email, enter SMTP hostname, port, STARTTLS/implicit TLS, optional username/password, sender address and up to twenty recipients. Certificate verification is mandatory. Use an organisation-approved SMTP relay or an SMTP/app password supported by your provider; OAuth-only mail providers require an appropriate relay or a future OAuth integration.
2. For Slack, create an Incoming Webhook for the desired Slack channel and paste its secret URL. The channel is selected when the webhook is authorised in Slack. Only HTTPS webhooks on hooks.slack.com or hooks.slack-gov.com are accepted; redirects are not followed.
3. Save settings and use **Send test email** or **Send test to Slack**. Tests are explicitly queued for the worker, can be sent while the global notification switch is off, and require the individual channel to be configured/enabled. Results update automatically in delivery history. Tests expire after ten minutes and are cancelled if the saved destination configuration changes.
4. Enable the global notification switch when ready. Choose warning/critical or critical-only delivery and adjust thresholds under Advanced settings.

Slack setup: https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks
SMTP/TLS reference: https://docs.python.org/3.12/library/smtplib.html

## What is monitored

The independent low-priority health monitor checks proxy/management services, proxy listener, disk, memory, CPU, DNS, NTP, management certificate expiry, background timers, telemetry lag, cached-sampler freshness, recorded backup age, policy drift and failed scheduled access expiry. Backup age refers to a successful recorded configuration backup; it is not a substitute for a restore drill or an off-VM backup.

The default is two failed checks before notification and two healthy checks before recovery. Related updates are batched per channel (up to ten per batch). An incident is not repeated every polling cycle. Unresolved incidents can repeat after the configured interval, or only once until state changes when repeat is zero. Severity changes create an update. Recovery is only sent to a channel that previously received that incident.

Each channel retries independently with bounded exponential backoff. A successful Slack delivery is not repeated just because email failed. SMTP refusal, TLS and HTTP failures are recorded as short error codes without credentials or provider response bodies. Delivery retries have at-least-once semantics: a remote server that accepts a message but loses its acknowledgement can cause a duplicate. Exactly-once SMTP/webhook delivery is not guaranteed.

The health timer runs around a minute after the prior run finishes, with a 90-second boot delay. External delivery never happens in a GUI request and never sits in Squid's request path. A nonblocking process lock avoids overlapping monitor instances. Channel failure does not stop incident collection or the other channel. Scheduled policy expiry is attempted before notification settings or transports are used.

The same VM cannot send an alert after total VM/power loss, loss of its network path, or failure of the monitor itself. Use an external uptime/heartbeat monitor for those cases. Delivery through a mail server or Slack also requires working DNS, network egress and provider credentials.

## Credential boundary

Production credentials are stored only in `/etc/security-web-gateway/notifications.json`, written atomically by the restricted root helper with root ownership, proxy-mgmt read access and mode 0640. This is OS permission protection, not application-level encryption at rest. Protect VM disks and root access accordingly.

Password/webhook inputs are blank when rendering saved settings. Blank preserves an existing secret; explicit Remove clears it. Changing the SMTP server or username requires re-entering or clearing the saved password, preventing its implicit reuse on a different server. Configuration revisions are serialized under a root lock. UI, polling, audit and delivery history never return stored passwords/webhook URLs. Credential files are outside Git and policy-state exports; cross-host state restores keep the target VM's notification configuration.

Candidate preview can save a local protected preview configuration but cannot send notifications or test messages.

## Policy and recovery corrections

- Policy generation and simulation exclude expired or malformed expiry dates. Form dates are normalized/displayed in UTC.
- The monitor expires already-deployed grants from the published snapshot, not from current desired state. Queued Operator/Admin changes are not published as a side effect. Expiry therefore applies on the monitor cadence rather than exactly at the deadline; an existing established CONNECT tunnel can outlive a policy reload. Check the monitor's health and use an external control if an exact session termination deadline is required.
- GUI policy writes and automatic discovery approval share a cross-process edit lock. Publications freeze configuration and snapshot in one database view and only clear pending flags if the complete policy state, including relationship tables, is unchanged. Updates arriving during the privileged call remain pending.
- The root helper checks the live base hash, validates a narrow managed-policy grammar and copies immutable validated bytes. Managed content cannot include arbitrary Squid include/program directives. Runtime locking has its own writable systemd RuntimeDirectory.
- Server browser discovery blocks Service Workers and forces HTTP(S) traffic through an authenticated loopback egress proxy. Outbound sockets use vetted numeric public addresses; a second browser DNS resolution cannot silently select a private address. Loopback proxy bypass, QUIC and non-proxied WebRTC are disabled. The proxy limits concurrency, headers, bytes and tunnel lifetime. Public-page discovery remains partial workflow evidence, not a guarantee that every necessary domain is found.
- Export manifests use relative database names. Restore staging also accepts old absolute-path manifests by verifying the extracted database directly. Only three expected regular archive entries are accepted; links, traversal entries, corrupt hashes and inconsistent databases are rejected before cutover.
- Restore stages/migrates first, quiesces active writers and all timers, backs up the old database, replaces the database atomically and restores the prior database on failed cutover. Queued discovery jobs, test messages, sessions and incident delivery state are revoked/reset. Target PAC/TLS/notification credentials remain local. Review and apply restored desired policy separately; importing state does not blindly replace live Squid policy.

## Installation and verification

Fresh install/upgrade deploys `security-web-gateway-health-monitor.service` and `.timer` alongside existing workers. Release 3.11 uses migration 017. An upgrade refuses to delete/stage into the currently active release directory. Failed upgrade rollback removes the new monitor units if the previous release had none.

`tests/smoke_v3110.py` includes existing connection/capture regressions plus incident confirmation, deduplication, recovery, per-channel retry, credential masking, TLS ordering, Slack redirect rejection, queued tests, frozen policy publication, deployed-only expiry, archive staging and discovery-proxy checks. Transport tests use mocks and do not contact real recipients.

Before production rollout verify systemd permissions, real Squid parsing/reload, SMTP delivery/TLS with your provider, the chosen Slack channel, an actual restore drill and external outage monitoring on the target VM. None of those credentials or destinations are presumed from a developer machine.
