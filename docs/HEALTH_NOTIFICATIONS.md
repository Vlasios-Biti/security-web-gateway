# Health notifications and operational safety — 3.11

## Configure everything from the GUI

Open **Alerts & SNMP** as an Administrator. Email and Slack are independent options; both and the global notification switch are off by default. No credentials are supplied with the source code.

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


## Optional SNMP polling and traps (3.12)

SNMPv2c is available as two independent opt-in options under Alerts & SNMP: outbound incident/recovery traps and inbound read-only polling. Both start off. This revision does not implement SNMPv3, encryption or INFORM acknowledgements. Use a private management network and a long private community; community/notification values are visible to observers on that network. The secret is masked and stored in the same protected VM configuration as other channel credentials, outside Git and state exports.

For traps configure the receiver's IPv4 address, UDP port (normally 162) and community. Enable the notification master switch for automatic incidents; the explicit queued SNMP test works independently. A SENT history row means local UDP submission, not confirmed receiver delivery. The global minimum severity, confirmation, deduplication, recovery and retry rules apply, though an unacknowledged UDP packet loss cannot be detected/retried by the sender.

For polling configure a specific gateway listener IPv4, UDP port (default 1161, range 1024–65535) and explicit permitted monitoring IPv4 addresses/subnets. There is no default public/community listener and no SET support. Source filtering, bounded packet/response size, GETBULK limits and response rate limits apply. The optional service watches configuration changes and opens/closes its listener accordingly. Polling is independent of the notification master switch. Configure firewall access to this UDP port only from the monitoring servers; installation does not alter the firewall automatically.

The default numeric base is `1.3.6.1.4.1.32473.42`, an example enterprise branch. Configure your assigned enterprise branch for production integration. The following scalar suffixes are readable:

| Suffix | Value |
| --- | --- |
| .1.0 | Health: 0 unknown, 1 healthy, 2 warning, 3 critical |
| .2.0 | Active incident count |
| .3.0 | CPU percent multiplied by 100 |
| .4.0 | Memory percent multiplied by 100 |
| .5.0 | Disk percent multiplied by 100 |
| .6.0 | Sampler stale: 1 stale, 0 fresh |
| .7.0 | Proxy listener: 1 up, 0 down, -1 unknown |
| .8.0 | Application version string |

Standard sysDescr.0, sysName.0 and agent-process sysUpTime.0 are also readable. Metric snapshots refresh about every five seconds from existing health/performance data; use health/stale indicators before interpreting zero resource values. Notification OID is base.0.1 with message at base.10.0 and severity at base.11.0. These scalar/OID conventions are documented for manual configuration in your NMS; no vendor MIB or automatic NMS provisioning is implied.

Local tests exchange real SNMP packets over loopback and verify read-only responses, wrong-community/source rejection, bounded bulk responses and trap decoding. Actual remote NMS receipt, polling, UDP firewall behavior and service installation need a target-VM acceptance check. See [Net-SNMP notification semantics](https://www.net-snmp.org/tutorial/tutorial-5/commands/snmptrap-v3.html) for the distinction between traps and acknowledged informs.

In 3.12.2, Alerts & SNMP is a direct primary navigation entry. Channel links at the top jump directly to Email, Slack or SNMP, without opening the Monitoring submenu. Administrator access remains required.


### Slack delivery choices (3.12.3)

In **Alerts & SNMP → Slack**, select categories (services, resources, DNS, certificate, backup, workers, clock, traffic, policy drift), severity, recovery notices, repeat interval and compact/detailed messages. All categories selected, inherited severity/repeats and recovery enabled preserve previous behavior. An empty category selection pauses incident delivery to Slack only. Tests bypass category filters, but never mention people.

Each Incoming Webhook has a destination channel selected during Slack authorization. The optional channel label is documentation only; replace the webhook to change the channel. Add up to ten explicit Slack member IDs (U/W...) or user-group IDs (S...). Mentions default to critical alerts only; recovery and tests never mention. Slack access, group membership and personal notification settings determine actual push delivery. The gateway does not fetch workspace members or send direct messages.

Only configured mention tokens use Slack markup; incident text remains plain text. Slack settings do not modify email/SNMP preferences. Existing deduplication, confirmation and delivery backoff continue to apply.

References: https://docs.slack.dev/messaging/sending-messages-using-incoming-webhooks/ and https://docs.slack.dev/messaging/formatting-message-text/
