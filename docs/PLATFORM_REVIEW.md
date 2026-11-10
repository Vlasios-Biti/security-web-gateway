# Platform review — 3.11

The review prioritizes a small administration surface, dependable policy publication, useful alerts and attributable application discovery. It does not claim a certification or a complete penetration test.

## Comparison with established products

- [Cloudflare One DEX notifications](https://developers.cloudflare.com/cloudflare-one/insights/dex/notifications/) expose connectivity/performance alerts with configurable triggers. This release adds local service/resource/worker checks, configurable thresholds, independent email/Slack channels and confirmed recovery. Distributed endpoint experience monitoring remains a separate future feature.
- [Zscaler alert administration](https://help.zscaler.com/zia/about-alerts) separates alert triggers, severity and recipient subscriptions. This release uses one GUI page with channel switches, minimum severity, confirmation counts, reminders and delivery history; the local gateway does not implement Zscaler's cloud threat detection services.
- [Cloudflare Health Checks notifications](https://developers.cloudflare.com/health-checks/how-to/health-checks-notifications/) distinguish health checks from their notification configuration. The gateway likewise keeps sampling and deployed-policy expiry running independently of the optional notification master switch.

Sources checked 2026-11-10. These are design comparisons, not claims of feature parity.

## Reviewed behavior and changes

Connection settings consolidate PAC routing, direct destination exceptions, optional fail-open behavior and the Windows client package. Optional Windows Update, Defender and connectivity profiles stay explicitly selectable. A PAC file governs supporting clients; it is not a router or a guarantee that every Windows service uses the same proxy settings.

Application workflows provide both selected-tab recording and HAR import. These capture requests made during the actions an administrator actually performs, including login and button-triggered requests, without attributing unrelated PC traffic by source IP. Public browser discovery also remains available with restricted egress. None can promise every dependency for unvisited actions, roles or future platform changes. Imported destinations require review before they become access policy.

The operational review corrected expired-rule evaluation, publication races, privileged policy validation, discovery DNS rebinding exposure, export hash portability and restore staging. See [Health notifications and operational safety](HEALTH_NOTIFICATIONS.md) for configuration, limitations and validation details.

## Recommended next increments

1. An external heartbeat/uptime integration for total VM or network loss. A notification worker on that same VM cannot report those outages itself.
2. Administrator MFA/SSO and centralized identity integration if the installation needs more than the existing local administrative roles.
3. Optional SIEM/syslog export and longer incident retention for organizations with centralized operations.
4. Guided application recapture after platform changes, retaining review of new shared/CDN domains rather than automatically granting all observed third-party destinations.

These remain recommendations; this release does not silently add configuration surfaces or enable integrations without an administrator selecting them.
