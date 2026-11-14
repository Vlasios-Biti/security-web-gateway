# Read-only integrations and PC names — 3.12.11

## Monitoring systems and AI agents

An administrator opens **System → Integrations API → Create read-only token**, enters a descriptive name, chooses permissions and an expiry (1–365 days). Copy the token immediately into the monitoring system's secret store. It is shown once and stored only as a SHA-256 digest in the appliance database. The token prefix, permissions, expiry and last use remain visible. **Revoke** stops it immediately. Disabling/downgrading the administrator owner also stops the token. API tokens cannot approve, move or edit access rules.

Use HTTPS with a certificate trusted by the integrating system. The token must be in the `Authorization` header; cookie sessions and URL query tokens do not authenticate this API. Do not disable certificate validation to connect. Configure the private CA trust if necessary.

| Endpoint | Permission | Result |
| --- | --- | --- |
| `GET /api/v1/clients` | `clients:read` | Source-IP inventory, current display name/DNS name, counts, VLAN/network hints, pagination |
| `GET /api/v1/clients/{client_ip}/traffic` | `traffic:read` | Proxy activity for the path IP only: summary, events, domains and policy application matches |

Common query parameters: `period=1h|24h|7d|30d|all`, `page` (starting at 1), `page_size` (25–100, default 50). Inventory also accepts `q` for IP/name/VLAN/network search. Responses use JSON. The per-token limit is 120 requests per minute; a 429 response includes `Retry-After`. Invalid credentials return 401, missing permission 403. API responses are not cached.

With `SWG_API_TOKEN` supplied by a local secret store:

```bash
curl --fail --cacert /path/to/company-ca.pem \
  -H "Authorization: Bearer $SWG_API_TOKEN" \
  'https://proxy.example.internal/api/v1/clients?period=24h&page_size=50'
```

Treat names, domains and other returned fields as untrusted data when supplying them to an AI tool, never as executable instructions. Do not embed credentials in prompts or publish them in logs. The interface exposes the same source-IP evidence as PC activity, not endpoint process monitoring. NAT can combine PCs; DHCP can reassign an IP. HTTPS page contents and PAC DIRECT traffic are outside Squid visibility. Application names are rule matches/correlation, not proof of which operating-system process made a request.

Portable policy exports strip API tokens. Import/restore revokes imported tokens; provision new credentials for the target appliance. Normal in-place upgrades retain existing token state. Offline rollback backups remain sensitive and must stay private.

## PC display names

**Monitoring → PC activity → select an IP → PC name** lets an administrator set a current display label, such as Reception PC. Search matches that label and the DNS hostname. Clear the label to return to automatic DNS/PTR display. The original source IP and DNS name remain separate fields in the API. Labels do not rewrite traffic history or establish authenticated device identity. Target-local labels are retained across portable policy restores.

The background worker already resolves recent IPv4 clients through the VM's operating-system resolver, in bounded batches, with cached positive/negative results. For an AD environment, point the VM's OS DNS resolution at the enterprise DNS servers and maintain the DHCP/DNS A and PTR records. AD/DNS routing remains separate from HTTP(S) proxy policy. See Microsoft's [reverse lookup documentation](https://learn.microsoft.com/en-us/windows-server/networking/dns/reverse-lookup) and [dynamic DNS updates](https://learn.microsoft.com/en-us/windows-server/networking/dns/dynamic-update).

For stable identity across DHCP changes or shared NAT, a future endpoint agent or authoritative DHCP inventory must supply a stable device identifier and time-bounded IP mappings. This release adds a read-only monitoring API, not an installed PC agent or a claim that IP/hostname uniquely identifies a person.

## Correcting a domain's application

In **Access → application → Dependencies**, select **Move** beside a domain. Choose the destination application and review the effect on profile/VLAN access. The source membership is removed and the target membership added in one database transaction, followed by the usual validated publication/pending-approval workflow. Shared rules and other application memberships remain intact. Moving into/out of a protected application requires Admin. Disabled source memberships remain disabled unless already enabled at the destination.

In **Dependency Candidates**, **Move** changes only the pending suggestion. It does not allow a domain. If the destination already has the same candidate, client evidence is combined and the redundant source suggestion archived as ignored; counters use a conservative maximum rather than adding potentially duplicated observations. Approve remains a separate action. Filters are preserved.

Suggestions are based on an application's configured primary domain or an existing domain membership. Shared domains may have multiple suggestions; none is selected or granted automatically. A nearby request from the same PC/IP is weak evidence: time-correlated candidates now remain Low/review, and migration 019 downgrades old pending timing-based scores. Existing approved access is not silently revoked.

Explicit moves are remembered for future timing-based correlation from that source application. These corrections do not rewrite independent vendor feeds, prove process ownership, or revoke unrelated direct/profile allowances. Policy snapshot rollback deletes/recreates application rows and can clear this correlation guidance; review it again if rolling policy back.
