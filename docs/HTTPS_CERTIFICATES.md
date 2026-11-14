# GUI certificate management — 3.12.13

Open **Connection → HTTPS certificate**. This visible card shows the panel certificate's subject, issuer, names and expiry, independently of the PAC address editor. Health links directly here. All certificate operations require Admin and valid CSRF; candidate mode does not publish changes.

## Import or renew an issued certificate

Expand **Import / renew from a certificate file**, choose a format and import:

- **PEM**: full certificate chain and matching unencrypted PEM private key, up to 64 KB each.
- **Windows PFX / PKCS#12**: one `.pfx`/`.p12` bundle containing the certificate/private key and its chain, up to 64 KB. Enter its password if protected. Legacy cipher bundles may need to be re-exported with modern AES-compatible settings. See [OpenSSL PKCS#12 input handling](https://docs.openssl.org/3.0/man1/openssl-pkcs12/).

PFX passwords are passed to OpenSSL over standard input, never command arguments, audit records or saved settings. The bundle and extracted private material exist only in root-only temporary files during import. Only public PEM certificate blocks are written to the public certificate file; a combined legacy PEM cannot leak its key through the public download.

The gateway verifies key pairing, dates and coverage of the configured management FQDN and any selected HTTPS PAC hostname before replacing files. To access the panel by IP, include that IP in the certificate; a trusted DNS name is preferable for a CA-issued deployment. Nginx configuration/reload is checked and the old pair restored if publication fails. Custom nginx certificate/key paths still require their existing management process; the helper writes only the standard gateway paths.

For an enterprise/public CA, obtain the renewed certificate from that issuer and import it here. This GUI does not obtain certificates automatically from AD CS/ACME, perform a CA renewal request, or change DNS/client trust. Keep an existing ACME renewal process responsible for certificates that it owns.

## Renew an existing self-signed certificate

For an existing self-signed certificate the card also exposes **Renew the existing self-signed certificate**. Choose 90 days or one year, confirm, and the gateway generates the replacement locally using the existing private key and subject. Names include its configured panel FQDN, current proxy IP and HTTPS PAC hostname. Old, unconfigured IP SANs are not carried forward automatically.

The root helper verifies that the current certificate is genuinely self-signed, including its self-signature, before generating a replacement. It refuses this operation for a CA-issued certificate. The same key/date/hostname/nginx checks and failure rollback apply. A generated service certificate is not a new inspection CA. Renewal does not enable TLS interception, change VLANs/profiles, or modify allow policies.

Clients may need to trust the renewed certificate again, even with the same key. Download the new public certificate and update trust on pilot browsers/PCs/monitoring systems before relying on HTTPS PAC or the integrations API. The service does not install trust on computers automatically. Existing TLS connections can continue briefly with their old session; test a fresh connection after renewal. Health warnings clear through the normal confirmed sampling/recovery cycle.

## Download

**Download public certificate** exports public certificate blocks only, never a private key or PFX password. For a CA-issued service certificate, distribute/trust the issuing CA chain through the organization's normal GPO/MDM/monitoring configuration. Downloading the service leaf does not automatically establish CA trust.

The installed private key remains mode 0600 and is not included in portable policy exports. No real installed VM certificate is replaced by source tests; pilot deployment and client trust must be checked on the actual appliance.
