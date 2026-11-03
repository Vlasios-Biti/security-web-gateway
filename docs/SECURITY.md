# Security Notes

- Keep the GitHub repository private by default.
- Never commit runtime DBs, `.env`, TLS private keys, certificates containing private material, HAR captures, logs or backup archives.
- Require standard users on Windows endpoints; Proxy Control changes require UAC/admin credentials.
- Windows proxy policy is not complete network enforcement. Applications with independent networking stacks or unauthorized VPNs require router/firewall controls.
- Do not expose FastAPI TCP/8200 outside loopback.
- Do not expose the privileged Unix socket outside the local host.
- Browser discovery runs as `proxy-mgmt`, not root, and rejects private/reserved destination resolution.
- HAR files can contain credentials/cookies. v3.4 parses the uploaded content in memory and stores only endpoint evidence; administrators must still treat the local HAR file as sensitive.
- Maintain centralized system/journal/Nginx/Squid logging and monitor failed systemd units.
