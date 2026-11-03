# GitHub Repository Guidance

Recommended repository visibility: **Private**.

Branch model for a small infrastructure team:

- `main` — production-ready releases
- short-lived `feature/*` and `fix/*` branches
- pull request required into `main`
- tagged releases: `v3.4.0`, `v3.4.1`, etc.

Recommended protections:

- require CI before merge
- require at least one review for production changes
- prohibit force push to `main`
- enable secret scanning / push protection where available
- signed commits/tags if your organization already maintains signing keys

Never store production runtime state in Git. Use `deploy/export_policy_state.sh` for a separate sensitive backup/migration artifact.
