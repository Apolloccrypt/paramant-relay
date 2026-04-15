# Security incidents log

## 2026-04-15 — Credential exposure remediated

### What
gitleaks scan revealed historical exposure of credentials in git history.

### Findings
- RESEND_API_KEY (re_K1YQ...XvA) committed in deploy/systemd/*.service files on 2026-04-01
- 3x demo API keys (pgp_...) committed in frontend/index.html and poc/README.md between 2026-04-01 and 2026-04-07

### Remediation
- RESEND_API_KEY: verified invalid via Resend API on 2026-04-15 (revoked, mechanism unknown)
- Demo pgp_ keys: verified status [PENDING] / revoked via /admin/ on 2026-04-15
- Server .env permissions: hardened to 600 on 2026-04-15
- gitleaks pre-commit hook installed on 2026-04-15

### Note on git history
Historical commits still contain the (now-invalid) credentials. Rewriting
git history would break existing clones with no security benefit since
the credentials are revoked. Documented here for transparency.
