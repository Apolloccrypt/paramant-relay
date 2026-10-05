# Paramant Security Roadmap

## Phase 1 - Baseline audit (current)
Run scripts/security/audit.sh. Record findings in COMPLIANCE-CHECKLIST.md.
Identify CRITICAL gaps (open /setup, unauth admin, web-reachable secrets).

## Phase 2 - By-design development
Build remaining features (dashboard-as-workplace, etc) under the four
non-negotiable rules in PARAMANT-SECURITY-STANDARD.md. Each PR is
checked against the controls it touches. No PR regresses a PASS.

## Phase 3 - ASVS hardening pass
Drive every checklist item to PASS at its required level (L2 baseline,
L3 for crypto + admin). Order CRITICAL > HIGH > MED. Each auth/network
change carries a tested fallback so the operator is never locked out.

Priority order:
1. CFG-01 - gate /setup after first-run
2. AC-02 / API-02 - server-side admin authz everywhere
3. AUTH-02 - enforce TOTP, no bypass
4. ARCH-02 / COMM-03 - admin network isolation (VPN/IP-allowlist)
5. AUTH-04 - auth rate-limit + lockout
6. VAL-04 - admin CLI whitelist hardening
7. Remaining L2 controls

## Phase 4 - External pentest
Engage an independent firm (Cure53 named as candidate). Scope: full
application, admin surface, crypto paths. Resolve all findings before
publishing the result on /security.

## Phase 5 - Continuous
- Per PR: four rules + touched controls.
- Per release: full checklist run + threat-model review.
- Annually / major change: re-pentest.
- Audit script in CI: scripts/security/audit.sh gates merges.
