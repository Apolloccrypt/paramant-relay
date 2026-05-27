# R001. Hot-fix flow and main reconciliation

Date: 2026-05-27
Status: Accepted

## Context

Production occasionally needs urgent fixes that cannot wait for the full PR review
cycle (an auth bug blocking login, data-loss risk). Historically such fixes were
applied directly to a production branch without integrating back to main. This
caused drift discovered during the M5b deploy: production ran
`fix/login-email-in-memory-keys` with two auth fixes that never reached main, so a
naive "deploy main" would have regressed them. PR #35 had to retroactively
cherry-pick those two commits onto main.

## Decision

Hot-fixes follow this pattern:

1. **Urgent (class S0):** apply on a dedicated `prod-hotfix/<short-name>` branch and
   deploy to production directly. Acceptable only for S0.
2. **Within 24 hours:** open an integration PR
   (`integrate/<hotfix-name>-into-main`) that cherry-picks the hot-fix commits onto
   main. Standard CI gate applies; rapid review (15-minute target).
3. **Merge:** the hot-fix is now in main. The next routine deploy realigns
   production to main.
4. **Audit:** tag the production state before the hot-fix (for example
   `prod-pre-hotfix-<date>`) for rollback.

Class S0 criteria: production-blocking bug (users cannot complete primary flows),
security regression (auth bypass, data leak), or live service degradation needing
immediate intervention. Anything below S0 follows the standard PR flow, no
exception.

## Consequences

- Main stays the source of truth (paramant-core ADR-0003 respected).
- Production drift is bounded to 24 hours, not weeks.
- Hot-fixes get an audit trail via the integration PR.
- Future deploys can safely `git checkout main && git pull` without surprises.

## Alternatives

- Strict PR-only, no hot-fixes: rejected; real auth bugs need a 5-minute fix, not a
  one-day cycle.
- Hot-fix only on main: rejected; urgency sometimes precludes the CI wait.
- No integration-PR requirement: rejected; that is exactly how the M5b drift
  happened.
