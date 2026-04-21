# Regression test suite

Guards the auth + TOTP stack against the class of breakage that hit production repeatedly.

## Scripts

| Script | When it runs | What it checks |
|---|---|---|
| `tests/static-sanity.sh` | pre-commit hook, `deploy.sh` step 1 | Node syntax, redisClient init, TOTP helpers, unsafe req.body access, orphan code, 410 in source |
| `tests/auth-smoke.sh` | `deploy.sh` step 4 | 21 live HTTP assertions against production |
| `deploy.sh` | manual deploy | Chains: sanity → build → health wait → smoke |

## Running manually

```bash
# Static analysis only (no network)
./tests/static-sanity.sh

# Live smoke tests against production
./tests/auth-smoke.sh

# Full safe deploy (builds admin container)
./deploy.sh admin

# Smoke against staging / local
PARAMANT_BASE=http://localhost:4200/admin ./tests/auth-smoke.sh
```

## Pre-commit hook

`tests/static-sanity.sh` is installed as `.git/hooks/pre-commit`. Commits that introduce syntax errors, undefined redisClient, or a missing 410 on /request-key are blocked automatically.

## Adding new checks

- **Static checks** go in `tests/static-sanity.sh`. Exit 1 on failure so the pre-commit hook blocks.
- **Live checks** go in `tests/auth-smoke.sh`. Use `check`/`check_not` helpers. Never hardcode credentials.
