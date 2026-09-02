# Screenshots, signed-in dashboard and account

Playwright, Chromium, 390px viewport, full page. Produced by
`scripts/shot-dashboard.mjs` on the branch `feat/dashboard-ingelogd`, with the
account endpoints stubbed so no live relay is needed.

- `390-dashboard-before.jpg`, `390-account-before.jpg` are `main`, which is what
  Mick sees on his phone today.
- `390-dashboard-community.jpg`, `390-account-community.jpg` are the branch on a
  free account: unified plan `community`, both product tiers `free`.
- `390-dashboard-pro.jpg`, `390-account-pro.jpg` are the branch on an account
  whose unified plan is `pro`, granted rather than bought.
- `390-dashboard-selfserve.jpg`, `390-account-selfserve.jpg` are the case that
  was broken: unified plan still `community`, ParaSign tier `pro` with a running
  paid period. The badge reads Pro, the upgrade band is gone, and the paid band
  names only the product actually bought.

This branch carries images only. It is not meant to be merged.
