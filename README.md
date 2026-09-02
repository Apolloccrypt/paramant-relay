# Screenshots, signed-in dashboard and account

Playwright, Chromium, 390x844 viewport, full page, written straight to JPEG by
`scripts/shot-dashboard.mjs` on `feat/dashboard-ingelogd`. The account endpoints
are stubbed, including the per-product tier fields, so no live relay is needed.

- `390-*-before.jpg` are `main`: what Mick sees on his phone today.
- `390-*-community.jpg` is the branch on a free account: unified plan
  `community`, both product tiers at their floor.
- `390-*-pro.jpg` is an account whose unified plan is `pro`, granted by hand
  rather than bought.
- `390-*-selfserve.jpg` is the case that was broken: unified plan still
  `community`, ParaSign tier `pro` with a running paid period. The badge reads
  Pro, the give-back band is gone, the paid band names only the product actually
  bought, and on /account the Active badge and Cancel button are visible to the
  person paying for them.

Offsets measured on the same runs, in px from the top of the page, viewport 844:

| | plan band | upgrade link | first action | second action |
| --- | --- | --- | --- | --- |
| before (`main`) | 323 | 624 | 718 | 1004 |
| after | 1132 | 1413 | 323 | 612 |

This branch carries images only. It is not meant to be merged.
