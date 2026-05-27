# Admin / dashboard regression investigation - 2026-05-28

Reported: "/admin onbereikbaar, /dashboard rendert leeg", suspected cause a
webroot `rsync --delete` that removed `admin/public/*`.

## Conclusion: NOT REPRODUCED. No regression. No changes made.

Both `/admin` and `/dashboard` are healthy at origin and edge. No production
changes were applied (no rsync, no nginx reload, no container restart). The
suspected root cause does not hold (see below).

## Evidence (live, cache-busted)

| Check | Result |
|-------|--------|
| `https://paramant.app/admin/` | HTTP 200, title "PARAMANT - Admin" |
| `https://paramant.app/admin/settings.html` | HTTP 200, title "Paramant Admin - Settings" |
| `https://paramant.app/admin/cli.html` | HTTP 200 |
| `https://paramant.app/dashboard` | HTTP 200, title "Developer Dashboard", 55,007 bytes |
| `/dashboard` cards-grid / card-header matches | 15 |
| admin container `paramant-relay-admin` | Up ~1h (healthy), `127.0.0.1:4200->4200` |
| origin `http://127.0.0.1:4200/admin/` | HTTP 200 |
| origin `http://127.0.0.1:8080/dashboard` | HTTP 200 |
| webroot `dashboard.html` | present, 55,007 B, cards-grid x15 |

## Why the suspected root cause does not hold

1. **`/admin` is NOT served from the static webroot.** nginx
   (`sites-enabled/paramant-public.conf`) routes
   `location /admin/ { proxy_pass http://127.0.0.1:4200/admin/; }` -- i.e. to
   the admin Docker container, which serves its own bundled `public/` from
   inside the image. A static webroot is never consulted for `/admin/`, so a
   webroot rsync (with or without `--delete`) cannot make `/admin`
   unreachable. The absence of a `/home/paramant/app/admin/` directory is the
   normal, correct state -- not a regression.

2. **The prior webroot sync did not use `--delete`.** The 2026-05-27 sync
   (PR #70) ran `rsync -a` WITHOUT `--delete` specifically to preserve
   server-only files. It could not have removed anything.

3. **`/dashboard` is fully present.** `dashboard.html` (55 KB, 15 cards-grid
   markers) is served correctly by the `:8080` static block; the page is not
   empty.

## Most likely explanation of the report

A transient blip during the earlier 3.0.0 deploy/sync window (the admin
container was recreated then -- it now shows ~1h uptime) and/or browser cache
showing a stale state. Both surfaces have been healthy since.

## Action taken

None. Acting on the proposed fix (rsync `admin/public/` -> `webroot/admin/`)
would have created files nginx never serves (dead clutter) and overwritten a
healthy webroot, while not affecting `/admin` at all. Reported instead.

## If it recurs

Check, in order: `docker ps --filter name=admin` (container health),
`curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:4200/admin/` (admin
app direct), then `curl ... http://127.0.0.1:8080/dashboard` (static). The
webroot is not involved in `/admin`.
