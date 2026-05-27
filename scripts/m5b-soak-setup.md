# M5b DEV-relay supervised soak (systemd --user)

This sets up the M5b DEV relay (running on the `@paramant/core` ML-KEM-768
binding) as a supervised `systemd --user` service plus a 5-minute soak timer, so
the 7-day soak survives shell-exit and reboot without touching production. No
sudo required; this is a developer-machine DEV instance on loopback only.

## Why systemd --user (not podman)

`relay.js` boots standalone -- Redis, NATS and TOTP are all opt-in via env, and
it serves plain HTTP. So a direct `node relay.js` under a user service is the
simplest stable supervisor; no image build or container runtime is needed.
`systemctl --user` works without root, and `loginctl enable-linger` (also
non-root here) makes the units survive logout and reboot.

## Units

Installed under `~/.config/systemd/user/`:

- `paramant-relay-dev.service` -- runs `node relay.js` from
  `~/paramant-relay-m5b/relay` with `Restart=on-failure`. DEV env: `PORT=3777`,
  `HOST=127.0.0.1`, no Redis/NATS/TOTP. State (identity, STH, peer-STHs) is
  redirected from the production `/data/*` defaults to
  `~/.local/state/paramant-m5b/` via `RELAY_IDENTITY_FILE`, `STH_FILE`,
  `TRIAL_KEYS_FILE`, `PEER_STH_DIR`, so the relay identity persists across
  restarts and there are no `/data` EACCES warnings. Logs append to
  `~/.local/state/paramant-m5b/relay.log`.
- `paramant-m5b-soak.service` (oneshot) + `paramant-m5b-soak.timer` -- runs
  `~/.local/bin/paramant-m5b-soak-check.sh` every 5 minutes, appending a
  `health=... mlkem768=...` line to `~/.local/state/paramant-m5b/soak.log`.

## Install

```sh
mkdir -p ~/.config/systemd/user ~/.local/state/paramant-m5b ~/.local/bin
# copy paramant-relay-dev.service, paramant-m5b-soak.service,
# paramant-m5b-soak.timer into ~/.config/systemd/user/
# copy paramant-m5b-soak-check.sh into ~/.local/bin/ and chmod +x it
systemctl --user daemon-reload
systemctl --user enable --now paramant-relay-dev.service
systemctl --user enable --now paramant-m5b-soak.timer
loginctl enable-linger "$USER"        # survive logout + reboot
```

(The unit files and the check script live on the developer machine, not in this
repo; this doc records their content and the procedure. The relay needs
`@paramant/core` installed in `relay/` -- see PR #32.)

## Operate

```sh
systemctl --user status paramant-relay-dev.service
curl -sf http://127.0.0.1:3777/health
curl -sf http://127.0.0.1:3777/v2/capabilities      # ML-KEM-768 loaded:true
tail -f ~/.local/state/paramant-m5b/soak.log        # 5-min samples
systemctl --user list-timers paramant-m5b-soak.timer
```

A clean 7-day soak is: every `soak.log` line shows `health={"ok":true...` and
`mlkem768="name":"ML-KEM-768","loaded":true`, with no gaps or `DOWN`/`MISSING`.

## Rollback / teardown

```sh
systemctl --user disable --now paramant-relay-dev.service paramant-m5b-soak.timer
loginctl disable-linger "$USER"        # optional
# the relay swap itself rolls back via: git checkout main && npm uninstall @paramant/core
```

No wire-format change, so nothing produced during the soak needs migration.
