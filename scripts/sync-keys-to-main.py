#!/usr/bin/env python3
"""Sync paramant relay users.json deltas between sectors.

ROOT CAUSE: admin/server.js SECTORS was missing 'main'. New signups fan out
to health/legal/finance/iot but never to main. main's users.json fell behind.

This script computes the delta from a "source" sector to a "target" sector
and POSTs the missing keys via /v2/admin/keys. It is idempotent: the relay
returns 409 for keys that already exist, which the script treats as success.
It does NOT touch users.json on disk -- every write goes through the relay
HTTP API so the running relay's in-memory apiKeys Map stays consistent.

USAGE (intended to run on the prod box where the relay containers live):
    sudo ./sync-keys-to-main.py --dry-run              # default, writes nothing
    sudo ./sync-keys-to-main.py --apply                # require explicit flag
    sudo ./sync-keys-to-main.py --apply --source health --target main
    sudo ./sync-keys-to-main.py --apply --target health --orphan-adopt
        # adopt main-only orphans into health (and the other 3 sectors)

DRY-RUN OUTPUT lists:
  - count of keys to be added (source-only set, after active-filter)
  - the orphans (target-only set) so the operator can inspect them

REQUIREMENTS: docker exec access to the relay containers; ADMIN_TOKEN must
be readable from /etc/paramant/admin-token or ADMIN_TOKEN env var.
"""
import argparse
import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone


CONTAINER_PREFIX = "paramant-relay-"   # e.g. paramant-relay-main, -health, ...
RELAY_PORT       = 3000
ALL_SECTORS      = ["main", "health", "finance", "legal", "iot"]
BACKUP_DIR       = "/home/paramant/backups"


def read_users_json(container: str) -> dict:
    """Read /data/users.json from a running container."""
    r = subprocess.run(
        ["docker", "exec", container, "cat", "/data/users.json"],
        capture_output=True, text=True, timeout=10,
    )
    if r.returncode != 0:
        raise SystemExit(f"FAIL: docker exec {container} cat /data/users.json -> {r.stderr.strip()}")
    return json.loads(r.stdout)


def backup_users_json(container: str, ts: str) -> str:
    """Copy /data/users.json out of the container into BACKUP_DIR."""
    os.makedirs(BACKUP_DIR, exist_ok=True)
    out_path = f"{BACKUP_DIR}/users-presync-{container}-{ts}.json"
    r = subprocess.run(
        ["docker", "exec", container, "cat", "/data/users.json"],
        capture_output=True, text=True, timeout=10,
    )
    if r.returncode != 0:
        raise SystemExit(f"FAIL: backup read on {container}: {r.stderr.strip()}")
    with open(out_path, "w") as f:
        f.write(r.stdout)
    return out_path


def post_key(host: str, port: int, admin_token: str, body: dict, timeout: int = 8) -> tuple[int, str]:
    """POST /v2/admin/keys with the given body. Returns (status, body_text)."""
    url = f"http://{host}:{port}/v2/admin/keys"
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Admin-Token": admin_token,
            "Authorization": f"Bearer {admin_token}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, f"transport_error: {e}"


def load_admin_token() -> str:
    """Try a few ordinary locations for the admin token."""
    if os.environ.get("ADMIN_TOKEN"):
        return os.environ["ADMIN_TOKEN"]
    for p in ("/etc/paramant/admin-token", "/opt/paramant-relay/.admin-token"):
        if os.path.isfile(p):
            with open(p) as f:
                return f.read().strip()
    raise SystemExit(
        "ADMIN_TOKEN not found. Set ADMIN_TOKEN env var or place the token in "
        "/etc/paramant/admin-token. The script needs it to POST /v2/admin/keys."
    )


def relay_for_sector(sector: str) -> tuple[str, str]:
    """Return (container_name, network_host) for a sector."""
    return f"{CONTAINER_PREFIX}{sector}", f"relay-{sector}"


def post_via_admin_container(sector: str, body: dict, admin_token: str) -> tuple[int, str]:
    """POST /v2/admin/keys from inside the admin container so we reuse relay-net.

    Uses busybox wget (present in the alpine-based admin image). The POST body
    is fed on stdin to avoid quoting issues. --server-response prints the HTTP
    status line, which we parse out.
    """
    host = f"relay-{sector}"
    payload = json.dumps(body)
    cmd = [
        "docker", "exec", "-i", "paramant-relay-admin",
        "sh", "-c",
        (
            f"wget -qO- --timeout=8 "
            f"--header='Content-Type: application/json' "
            f"--header='X-Admin-Token: {admin_token}' "
            f"--server-response "
            f"--post-data=\"$(cat)\" "
            f"http://{host}:{RELAY_PORT}/v2/admin/keys 2>&1 | head -200"
        ),
    ]
    r = subprocess.run(cmd, input=payload, capture_output=True, text=True, timeout=15)
    out = (r.stdout or "") + (r.stderr or "")
    status = 0
    for line in out.splitlines():
        s = line.strip()
        if s.startswith("HTTP/"):
            parts = s.split()
            if len(parts) >= 2 and parts[1].isdigit():
                status = int(parts[1])
    return status, out[-800:]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", default="health", choices=ALL_SECTORS,
                   help="sector to read keys FROM (default: health = canonical)")
    p.add_argument("--target", default="main", choices=ALL_SECTORS,
                   help="sector to write missing keys TO (default: main = the lagger)")
    p.add_argument("--apply", action="store_true",
                   help="actually write. Without this flag the script only prints what it WOULD do.")
    p.add_argument("--dry-run", action="store_true",
                   help="explicit dry-run flag (default behaviour without --apply)")
    p.add_argument("--orphan-adopt", action="store_true",
                   help="also POST target-only keys to the OTHER 4 sectors so they get adopted")
    p.add_argument("--include-inactive", action="store_true",
                   help="also sync keys where active === false (default: skip them)")
    args = p.parse_args()

    if args.source == args.target:
        sys.exit("--source and --target must differ")

    apply_mode = args.apply and not args.dry_run
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")

    src_container, _ = relay_for_sector(args.source)
    tgt_container, _ = relay_for_sector(args.target)

    print(f"[sync] source={args.source} target={args.target} mode={'APPLY' if apply_mode else 'DRY-RUN'}")
    src = read_users_json(src_container)
    tgt = read_users_json(tgt_container)

    def active(k):
        return k.get("active") is not False
    src_keys = {k["key"]: k for k in src.get("api_keys", []) if (args.include_inactive or active(k))}
    tgt_keys = {k["key"]: k for k in tgt.get("api_keys", []) if (args.include_inactive or active(k))}

    # delta-A: in source, not in target (these need to flow source -> target)
    flow_in = [src_keys[k] for k in src_keys if k not in tgt_keys]
    # delta-B: in target, not in source (orphans on target)
    orphans = [tgt_keys[k] for k in tgt_keys if k not in src_keys]

    print()
    print(f"[summary] {args.source} has {len(src_keys)} active keys; {args.target} has {len(tgt_keys)}.")
    print(f"[summary] keys to push {args.source} -> {args.target}: {len(flow_in)}")
    print(f"[summary] orphans currently only on {args.target} (target-only):  {len(orphans)}")
    print()

    if orphans:
        print(f"--- {args.target}-only orphans (inspect before --orphan-adopt) ---")
        for k in orphans:
            email = k.get("email") or "(no email)"
            label = k.get("label") or ""
            created = k.get("created") or k.get("created_at") or ""
            key_head = (k.get("key") or "")[:16]
            print(f"  {key_head}...  email={email!r:32}  label={label!r:24}  created={created}")
        print()

    if not apply_mode:
        print("[dry-run] No writes performed. Re-run with --apply to commit.")
        if args.orphan_adopt:
            print(f"[dry-run] --orphan-adopt would also push {len(orphans)} key(s) to the OTHER 4 sectors.")
        return 0

    # ---- APPLY path ----
    admin_token = load_admin_token()

    print(f"[backup] backing up users.json of source + target to {BACKUP_DIR}/")
    print(f"  -> {backup_users_json(src_container, ts)}")
    print(f"  -> {backup_users_json(tgt_container, ts)}")
    if args.orphan_adopt:
        for s in ALL_SECTORS:
            if s == args.target:
                continue
            print(f"  -> {backup_users_json(f'{CONTAINER_PREFIX}{s}', ts)}")
    print()

    def push(sector, body):
        status, snippet = post_via_admin_container(sector, body, admin_token)
        return status, snippet

    # 1) flow source -> target
    print(f"[apply] pushing {len(flow_in)} keys: {args.source} -> {args.target}")
    counts = {"created": 0, "exists": 0, "error": 0}
    for k in flow_in:
        body = {
            "key": k["key"],
            "email": k.get("email"),
            "label": k.get("label") or None,
            "plan": k.get("plan") or "community",
            "active": True,
            "created": k.get("created") or k.get("created_at") or datetime.now(timezone.utc).isoformat(),
        }
        status, snippet = push(args.target, body)
        if status in (200, 201):
            counts["created"] += 1
            tag = "201"
        elif status == 409:
            counts["exists"] += 1
            tag = "409"
        else:
            counts["error"] += 1
            tag = f"ERR{status}"
        print(f"  [{tag}] {k['key'][:16]}... email={k.get('email','-')}")
    print(f"[apply] flow done: created={counts['created']}, exists={counts['exists']}, error={counts['error']}")
    print()

    # 2) orphan adopt
    if args.orphan_adopt and orphans:
        adopt_sectors = [s for s in ALL_SECTORS if s != args.target]
        print(f"[apply] adopting {len(orphans)} orphan(s) into: {adopt_sectors}")
        for k in orphans:
            body = {
                "key": k["key"],
                "email": k.get("email"),
                "label": k.get("label") or None,
                "plan": k.get("plan") or "community",
                "active": True,
                "created": k.get("created") or k.get("created_at") or datetime.now(timezone.utc).isoformat(),
            }
            for s in adopt_sectors:
                status, _ = push(s, body)
                tag = "201" if status in (200, 201) else "409" if status == 409 else f"ERR{status}"
                print(f"  [{tag}] {s}: {k['key'][:16]}... email={k.get('email','-')}")
        print(f"[apply] orphan adopt done")
    print()
    print("[done] Re-run with --dry-run to verify state.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
