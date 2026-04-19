#!/usr/bin/env python3
"""
paramant-benchmark — measure Ghost Pipe round-trip latency

Usage:
  paramant-benchmark --relay https://iot.paramant.app --key pgp_xxx --count 100 --size 4096
  paramant-benchmark --relay https://iot.paramant.app --key pgp_xxx --count 50 --size 65536
  paramant-benchmark --relay https://iot.paramant.app --key pgp_xxx --count 20 --size 1048576
"""
import argparse, base64, hashlib, json, os, secrets, struct, sys, time
import urllib.request, urllib.error

VERSION = "1.0.0"

def _pct(data, p):
    s = sorted(data)
    idx = max(0, min(len(s) - 1, int(len(s) * p / 100)))
    return s[idx]

def _fmt_size(n):
    if n >= 1024 * 1024: return f"{n // (1024*1024)} MB"
    if n >= 1024:        return f"{n // 1024} KB"
    return f"{n} B"

def _post(relay, key, h, payload_b64, ttl_ms):
    body = json.dumps({"hash": h, "payload": payload_b64, "ttl_ms": ttl_ms, "max_views": 1}).encode()
    req = urllib.request.Request(
        f"{relay}/v2/inbound", data=body, method="POST",
        headers={"X-Api-Key": key, "Content-Type": "application/json",
                 "Content-Length": str(len(body)), "User-Agent": f"paramant-benchmark/{VERSION}"}
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())

def _get(relay, key, h):
    req = urllib.request.Request(
        f"{relay}/v2/outbound/{h}",
        headers={"X-Api-Key": key, "User-Agent": f"paramant-benchmark/{VERSION}"}
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read()

def run(relay, key, count, size, quiet):
    payload = secrets.token_bytes(size)
    # pad to size with length prefix (relay accepts any blob size)
    blob = struct.pack(">I", size) + payload
    h = hashlib.sha256(blob).hexdigest()
    payload_b64 = base64.b64encode(blob).decode()
    ttl_ms = 60_000  # 60s — enough for the download leg

    inbound_ms, outbound_ms, total_ms = [], [], []
    errors = 0

    if not quiet:
        print(f"\nParamant Ghost Pipe latency benchmark")
        print(f"Relay:  {relay}")
        print(f"Size:   {size:,} bytes ({_fmt_size(size)})")
        print(f"Count:  {count} transfers\n")

    for i in range(count):
        # Fresh blob each iteration (burn-on-read requires unique hash)
        blob_i = struct.pack(">I", i) + payload
        h_i = hashlib.sha256(blob_i).hexdigest()
        b64_i = base64.b64encode(blob_i).decode()

        try:
            t0 = time.perf_counter()
            _post(relay, key, h_i, b64_i, ttl_ms)
            t1 = time.perf_counter()
            _get(relay, key, h_i)
            t2 = time.perf_counter()

            ib = (t1 - t0) * 1000
            ob = (t2 - t1) * 1000
            tt = (t2 - t0) * 1000
            inbound_ms.append(ib)
            outbound_ms.append(ob)
            total_ms.append(tt)
            if not quiet:
                print(f"  #{i+1:3d}: inbound {ib:5.0f}ms  outbound {ob:5.0f}ms  total {tt:5.0f}ms")
        except Exception as e:
            errors += 1
            if not quiet:
                print(f"  #{i+1:3d}: ERROR — {e}")

    if not total_ms:
        print("\nAll requests failed. Check relay URL and API key.")
        sys.exit(1)

    n = len(total_ms)
    elapsed_s = sum(total_ms) / 1000
    tpm = int(n / (elapsed_s / 60)) if elapsed_s > 0 else 0

    print(f"\nResults ({n} successful{f', {errors} errors' if errors else ''}):")
    print(f"  {'Metric':<12} {'Inbound':>10} {'Outbound':>10} {'Round-trip':>10}")
    print(f"  {'':-<12} {'':-<10} {'':-<10} {'':-<10}")
    for label, p in [("p50", 50), ("p95", 95), ("p99", 99)]:
        ib = _pct(inbound_ms, p)
        ob = _pct(outbound_ms, p)
        tt = _pct(total_ms, p)
        print(f"  {label:<12} {ib:>9.0f}ms {ob:>9.0f}ms {tt:>9.0f}ms")
    print(f"  {'min':<12} {min(inbound_ms):>9.0f}ms {min(outbound_ms):>9.0f}ms {min(total_ms):>9.0f}ms")
    print(f"  {'max':<12} {max(inbound_ms):>9.0f}ms {max(outbound_ms):>9.0f}ms {max(total_ms):>9.0f}ms")
    print(f"\nThroughput: ~{tpm} transfers/minute")
    print(f"Payload:    {_fmt_size(size)} per transfer\n")

    return {
        "relay": relay, "size": size, "count": n, "errors": errors,
        "p50": round(_pct(total_ms, 50)), "p95": round(_pct(total_ms, 95)),
        "p99": round(_pct(total_ms, 99)),
        "min": round(min(total_ms)), "max": round(max(total_ms)),
        "tpm": tpm,
    }

def main():
    p = argparse.ArgumentParser(description=f"PARAMANT benchmark v{VERSION}")
    p.add_argument("--relay", default="https://iot.paramant.app",
                   help="Relay URL (default: https://iot.paramant.app)")
    p.add_argument("--key",   required=True, help="API key (pgp_xxx or plk_xxx)")
    p.add_argument("--count", type=int, default=100,
                   help="Number of round-trips (default: 100)")
    p.add_argument("--size",  type=int, default=4096,
                   help="Payload size in bytes (default: 4096)")
    p.add_argument("--quiet", action="store_true",
                   help="Suppress per-request output, print summary only")
    args = p.parse_args()

    if args.size < 8:
        print("--size must be at least 8 bytes"); sys.exit(1)
    if args.count < 1:
        print("--count must be at least 1"); sys.exit(1)

    run(args.relay, args.key, args.count, args.size, args.quiet)

if __name__ == "__main__":
    main()
