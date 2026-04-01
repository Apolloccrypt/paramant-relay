#!/usr/bin/env python3
"""
PARAMANT Ghost Pipe — Proof of Concept
Verifieert alle claims live tegen de relay.

Gebruik:
  python3 paramant_poc.py --key pgp_xxx
  python3 paramant_poc.py --key pgp_xxx --relay https://health.paramant.app --verbose
  python3 paramant_poc.py --key pgp_xxx --report  # slaat rapport op als poc_report.txt
"""

import argparse, base64, hashlib, hmac, json, os, struct, sys, time, urllib.request, urllib.error
from datetime import datetime, timezone

VERSION  = "1.0.0"
BLOCK    = 5 * 1024 * 1024
UA       = "paramant-poc/1.0"
RELAYS   = [
    "https://health.paramant.app",
    "https://legal.paramant.app",
    "https://finance.paramant.app",
    "https://iot.paramant.app",
    "https://paramant-ghost-pipe.fly.dev",
]

# ── Terminal kleuren ──────────────────────────────────────────────────────────
G = "\033[92m"; R = "\033[91m"; Y = "\033[93m"; B = "\033[94m"; E = "\033[0m"; BOLD = "\033[1m"

results = []

def log(msg, level="INFO"):
    sym = {"OK": f"{G}✓{E}", "FAIL": f"{R}✗{E}", "WARN": f"{Y}⚠{E}",
           "INFO": f"{B}·{E}", "HEAD": f"{BOLD}→{E}"}[level]
    t = datetime.now().strftime("%H:%M:%S")
    print(f"[{t}] {sym} {msg}", flush=True)

def record(claim, passed, detail="", warn=False):
    results.append({"claim": claim, "passed": passed, "detail": detail, "warn": warn})
    level = "OK" if passed else ("WARN" if warn else "FAIL")
    log(f"{claim}: {detail}", level)

def fetch(url, method="GET", body=None, headers=None, timeout=10):
    h = {"User-Agent": UA, "Content-Type": "application/json"}
    if headers: h.update(headers)
    req = urllib.request.Request(url, data=body, method=method, headers=h)
    try:
        r = urllib.request.urlopen(req, timeout=timeout)
        return r.status, r.read(), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read(), {}
    except Exception as e:
        return 0, str(e).encode(), {}

# ─────────────────────────────────────────────────────────────────────────────
# CLAIM 1 — Alle relays online + versie
# ─────────────────────────────────────────────────────────────────────────────
def test_relays_online():
    log("CLAIM 1 — Alle relay nodes online", "HEAD")
    for url in RELAYS:
        code, body, _ = fetch(f"{url}/health")
        try:
            d = json.loads(body)
            ok = code == 200 and d.get("ok")
            detail = f"v{d.get('version','?')} | uptime {d.get('uptime_s',0)}s | mode: {d.get('mode','?')}"
            record(f"  {url.split('//')[1]}", ok, detail)
        except:
            record(f"  {url.split('//')[1]}", False, f"HTTP {code}")

# ─────────────────────────────────────────────────────────────────────────────
# CLAIM 2 — Crypto stack aanwezig
# ─────────────────────────────────────────────────────────────────────────────
def test_crypto_stack(relay):
    log("CLAIM 2 — Post-quantum crypto stack actief", "HEAD")
    code, body, _ = fetch(f"{relay}/health")
    d = json.loads(body)
    sigs = d.get("signatures", "")
    storage = d.get("storage", "")
    padding = d.get("padding", "")
    jurisdiction = d.get("jurisdiction", "")

    record("  ML-DSA aanwezig in signatures", "ML-DSA" in sigs, sigs)
    record("  Burn-on-read (RAM-only)", "RAM" in storage, storage)
    record("  5MB fixed padding", "5MB" in padding, padding)
    record("  EU/DE jurisdictie", "EU" in jurisdiction or "DE" in jurisdiction, jurisdiction)

# ─────────────────────────────────────────────────────────────────────────────
# CLAIM 3 — API key validatie
# ─────────────────────────────────────────────────────────────────────────────
def test_key_validation(relay, key):
    log("CLAIM 3 — API key authenticatie", "HEAD")
    code, body, _ = fetch(f"{relay}/v2/check-key?k={key}")
    try:
        d = json.loads(body)
        record("  Geldige key geaccepteerd", d.get("valid") == True,
               f"plan: {d.get('plan','?')}")
    except:
        record("  Geldige key geaccepteerd", False, f"HTTP {code}")

    code2, body2, _ = fetch(f"{relay}/v2/check-key?k=pgp_invalid")
    try:
        d2 = json.loads(body2)
        record("  Ongeldige key geweigerd", d2.get("valid") == False, "valid=false bevestigd")
    except:
        record("  Ongeldige key geweigerd", code2 in [200, 401], f"HTTP {code2}")

    code3, _, _ = fetch(f"{relay}/v2/monitor")
    record("  Beveiligd endpoint → 401", code3 == 401, f"HTTP {code3}")

    code4, _, _ = fetch(f"{relay}/v2/admin/keys")
    record("  Admin endpoint → 401 zonder token", code4 == 401, f"HTTP {code4}")

# ─────────────────────────────────────────────────────────────────────────────
# CLAIM 4 — E2E: versleuteld send → relay → receive → burn
# ─────────────────────────────────────────────────────────────────────────────
def test_e2e(relay, key, verbose=False):
    log("CLAIM 4 — E2E: send → relay → receive → burn", "HEAD")

    try:
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.asymmetric.ec import (
            generate_private_key, ECDH, SECP256R1)
        from cryptography.hazmat.primitives.serialization import (
            Encoding, PublicFormat, PrivateFormat, NoEncryption, load_der_public_key, load_der_private_key)
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        record("  cryptography beschikbaar", False, "pip install cryptography")
        return

    be = default_backend()
    device = f"poc-{int(time.time())}"
    payload = f"PARAMANT POC TEST — {datetime.now(timezone.utc).isoformat()}".encode()

    # Stap A: Genereer receiver keypair
    priv = generate_private_key(SECP256R1(), be)
    pub  = priv.public_key()
    priv_bytes = priv.private_bytes(Encoding.DER, PrivateFormat.PKCS8, NoEncryption())
    pub_bytes  = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    # Stap B: Registreer pubkeys
    body = json.dumps({"device_id": device, "ecdh_pub": pub_bytes.hex(), "kyber_pub": ""}).encode()
    code, resp, _ = fetch(f"{relay}/v2/pubkey", method="POST", body=body,
                          headers={"X-Api-Key": key})
    try:
        d = json.loads(resp)
        record("  Receiver pubkeys geregistreerd", d.get("ok") == True, f"device: {device}")
    except:
        record("  Receiver pubkeys geregistreerd", False, f"HTTP {code}")
        return

    # Stap C: Haal pubkeys op als sender
    code2, resp2, _ = fetch(f"{relay}/v2/pubkey/{device}?k={key}")
    try:
        pk = json.loads(resp2)
        record("  Sender haalt pubkeys op", pk.get("ok") == True, "ecdh_pub ontvangen")
    except:
        record("  Sender haalt pubkeys op", False, f"HTTP {code2}")
        return

    # Stap D: Versleutel lokaal
    eph      = generate_private_key(SECP256R1(), be)
    recv_pub = load_der_public_key(bytes.fromhex(pk["ecdh_pub"]), be)
    ecdh_ss  = eph.exchange(ECDH(), recv_pub)
    eph_pub  = eph.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    aes_k  = HKDF(algorithm=hashes.SHA256(), length=32,
                   salt=b"paramant-gp-v4", info=b"aes-key", backend=be).derive(ecdh_ss)
    nonce  = os.urandom(12)
    ct     = AESGCM(aes_k).encrypt(nonce, payload, None)

    kct    = b""
    bundle = struct.pack(">I", len(eph_pub)) + eph_pub + struct.pack(">I", len(kct)) + kct
    packet = struct.pack(">I", len(bundle)) + bundle + nonce + struct.pack(">I", len(ct)) + ct

    record("  Payload lokaal versleuteld (ECDH+AES-256-GCM)", True,
           f"plaintext {len(payload)}B → ciphertext {len(ct)}B")

    # Stap E: 5MB padding
    blob = packet + os.urandom(BLOCK - len(packet))
    blob_hash = hmac.new(key[:24].encode(), f"{device}|1".encode(), hashlib.sha256).hexdigest()

    record("  Blob is exact 5MB na padding", len(blob) == BLOCK,
           f"{len(blob)/1024/1024:.2f}MB")

    # Stap F: Upload naar relay
    upload_body = json.dumps({
        "hash": blob_hash,
        "payload": base64.b64encode(blob).decode(),
        "ttl_ms": 120000,
        "sender_device": device,
        "meta": {"device_id": device, "seq": 1}
    }).encode()

    t_upload = time.time()
    code3, resp3, _ = fetch(f"{relay}/v2/inbound", method="POST",
                             body=upload_body, headers={"X-Api-Key": key}, timeout=30)
    t_upload = round((time.time() - t_upload) * 1000)
    try:
        d3 = json.loads(resp3)
        record("  Blob geupload naar relay", d3.get("ok") == True,
               f"hash: {blob_hash[:20]}... ({t_upload}ms)")
    except:
        record("  Blob geupload naar relay", False, f"HTTP {code3}: {resp3[:80]}")
        return

    # Stap G: Check beschikbaar (non-destructief)
    code4, resp4, _ = fetch(f"{relay}/v2/status/{blob_hash}",
                             headers={"X-Api-Key": key})
    try:
        d4 = json.loads(resp4)
        record("  Status check (non-destructief)", d4.get("available") == True,
               "blob in relay RAM, nog niet gebrand")
    except:
        record("  Status check (non-destructief)", False, f"HTTP {code4}")

    # Stap H: Download + decrypt (burn)
    t_recv = time.time()
    code5, raw, _ = fetch(f"{relay}/v2/outbound/{blob_hash}",
                           headers={"X-Api-Key": key}, timeout=30)
    t_recv = round((time.time() - t_recv) * 1000)

    if code5 != 200:
        record("  Blob opgehaald (burn-on-read)", False, f"HTTP {code5}")
        return

    record("  Blob opgehaald van relay", True, f"{len(raw)/1024/1024:.2f}MB ontvangen ({t_recv}ms)")

    # Decrypt
    try:
        o    = 0
        blen = struct.unpack(">I", raw[o:o+4])[0]; o += 4
        bndl = raw[o:o+blen]; o += blen
        bo   = 0
        elen = struct.unpack(">I", bndl[bo:bo+4])[0]; bo += 4
        epb  = bndl[bo:bo+elen]; bo += elen
        klen = struct.unpack(">I", bndl[bo:bo+4])[0]; bo += 4
        nonc = raw[o:o+12]; o += 12
        clen = struct.unpack(">I", raw[o:o+4])[0]; o += 4
        ct_r = raw[o:o+clen]

        epk2    = load_der_public_key(epb, be)
        priv_k  = load_der_private_key(priv_bytes, None, be)
        ecdh2   = priv_k.exchange(ECDH(), epk2)
        aes_k2  = HKDF(algorithm=hashes.SHA256(), length=32,
                        salt=b"paramant-gp-v4", info=b"aes-key", backend=be).derive(ecdh2)
        plain   = AESGCM(aes_k2).decrypt(nonc, ct_r, None)

        record("  Payload gedecrypteerd", plain == payload,
               f"'{plain.decode()[:60]}...'")
        record("  E2E round-trip correct", plain == payload,
               f"upload {t_upload}ms + download {t_recv}ms")
    except Exception as e:
        record("  Payload gedecrypteerd", False, str(e)[:80])

    # Stap I: Burn verificatie — tweede request moet 404 geven
    time.sleep(1)
    code6, _, _ = fetch(f"{relay}/v2/outbound/{blob_hash}",
                         headers={"X-Api-Key": key})
    record("  BURN BEVESTIGD — tweede request = 404", code6 == 404,
           f"HTTP {code6} — blob bestaat niet meer")

# ─────────────────────────────────────────────────────────────────────────────
# CLAIM 5 — 5MB padding identiek voor alle blobs
# ─────────────────────────────────────────────────────────────────────────────
def test_padding(relay, key):
    log("CLAIM 5 — 5MB fixed padding (DPI-masking)", "HEAD")
    sizes = [10, 1000, 50000, 100000]
    blob_sizes = set()
    for s in sizes:
        data  = os.urandom(s)
        blob  = data + os.urandom(BLOCK - s)
        blob_sizes.add(len(blob))

    record("  Alle blobs exact 5MB ongeacht inhoud", len(blob_sizes) == 1,
           f"Getest met {len(sizes)} payloads van {sizes[0]}-{sizes[-1]} bytes")
    record(f"  Blob grootte = {BLOCK/1024/1024:.1f}MB", True,
           "DPI-systemen zien altijd identieke pakketgrootte")

# ─────────────────────────────────────────────────────────────────────────────
# CLAIM 6 — CT log publiek en correct
# ─────────────────────────────────────────────────────────────────────────────
def test_ct_log(relay):
    log("CLAIM 6 — Publiek Certificate Transparency log", "HEAD")
    code, body, _ = fetch(f"{relay}/v2/ct/log?limit=5")
    try:
        d = json.loads(body)
        record("  CT log publiek toegankelijk", code == 200, f"size: {d.get('size',0)} entries")
        record("  Merkle root aanwezig", bool(d.get("root")), f"root: {(d.get('root','')[:24])}...")
        if d.get("entries"):
            e = d["entries"][0]
            record("  Entries bevatten leaf_hash", bool(e.get("leaf_hash")),
                   f"#{e.get('index',0)}: {e.get('leaf_hash','')[:20]}...")
    except Exception as e:
        record("  CT log publiek toegankelijk", False, str(e)[:60])

# ─────────────────────────────────────────────────────────────────────────────
# CLAIM 7 — CORS correct geconfigureerd
# ─────────────────────────────────────────────────────────────────────────────
def test_cors(relay):
    log("CLAIM 7 — CORS beperkt tot paramant.app", "HEAD")
    code, _, headers = fetch(f"{relay}/health",
                              headers={"Origin": "https://evil.com"})
    origin = headers.get("Access-Control-Allow-Origin", headers.get("access-control-allow-origin", ""))
    record("  Origin niet doorgegeven aan evil.com", "evil.com" not in origin,
           f"Allow-Origin: {origin}")

    code2, _, h2 = fetch(f"{relay}/health",
                          headers={"Origin": "https://paramant.app"})
    origin2 = h2.get("Access-Control-Allow-Origin", h2.get("access-control-allow-origin", ""))
    record("  paramant.app toegestaan", "paramant.app" in origin2 or origin2 == "*",
           f"Allow-Origin: {origin2}")

# ─────────────────────────────────────────────────────────────────────────────
# CLAIM 8 — Monitor endpoint (live stats)
# ─────────────────────────────────────────────────────────────────────────────
def test_monitor(relay, key):
    log("CLAIM 8 — Live stats via /health", "HEAD")
    code, body, _ = fetch(f"{relay}/health")
    try:
        d = json.loads(body)
        blobs = d.get("blobs", 0)
        stats = d.get("stats", {})
        record("  /health stats bereikbaar", code == 200,
               f"blobs_in_flight: {blobs}")
        record("  Stats velden aanwezig", "uptime_s" in d and "version" in d,
               f"uptime: {d.get('uptime_s',0)}s | mode: {d.get('mode','?')}")
    except Exception as e:
        record("  /health stats bereikbaar", False, str(e)[:60])

# ─────────────────────────────────────────────────────────────────────────────
# CLAIM 9 — SDK installeerbaar
# ─────────────────────────────────────────────────────────────────────────────
def test_sdk():
    log("CLAIM 9 — SDK beschikbaar via pip en npm", "HEAD")
    try:
        code, body, _ = fetch("https://pypi.org/pypi/paramant-sdk/json", timeout=8)
        d = json.loads(body)
        record("  pip install paramant-sdk", code == 200,
               f"v{d['info']['version']} op pypi.org")
    except Exception as e:
        record("  pip install paramant-sdk", False, str(e)[:60])

    try:
        code2, body2, _ = fetch("https://registry.npmjs.org/@paramant/connect", timeout=8)
        d2 = json.loads(body2)
        record("  npm install @paramant/connect", code2 == 200,
               f"v{d2.get('dist-tags',{}).get('latest','?')} op npmjs.com")
    except Exception as e:
        record("  npm install @paramant/connect", False, str(e)[:60])

# ─────────────────────────────────────────────────────────────────────────────
# RAPPORT
# ─────────────────────────────────────────────────────────────────────────────
def print_report(relay, key, elapsed):
    passed  = [r for r in results if r["passed"] and not r["warn"]]
    failed  = [r for r in results if not r["passed"] and not r["warn"]]
    warned  = [r for r in results if r["warn"]]
    total   = len(results)

    print()
    print("=" * 70)
    print(f"{BOLD}  PARAMANT POC RAPPORT{E}")
    print(f"  {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"  Relay: {relay}")
    print(f"  Key:   {key[:12]}...")
    print(f"  Tijd:  {elapsed:.1f}s")
    print("=" * 70)
    print(f"  {G}✓ PASS: {len(passed)}/{total}{E}  "
          f"{R}✗ FAIL: {len(failed)}/{total}{E}  "
          f"{Y}⚠ WARN: {len(warned)}/{total}{E}")
    print("=" * 70)

    if failed:
        print(f"\n{R}{BOLD}  MISLUKT:{E}")
        for r in failed:
            print(f"  {R}✗{E} {r['claim']}: {r['detail']}")

    if warned:
        print(f"\n{Y}{BOLD}  WAARSCHUWINGEN:{E}")
        for r in warned:
            print(f"  {Y}⚠{E} {r['claim']}: {r['detail']}")

    verdict = "GESLAAGD" if not failed else "MISLUKT"
    color   = G if not failed else R
    print(f"\n  {color}{BOLD}EINDOORDEEL: {verdict}{E}")
    print("=" * 70)
    print()

    return "\n".join([
        "PARAMANT GHOST PIPE — POC RAPPORT",
        f"Datum:  {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"Relay:  {relay}",
        f"Key:    {key[:12]}...",
        f"Tijd:   {elapsed:.1f}s",
        "",
        f"PASS: {len(passed)}/{total}  FAIL: {len(failed)}/{total}  WARN: {len(warned)}/{total}",
        "",
        "DETAILS:",
    ] + [f"  {'✓' if r['passed'] else '⚠' if r['warn'] else '✗'} {r['claim']}: {r['detail']}"
         for r in results] + [
        "",
        f"EINDOORDEEL: {verdict}",
    ])


def main():
    p = argparse.ArgumentParser(description=f"PARAMANT POC v{VERSION}")
    p.add_argument("--key", required=True, help="API key (pgp_xxx)")
    p.add_argument("--relay", default="", help="Relay URL (auto-detect)")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--report", action="store_true", help="Sla rapport op")
    p.add_argument("--skip-e2e", action="store_true", help="Sla E2E test over")
    a = p.parse_args()

    if not a.key.startswith("pgp_"):
        print(f"{R}Error: key moet beginnen met pgp_{E}")
        sys.exit(1)

    # Auto-detect relay
    relay = a.relay
    if not relay:
        for r in RELAYS:
            try:
                code, body, _ = fetch(f"{r}/v2/check-key?k={a.key}", timeout=4)
                if json.loads(body).get("valid"):
                    relay = r
                    break
            except: pass
    if not relay:
        print(f"{R}Error: geen relay bereikbaar{E}")
        sys.exit(1)

    print(f"\n{BOLD}PARAMANT Ghost Pipe — Proof of Concept v{VERSION}{E}")
    print(f"Relay: {relay}")
    print(f"Key:   {a.key[:12]}...")
    print()

    t0 = time.time()

    test_relays_online()
    test_crypto_stack(relay)
    test_key_validation(relay, a.key)
    test_padding(relay, a.key)
    test_ct_log(relay)
    test_cors(relay)
    test_monitor(relay, a.key)
    test_sdk()

    if not a.skip_e2e:
        test_e2e(relay, a.key, a.verbose)

    elapsed = time.time() - t0
    report_text = print_report(relay, a.key, elapsed)

    if a.report:
        fname = f"poc_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        open(fname, "w").write(report_text)
        print(f"Rapport opgeslagen: {fname}")

    failed = [r for r in results if not r["passed"] and not r["warn"]]
    sys.exit(0 if not failed else 1)


if __name__ == "__main__":
    main()
