#!/usr/bin/env python3
"""
PARAMANT Sender v6.0
Gebruik: paramant-sender --key pgp_xxx --relay health --file document.pdf
         paramant-sender --key pgp_xxx --relay health --stdin
         paramant-sender --key pgp_xxx --relay health --text "bericht"
"""
import argparse, base64, os, sys, json, time, hashlib, secrets, struct
import urllib.request, urllib.error

VERSION = "6.0.0"
RELAYS = {
    "health":  "https://health.paramant.app",
    "legal":   "https://legal.paramant.app",
    "finance": "https://finance.paramant.app",
    "iot":     "https://iot.paramant.app",
    "fly":     "https://paramant-ghost-pipe.fly.dev",
}
BLOB_SIZE = 5 * 1024 * 1024
UA = "paramant-sender/6.0"

G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"; E = "\033[0m"; B = "\033[94m"

def log(msg, color=None):
    c = color or ""
    print(f"{c}{msg}{E}", flush=True)

AES_OVERHEAD = 32 + 12 + 16  # salt + nonce + GCM tag

def pad(data, target=BLOB_SIZE):
    """Pad data to exactly `target` bytes: 4-byte BE length prefix + data + random padding."""
    max_data = target - 4
    if len(data) > max_data:
        raise ValueError(f"Data te groot: {len(data)} bytes (max {max_data})")
    return struct.pack(">I", len(data)) + data + secrets.token_bytes(max_data - len(data))

def encrypt(data, key):
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        salt = secrets.token_bytes(32)
        hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"paramant-v6")
        aes_key = hkdf.derive(key.encode())
        nonce = secrets.token_bytes(12)
        # Pad to BLOB_SIZE - AES_OVERHEAD so encrypted output is exactly BLOB_SIZE
        padded = pad(data, BLOB_SIZE - AES_OVERHEAD)
        ct = AESGCM(aes_key).encrypt(nonce, padded, None)
        blob = salt + nonce + ct  # 32 + 12 + (BLOB_SIZE-AES_OVERHEAD+16) = BLOB_SIZE
        return blob, hashlib.sha256(blob).hexdigest()
    except ImportError:
        log(f"{Y}⚠ cryptography niet geinstalleerd — plaintext (pip install cryptography){E}")
        return pad(data), hashlib.sha256(pad(data)).hexdigest()

def send_blob(relay_url, key, blob):
    h = hashlib.sha256(blob).hexdigest()
    body = json.dumps({
        "hash": h,
        "payload": base64.b64encode(blob).decode(),
        "ttl_ms": 300000,
    }).encode()
    req = urllib.request.Request(
        f"{relay_url}/v2/inbound", data=body, method="POST",
        headers={"X-Api-Key": key, "Content-Type": "application/json",
                 "Content-Length": str(len(body)), "User-Agent": UA}
    )
    for attempt in range(1, 4):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read()).get("hash", h)
        except urllib.error.HTTPError as e:
            body = e.read().decode()
            if attempt == 3:
                raise RuntimeError(f"HTTP {e.code}: {body}")
            log(f"{Y}Poging {attempt} mislukt ({e.code}) — retry...{E}")
            time.sleep(2 ** attempt)
        except Exception as ex:
            if attempt == 3: raise
            log(f"{Y}Poging {attempt} fout: {ex} — retry...{E}")
            time.sleep(2 ** attempt)

def main():
    p = argparse.ArgumentParser(description=f"PARAMANT Sender v{VERSION}")
    p.add_argument("--key",        required=True)
    p.add_argument("--relay",      default="health", choices=list(RELAYS.keys()))
    p.add_argument("--file",       help="Bestand om te sturen")
    p.add_argument("--stdin",      action="store_true")
    p.add_argument("--text",       help="Stuur tekst direct")
    p.add_argument("--no-encrypt", action="store_true")
    p.add_argument("--version",    action="version", version=f"%(prog)s {VERSION}")
    args = p.parse_args()

    relay_url = RELAYS[args.relay]
    log(f"{B}PARAMANT Sender v{VERSION}{E}")
    log(f"Relay: {relay_url}")

    if args.file:
        if not os.path.exists(args.file):
            log(f"{R}Bestand niet gevonden: {args.file}{E}"); sys.exit(1)
        data = open(args.file, "rb").read()
        log(f"Bestand: {args.file} ({len(data):,} bytes)")
    elif args.stdin:
        log("Wacht op stdin..."); data = sys.stdin.buffer.read()
    elif args.text:
        data = args.text.encode()
    else:
        log(f"{R}Geef --file, --stdin of --text{E}"); sys.exit(1)

    if not args.no_encrypt:
        log("Versleutelen..."); blob, _ = encrypt(data, args.key)
    else:
        blob = pad(data)

    log("Versturen...")
    try:
        h = send_blob(relay_url, args.key, blob)
        log(f"{G}Verstuurd{E}")
        log(f"{G}Hash: {h}{E}")
        log(f"\nOm te ontvangen:")
        log(f"  paramant-receiver --key {args.key} --relay {args.relay} --hash {h}")
    except Exception as e:
        log(f"{R}Verzenden mislukt: {e}{E}"); sys.exit(1)

if __name__ == "__main__":
    main()
