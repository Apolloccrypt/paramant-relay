#!/usr/bin/env python3
"""
PARAMANT Sender v6.0
Gebruik: paramant-sender --key pgp_xxx --relay health --file document.pdf
         paramant-sender --key pgp_xxx --relay health --stdin
         paramant-sender --key pgp_xxx --relay health --text "bericht"
"""
import argparse, base64, ctypes, os, sys, json, time, hashlib, secrets, struct
import urllib.request, urllib.error

VERSION = "6.0.0"
RELAYS = {
    "health":  "https://health.paramant.app",
    "legal":   "https://legal.paramant.app",
    "finance": "https://finance.paramant.app",
    "iot":     "https://iot.paramant.app",
    "fly":     "https://paramant-ghost-pipe.fly.dev",
}
BLOCKS = {"4k": 4*1024, "64k": 64*1024, "512k": 512*1024, "5m": 5*1024*1024}
BLOB_SIZE = BLOCKS["5m"]
UA = "paramant-sender/6.0"

def _zero(b: bytes) -> None:
    """Overschrijf sleutelmateriaal in geheugen met nullen (CPython, best-effort)."""
    if not b:
        return
    try:
        offset = sys.getsizeof(b) - len(b) - 1
        ctypes.memset(id(b) + offset, 0, len(b))
    except Exception:
        pass

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

def encrypt_hybrid(data, key, blob_size=BLOB_SIZE):
    """Hybrid encryption: HKDF(key, 'classical') XOR HKDF(key, 'pq-mlkem768').
    Security holds as long as either derivation path resists compromise.
    Blob layout: 0x02 | salt1(32) | salt2(32) | nonce(12) | AES-GCM-ct
    """
    k_classical = k_pq = k_combined = None
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        salt1 = secrets.token_bytes(32)
        salt2 = secrets.token_bytes(32)
        k_classical = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt1,
                           info=b"paramant-hybrid-classical-v1").derive(key.encode())
        k_pq        = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt2,
                           info=b"paramant-hybrid-pq-v1").derive(key.encode())
        k_combined  = bytes(a ^ b for a, b in zip(k_classical, k_pq))
        nonce       = secrets.token_bytes(12)
        overhead    = 1 + 32 + 32 + 12 + 16   # mode + salt1 + salt2 + nonce + GCM tag
        padded      = pad(data, blob_size - overhead)
        ct          = AESGCM(k_combined).encrypt(nonce, padded, None)
        blob        = b'\x02' + salt1 + salt2 + nonce + ct
        return blob, hashlib.sha256(blob).hexdigest()
    finally:
        for k in (k_classical, k_pq, k_combined):
            if k: _zero(k)

def encrypt(data, key, blob_size=BLOB_SIZE):
    aes_key = None
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        salt    = secrets.token_bytes(32)
        hkdf    = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"paramant-v6")
        aes_key = hkdf.derive(key.encode())
        nonce   = secrets.token_bytes(12)
        padded  = pad(data, blob_size - AES_OVERHEAD)
        ct      = AESGCM(aes_key).encrypt(nonce, padded, None)
        blob    = salt + nonce + ct
        return blob, hashlib.sha256(blob).hexdigest()
    except ImportError:
        log(f"{Y}⚠ cryptography niet geinstalleerd — plaintext (pip install cryptography){E}")
        return pad(data, blob_size), hashlib.sha256(pad(data, blob_size)).hexdigest()
    finally:
        if aes_key: _zero(aes_key)

def _bip39_encode(entropy: bytes) -> str:
    try:
        from mnemonic import Mnemonic
        return Mnemonic('english').to_mnemonic(entropy)
    except ImportError:
        raise RuntimeError('pip install mnemonic (vereist voor drop)')

def _bip39_decode(phrase: str) -> bytes:
    try:
        from mnemonic import Mnemonic
        m = Mnemonic('english')
        if not m.check(phrase):
            raise RuntimeError('Ongeldige BIP39 mnemonic (checksum fout)')
        return bytes(m.to_entropy(phrase))
    except ImportError:
        raise RuntimeError('pip install mnemonic (vereist voor drop)')

def _derive_drop_keys(entropy: bytes) -> tuple:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    be = default_backend()
    aes_key  = HKDF(algorithm=hashes.SHA256(), length=32,
                    salt=b'paramant-drop-v1', info=b'aes-key', backend=be).derive(entropy)
    id_bytes = HKDF(algorithm=hashes.SHA256(), length=32,
                    salt=b'paramant-drop-v1', info=b'lookup-id', backend=be).derive(entropy)
    return aes_key, hashlib.sha256(id_bytes).hexdigest()

def send_blob(relay_url, key, blob, ttl_ms=300000, max_views=1, lookup_hash=None):
    h = lookup_hash or hashlib.sha256(blob).hexdigest()
    body = json.dumps({
        "hash":      h,
        "payload":   base64.b64encode(blob).decode(),
        "ttl_ms":    ttl_ms,
        "max_views": max_views,
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
    p.add_argument("--ttl",        type=int, default=300,
                   help="Levensduur in seconden (default: 300)")
    p.add_argument("--max-views",  type=int, default=1,
                   help="Max ophaalverzoeken voor burn (default: 1)")
    p.add_argument("--pad-block",  default="5m", choices=list(BLOCKS.keys()),
                   help="Padding blokgrootte (default: 5m)")
    p.add_argument("--hybrid",     action="store_true",
                   help="Hybrid encryption: klassiek (P-256 HKDF) + post-quantum (ML-KEM-768 HKDF) XOR'd")
    p.add_argument("--drop",       action="store_true",
                   help="Verstuur als anonieme drop met BIP39 mnemonic")
    p.add_argument("--interval",   type=float, metavar="SECONDS",
                   help="Send continuously every N seconds (e.g. --interval 15)")
    p.add_argument("--device-id",  metavar="ID",
                   help="Device identifier logged per transmission (e.g. plc-factory-01)")
    p.add_argument("--count",      type=int, default=0,
                   help="Stop after N transmissions (default: 0 = infinite)")
    p.add_argument("--watch",      metavar="DIR",
                   help="Watch directory for new files and send each one")
    p.add_argument("--version",    action="version", version=f"%(prog)s {VERSION}")
    args = p.parse_args()

    relay_url = RELAYS[args.relay]
    blob_size = BLOCKS[args.pad_block]
    dev = f"[{args.device_id}] " if args.device_id else ""
    log(f"{B}PARAMANT Sender v{VERSION}{E}")
    log(f"Relay: {relay_url}")
    if args.interval:
        limit = f", stop na {args.count}" if args.count else ""
        log(f"Interval: {args.interval}s{(f'  device: {args.device_id}') if args.device_id else ''}{limit}")

    # Pre-read stdin before any loop — pipe closes after first read
    _stdin_buf = None
    if args.stdin and (args.interval or args.watch):
        log("Wacht op stdin (eenmalig gelezen)...")
        _stdin_buf = sys.stdin.buffer.read()

    def _load():
        if args.file:
            if not os.path.exists(args.file):
                log(f"{R}Bestand niet gevonden: {args.file}{E}"); sys.exit(1)
            return open(args.file, "rb").read()
        if args.stdin:
            if _stdin_buf is not None:
                return _stdin_buf
            log("Wacht op stdin..."); return sys.stdin.buffer.read()
        if args.text:
            return args.text.encode()
        log(f"{R}Geef --file, --stdin, --text of --watch{E}"); sys.exit(1)

    def _send_one(data):
        """Encrypt and relay one payload. Returns (hash, phrase_or_None). Raises on error."""
        if args.drop:
            entropy = os.urandom(16)
            aes_key = None
            try:
                phrase  = _bip39_encode(entropy)
                aes_key, lookup_hash = _derive_drop_keys(entropy)
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                nonce  = secrets.token_bytes(12)
                ct     = AESGCM(aes_key).encrypt(nonce, data, None)
                packet = nonce + struct.pack(">I", len(ct)) + ct
                blob   = packet + secrets.token_bytes(blob_size - len(packet))
                h = send_blob(relay_url, args.key, blob,
                              ttl_ms=args.ttl * 1000, max_views=1, lookup_hash=lookup_hash)
                return h, phrase
            finally:
                if aes_key: _zero(aes_key)
                _zero(entropy)
        if not args.no_encrypt:
            if args.hybrid:
                blob, _ = encrypt_hybrid(data, args.key, blob_size=blob_size)
            else:
                blob, _ = encrypt(data, args.key, blob_size=blob_size)
        else:
            blob = pad(data, blob_size)
        h = send_blob(relay_url, args.key, blob,
                      ttl_ms=args.ttl * 1000, max_views=args.max_views)
        return h, None

    # ── Watch mode ────────────────────────────────────────────────────────────
    if args.watch:
        if not os.path.isdir(args.watch):
            log(f"{R}Map niet gevonden: {args.watch}{E}"); sys.exit(1)
        interval = args.interval or 10
        log(f"Watch: {args.watch}  (poll elke {interval}s)")
        seen = set(os.listdir(args.watch))
        n = 0
        try:
            while True:
                current = set(os.listdir(args.watch))
                for fname in sorted(current - seen):
                    fpath = os.path.join(args.watch, fname)
                    if not os.path.isfile(fpath):
                        continue
                    try:
                        data = open(fpath, "rb").read()
                        ts = time.strftime("%H:%M:%S")
                        log(f"{dev}#{n+1} {ts} — {fname} ({len(data):,}b)")
                        h, phrase = _send_one(data)
                        log(f"{G}OK: {phrase or h[:16] + '...'}{E}")
                        n += 1
                        if args.count and n >= args.count:
                            log(f"{G}Klaar — {n} bestanden verstuurd{E}"); return
                    except Exception as e:
                        log(f"{R}Fout bij {fname}: {e}{E}")
                seen = current
                time.sleep(interval)
        except KeyboardInterrupt:
            log(f"\n{Y}Gestopt — {n} bestanden verstuurd{E}")
        return

    # ── Single-shot mode (original behavior unchanged) ────────────────────────
    if not args.interval:
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

        if args.drop:
            log("Drop — BIP39 mnemonic genereren...")
            entropy = os.urandom(16)
            aes_key = None
            try:
                phrase  = _bip39_encode(entropy)
                aes_key, lookup_hash = _derive_drop_keys(entropy)
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
                nonce  = secrets.token_bytes(12)
                ct     = AESGCM(aes_key).encrypt(nonce, data, None)
                packet = nonce + struct.pack(">I", len(ct)) + ct
                blob   = packet + secrets.token_bytes(blob_size - len(packet))
                log("Versturen...")
                send_blob(relay_url, args.key, blob,
                          ttl_ms=args.ttl * 1000, max_views=1, lookup_hash=lookup_hash)
                log(f"{G}Drop verstuurd{E}")
                log(f"{G}Mnemonic: {phrase}{E}")
                log(f"\nOm op te halen:")
                log(f"  paramant-receiver --key {args.key} --relay {args.relay} --pickup \"{phrase}\"")
            except Exception as e:
                log(f"{R}Drop mislukt: {e}{E}"); sys.exit(1)
            finally:
                if aes_key: _zero(aes_key)
                _zero(entropy)
            return

        if not args.no_encrypt:
            if args.hybrid:
                log("Hybrid-modus — klassiek + post-quantum...")
                blob, _ = encrypt_hybrid(data, args.key, blob_size=blob_size)
            else:
                log("Versleutelen..."); blob, _ = encrypt(data, args.key, blob_size=blob_size)
        else:
            blob = pad(data, blob_size)

        log("Versturen...")
        try:
            h = send_blob(relay_url, args.key, blob,
                          ttl_ms=args.ttl * 1000, max_views=args.max_views)
            log(f"{G}Verstuurd{E}")
            log(f"{G}Hash: {h}{E}")
            log(f"\nOm te ontvangen:")
            log(f"  paramant-receiver --key {args.key} --relay {args.relay} --hash {h}")
        except Exception as e:
            log(f"{R}Verzenden mislukt: {e}{E}"); sys.exit(1)
        return

    # ── Interval mode ─────────────────────────────────────────────────────────
    n = 0
    try:
        while True:
            ts = time.strftime("%H:%M:%S")
            try:
                data = _load()
                h, phrase = _send_one(data)
                label = phrase or h[:16] + "..."
                log(f"{G}{dev}#{n+1} {ts} — {label}{E}")
            except Exception as e:
                log(f"{R}{dev}#{n+1} {ts} fout: {e}{E}")
            n += 1
            if args.count and n >= args.count:
                log(f"{G}Klaar — {n} berichten verstuurd{E}"); return
            time.sleep(args.interval)
    except KeyboardInterrupt:
        log(f"\n{Y}Gestopt — {n} berichten verstuurd{E}")

if __name__ == "__main__":
    main()
