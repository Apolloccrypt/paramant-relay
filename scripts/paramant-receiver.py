#!/usr/bin/env python3
"""
PARAMANT Receiver v6.0
Gebruik: paramant-receiver --key pgp_xxx --relay health --hash <hash> --output /tmp/
         paramant-receiver --key pgp_xxx --relay health --listen --output /tmp/
"""
import argparse, ctypes, os, sys, json, time, hashlib, struct
import urllib.request, urllib.error

VERSION = "6.0.0"
RELAYS = {
    "health":  "https://health.paramant.app",
    "legal":   "https://legal.paramant.app",
    "finance": "https://finance.paramant.app",
    "iot":     "https://iot.paramant.app",
    "fly":     "https://paramant-ghost-pipe.fly.dev",
}
UA = "paramant-receiver/6.0"

G = "\033[92m"; Y = "\033[93m"; R = "\033[91m"; E = "\033[0m"; B = "\033[94m"

def log(msg, color=None):
    c = color or ""
    print(f"{c}{msg}{E}", flush=True)

def _zero(b: bytes) -> None:
    """Overschrijf sleutelmateriaal in geheugen met nullen (CPython, best-effort)."""
    if not b:
        return
    try:
        offset = sys.getsizeof(b) - len(b) - 1
        ctypes.memset(id(b) + offset, 0, len(b))
    except Exception:
        pass

def _bip39_decode(phrase: str) -> bytes:
    try:
        from mnemonic import Mnemonic
        m = Mnemonic('english')
        if not m.check(phrase):
            raise RuntimeError('Ongeldige BIP39 mnemonic (checksum fout)')
        return bytes(m.to_entropy(phrase))
    except ImportError:
        raise RuntimeError('pip install mnemonic (vereist voor pickup)')

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

def decrypt(blob, key):
    aes_key = None
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        salt, nonce, ct = blob[:32], blob[32:44], blob[44:]
        hkdf    = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"paramant-v6")
        aes_key = hkdf.derive(key.encode())
        return AESGCM(aes_key).decrypt(nonce, ct, None)
    except ImportError:
        return blob
    except Exception as e:
        log(f"{Y}Decrypt mislukt: {e} — raw data{E}"); return blob
    finally:
        if aes_key: _zero(aes_key)

def unpad(data):
    if len(data) < 4: return data
    try:
        size = struct.unpack(">I", data[:4])[0]
        return data[4:4+size]
    except:
        return data

def fetch_blob(relay_url, key, h):
    req = urllib.request.Request(
        f"{relay_url}/v2/outbound/{h}",
        headers={"X-Api-Key": key, "User-Agent": UA}
    )
    for attempt in range(1, 4):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code == 404: raise RuntimeError("Hash niet gevonden of al verbrand")
            if e.code == 403: raise RuntimeError("Geen toegang — verkeerde API key")
            if attempt == 3: raise RuntimeError(f"HTTP {e.code}")
            time.sleep(2 ** attempt)
        except Exception:
            if attempt == 3: raise
            time.sleep(2 ** attempt)

def send_ack(relay_url, key, h):
    try:
        req = urllib.request.Request(
            f"{relay_url}/v2/ack/{h}", data=b"", method="POST",
            headers={"X-Api-Key": key, "Content-Length": "0", "User-Agent": UA}
        )
        urllib.request.urlopen(req, timeout=10)
    except:
        pass

def save(data, output_dir, h):
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, f"received_{h[:8]}.bin")
    open(path, "wb").write(data)
    return path

def receive_one(relay_url, key, h, output, no_decrypt):
    log(f"Ophalen: {h[:16]}...")
    blob = fetch_blob(relay_url, key, h)
    log(f"{G}Ontvangen ({len(blob):,} bytes){E}")
    data = blob if no_decrypt else unpad(decrypt(blob, key))
    path = save(data, output, h)
    send_ack(relay_url, key, h)
    log(f"{G}Opgeslagen: {path}{E}")
    log(f"{G}ACK verstuurd — blob verbrand{E}")
    return path

def listen_mode(relay_url, key, output, no_decrypt, interval):
    log(f"{B}Listen mode — poll elke {interval}s (Ctrl+C om te stoppen){E}")
    seen = set()
    while True:
        try:
            req = urllib.request.Request(
                f"{relay_url}/v2/monitor",
                headers={"X-Api-Key": key, "User-Agent": UA}
            )
            with urllib.request.urlopen(req, timeout=10) as r:
                data = json.loads(r.read())
                for h in data.get("pending", []):
                    if h not in seen:
                        seen.add(h)
                        log(f"{Y}Nieuw blob: {h[:16]}...{E}")
                        try:
                            receive_one(relay_url, key, h, output, no_decrypt)
                        except Exception as e:
                            log(f"{R}Fout: {e}{E}")
        except KeyboardInterrupt:
            log("\nGestopt."); break
        except Exception as e:
            log(f"{Y}Monitor fout: {e}{E}")
        time.sleep(interval)

def pickup(relay_url, key, phrase, output):
    """Haal een anonieme drop op via 12-woord BIP39 mnemonic."""
    entropy = _bip39_decode(phrase.strip())
    aes_key = None
    try:
        aes_key, lookup_hash = _derive_drop_keys(entropy)
        log(f"Pickup ophalen...")
        req = urllib.request.Request(
            f"{relay_url}/v2/outbound/{lookup_hash}",
            headers={"X-Api-Key": key, "User-Agent": UA}
        )
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
        nonce  = raw[:12]
        ct_len = struct.unpack(">I", raw[12:16])[0]
        ct     = raw[16:16 + ct_len]
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        data = AESGCM(aes_key).decrypt(nonce, ct, None)
        path = save(data, output, lookup_hash)
        log(f"{G}Ontvangen ({len(data):,} bytes){E}")
        log(f"{G}Opgeslagen: {path}{E}")
        log(f"{G}Drop verbrand (burn-on-read){E}")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise RuntimeError("Drop niet gevonden. Verlopen, al opgehaald, of ongeldige mnemonic.")
        raise RuntimeError(f"HTTP {e.code}")
    finally:
        if aes_key: _zero(aes_key)
        _zero(entropy)

def main():
    p = argparse.ArgumentParser(description=f"PARAMANT Receiver v{VERSION}")
    p.add_argument("--key",        required=True)
    p.add_argument("--relay",      default="health", choices=list(RELAYS.keys()))
    p.add_argument("--hash",       help="Specifieke hash ophalen")
    p.add_argument("--pickup",     help='12-woord BIP39 mnemonic voor anonieme drop',
                   metavar="MNEMONIC")
    p.add_argument("--listen",     action="store_true")
    p.add_argument("--output",     default="./received")
    p.add_argument("--interval",   type=int, default=5)
    p.add_argument("--no-decrypt", action="store_true")
    p.add_argument("--version",    action="version", version=f"%(prog)s {VERSION}")
    args = p.parse_args()

    relay_url = RELAYS[args.relay]
    log(f"{B}PARAMANT Receiver v{VERSION}{E}")
    log(f"Relay: {relay_url}")

    if args.pickup:
        try:
            pickup(relay_url, args.key, args.pickup, args.output)
        except Exception as e:
            log(f"{R}{e}{E}"); sys.exit(1)
    elif args.hash:
        try:
            receive_one(relay_url, args.key, args.hash, args.output, args.no_decrypt)
        except Exception as e:
            log(f"{R}{e}{E}"); sys.exit(1)
    elif args.listen:
        listen_mode(relay_url, args.key, args.output, args.no_decrypt, args.interval)
    else:
        log(f"{R}Geef --hash, --pickup of --listen{E}"); sys.exit(1)

if __name__ == "__main__":
    main()
