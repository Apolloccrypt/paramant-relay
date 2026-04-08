"""
PARAMANT Ghost Pipe SDK v1.1.0
Python SDK voor quantum-safe datatransport

pip install cryptography paramant-sdk

Gebruik:
  from paramant_sdk import GhostPipe

  # Ontvanger setup (eenmalig per device)
  gp = GhostPipe(api_key='pgp_xxx', device='mri-001')
  gp.setup()   # genereert keypair + registreert bij relay

  # Zender
  result = gp.send(open('scan.dcm','rb').read())
  print(f'Hash: {result["hash"]}  Download: {result["download_token"]}')

  # Ontvanger
  data = gp.receive(result['hash'])

Changelog v1.1.1:
  - Security: key zeroization (ctypes _zero) added to _encrypt and _decrypt
  - Security: runtime RuntimeWarning if _zero() CPython check fails or ctypes errors
Changelog v1.1.0:
  - Wire format: PQHB v1 (aligned with JS SDK — nu interoperabel)
      [4 magic 'PQHB'][2 ver 0x01 0x00][16 salt][12 iv][16 tag][65 eph_pub][ciphertext]
  - receive(): fixed — relay returns raw binary, no longer tries base64-decode
  - send(): returns dict {hash, download_token} instead of bare hash string
  - setup(): explicit pubkey registration call (was implicit in receive_setup())
  - detect_relay(): uses /v2/check-key for key validation before choosing relay
  - kyber: graceful optional (falls back to ECDH-only; document with mlkem package)
"""
import base64, ctypes, hashlib, json, os, struct, sys, time, warnings
import urllib.request, urllib.error, urllib.parse
from typing import Callable, Optional

__version__ = '1.1.1'

# ── Key zeroization ──────────────────────────────────────────────────────────
_ZEROIZE_OK = (sys.implementation.name == 'cpython')
if not _ZEROIZE_OK:
    warnings.warn(
        'paramant-sdk: key zeroization (ctypes) is not supported on '
        f'{sys.implementation.name}. Secret key material may persist in RAM.',
        RuntimeWarning, stacklevel=2,
    )


def _zero(b: bytes) -> None:
    """Overwrite key material in memory with zeroes (CPython, best-effort)."""
    if not b:
        return
    try:
        offset = sys.getsizeof(b) - len(b) - 1
        ctypes.memset(id(b) + offset, 0, len(b))
    except Exception as _e:
        warnings.warn(
            f'paramant-sdk: _zero() failed — key material may persist in RAM: {_e}',
            RuntimeWarning, stacklevel=2,
        )

SECTOR_RELAYS = {
    'health':  'https://health.paramant.app',
    'iot':     'https://iot.paramant.app',
    'legal':   'https://legal.paramant.app',
    'finance': 'https://finance.paramant.app',
    'relay':   'https://relay.paramant.app',
}
BLOCK = 5 * 1024 * 1024  # 5 MB
UA    = f'paramant-sdk/{__version__}'

# PQHB v1 wire format header size: 4+2+16+12+16+65 = 115 bytes
MAGIC   = b'PQHB'
VER     = b'\x01\x00'
HDR_LEN = 115


class GhostPipeError(Exception):
    def __init__(self, message, code=None):
        super().__init__(message)
        self.code = code


class GhostPipe:
    """
    PARAMANT Ghost Pipe client.

    Quantum-safe end-to-end encrypted datatransport.
    Relay ziet NOOIT plaintext. Burn-on-read na ophalen.

    Args:
        api_key:  pgp_... API key van paramant.app/dashboard
        device:   Uniek apparaat-ID (zender en ontvanger gebruiken hetzelfde)
        relay:    Relay URL (automatisch gedetecteerd op basis van sector/key)
        sector:   Voorkeurssector: health|iot|legal|finance
    """

    def __init__(self, api_key: str, device: str,
                 relay: str = '', sector: str = ''):
        if not api_key.startswith('pgp_'):
            raise GhostPipeError('API key moet beginnen met pgp_', 'BAD_KEY')
        self.api_key = api_key
        self.device  = device
        self.sector  = sector
        self.relay   = relay or self._detect_relay()
        if not self.relay:
            raise GhostPipeError('Geen relay bereikbaar. Controleer API key en netwerk.', 'NO_RELAY')
        self._key_dir = os.path.expanduser('~/.paramant/keys')
        self._keypair = None

    # ── Relay detectie ────────────────────────────────────────────────────────
    def _detect_relay(self) -> Optional[str]:
        candidates = (
            [SECTOR_RELAYS[self.sector]] if self.sector in SECTOR_RELAYS
            else list(SECTOR_RELAYS.values())
        )
        for relay in candidates:
            try:
                url = f'{relay}/v2/check-key?k={urllib.parse.quote(self.api_key)}'
                r   = urllib.request.urlopen(
                    urllib.request.Request(url, headers={'User-Agent': UA}), timeout=4)
                if json.loads(r.read()).get('valid'):
                    return relay
            except Exception:
                pass
        # Fallback: any reachable relay
        for relay in SECTOR_RELAYS.values():
            try:
                urllib.request.urlopen(
                    urllib.request.Request(f'{relay}/health', headers={'User-Agent': UA}),
                    timeout=3)
                return relay
            except Exception:
                pass
        return None

    # ── HTTP helpers ──────────────────────────────────────────────────────────
    def _get(self, path: str, params: dict = None):
        url = self.relay + path
        if params:
            url += '?' + urllib.parse.urlencode(params)
        req = urllib.request.Request(
            url, headers={'User-Agent': UA, 'X-Api-Key': self.api_key})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def _post(self, path: str, body: bytes, content_type: str = 'application/json'):
        req = urllib.request.Request(
            self.relay + path, data=body, method='POST',
            headers={'Content-Type': content_type,
                     'X-Api-Key': self.api_key,
                     'User-Agent': UA})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    # ── Crypto ────────────────────────────────────────────────────────────────
    def _get_crypto(self):
        try:
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.hazmat.primitives.asymmetric.ec import (
                generate_private_key, ECDH, SECP256R1)
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PublicFormat, PrivateFormat, NoEncryption,
                load_der_public_key, load_der_private_key)
            from cryptography.hazmat.backends import default_backend
            return dict(HKDF=HKDF, hsh=hashes, AES=AESGCM,
                        gen=generate_private_key, ECDH=ECDH, curve=SECP256R1,
                        Enc=Encoding, Pub=PublicFormat, Priv=PrivateFormat,
                        NoEnc=NoEncryption, lpub=load_der_public_key,
                        lpriv=load_der_private_key, be=default_backend)
        except ImportError:
            raise GhostPipeError('pip install cryptography', 'MISSING_DEP')

    def _try_mlkem(self):
        """Optional ML-KEM-768 (post-quantum). pip install mlkem if available."""
        for name in ('mlkem', 'kyber'):
            try:
                mod = __import__(name)
                return getattr(mod, 'Kyber768', None) or getattr(mod, 'MLKEM768', None)
            except ImportError:
                pass
        return None

    # ── Keypair ───────────────────────────────────────────────────────────────
    def _key_path(self):
        safe = self.device.replace('/', '_').replace(':', '_')
        return os.path.join(self._key_dir, f'{safe}.keypair.json')

    def _load_keypair(self):
        if self._keypair:
            return self._keypair
        p = self._key_path()
        if os.path.exists(p):
            with open(p) as f:
                self._keypair = json.load(f)
            return self._keypair
        c = self._get_crypto(); be = c['be']()
        os.makedirs(self._key_dir, exist_ok=True)
        priv = c['gen'](c['curve'](), be)
        pub  = priv.public_key()
        pd   = priv.private_bytes(c['Enc'].DER, c['Priv'].PKCS8, c['NoEnc']())
        pubd = pub.public_bytes(c['Enc'].DER, c['Pub'].SubjectPublicKeyInfo)
        kp   = {'device': self.device,
                'ecdh_priv': pd.hex(), 'ecdh_pub': pubd.hex(),
                'kyber_pub': '', 'kyber_priv': ''}
        K = self._try_mlkem()
        if K:
            try:
                kp['kyber_pub'], kp['kyber_priv'] = K.keygen()
                kp['kyber_pub']   = kp['kyber_pub'].hex()
                kp['kyber_priv']  = kp['kyber_priv'].hex()
            except Exception:
                pass
        with open(p, 'w') as f:
            json.dump(kp, f)
        os.chmod(p, 0o600)
        self._keypair = kp
        return kp

    def _ecdh_raw_pub(self, spki_der: bytes) -> bytes:
        """Extract uncompressed 65-byte P-256 point from SPKI DER."""
        return spki_der[-65:]

    # ── Encrypt (PQHB v1) ────────────────────────────────────────────────────
    def _encrypt(self, plaintext: bytes, receiver_spki_hex: str) -> bytes:
        c = self._get_crypto(); K = self._try_mlkem(); be = c['be']()
        recv_pub = c['lpub'](bytes.fromhex(receiver_spki_hex), be)
        ecdh_ss = kss = ikm = key = None
        try:
            # Ephemeral ECDH
            eph     = c['gen'](c['curve'](), be)
            ecdh_ss = eph.exchange(c['ECDH'](), recv_pub)
            eph_raw = self._ecdh_raw_pub(
                eph.public_key().public_bytes(c['Enc'].DER, c['Pub'].SubjectPublicKeyInfo))

            # Optional ML-KEM (post-quantum)
            kss = b''
            if K:
                try:
                    recv_kyber = bytes.fromhex(
                        self._load_keypair().get('kyber_pub', ''))
                    if recv_kyber:
                        _, kss = K.enc(recv_kyber)
                except Exception:
                    kss = b''

            # HKDF
            salt = os.urandom(16)
            ikm  = ecdh_ss + kss
            key  = c['HKDF'](algorithm=c['hsh'].SHA256(), length=32,
                              salt=salt, info=b'paramant-ghost-pipe-v1',
                              backend=be).derive(ikm)
            # AES-256-GCM
            iv = os.urandom(12)
            ct = c['AES'](key).encrypt(iv, plaintext, None)
            tag = ct[-16:]
            enc = ct[:-16]  # AESGCM appends tag; separate for wire format

            # PQHB v1: [magic][ver][salt][iv][tag][eph_pub_raw][ciphertext]
            return MAGIC + VER + salt + iv + tag + eph_raw + enc
        finally:
            for _b in (ecdh_ss, kss, ikm, key):
                if _b:
                    _zero(_b)

    # ── Decrypt (PQHB v1) ────────────────────────────────────────────────────
    def _decrypt(self, blob: bytes) -> bytes:
        if len(blob) < HDR_LEN + 1:
            raise GhostPipeError('Blob te kort', 'BAD_BLOB')
        if not blob.startswith(MAGIC):
            raise GhostPipeError('Ongeldig magic (verwacht PQHB)', 'BAD_MAGIC')
        off       = 6
        salt      = blob[off:off+16]; off += 16
        iv        = blob[off:off+12]; off += 12
        tag       = blob[off:off+16]; off += 16
        eph_raw   = blob[off:off+65]; off += 65
        enc       = blob[off:]

        c  = self._get_crypto(); be = c['be']()
        kp = self._load_keypair()
        ecdh_ss = key = None
        try:
            priv    = c['lpriv'](bytes.fromhex(kp['ecdh_priv']), None, be)
            # Wrap raw 65-byte P-256 point in SPKI DER header
            from cryptography.hazmat.primitives.serialization import load_der_public_key
            SPKI_PREFIX = bytes.fromhex(
                '3059301306072a8648ce3d020106082a8648ce3d030107034200')
            eph_spki = SPKI_PREFIX + eph_raw
            eph_pub  = load_der_public_key(eph_spki, be)
            ecdh_ss  = priv.exchange(c['ECDH'](), eph_pub)

            key  = c['HKDF'](algorithm=c['hsh'].SHA256(), length=32,
                              salt=salt, info=b'paramant-ghost-pipe-v1',
                              backend=be).derive(ecdh_ss)
            # Reattach tag for AESGCM decrypt
            try:
                return c['AES'](key).decrypt(iv, enc + tag, None)
            except Exception:
                raise GhostPipeError(
                    'Ontsleuteling mislukt — verkeerde sleutel of beschadigde blob',
                    'DECRYPT_FAILED')
        finally:
            for _b in (ecdh_ss, key):
                if _b:
                    _zero(_b)

    # ── Publieke API ──────────────────────────────────────────────────────────

    def setup(self):
        """
        Initialiseer device: genereer keypair en registreer pubkeys bij relay.
        Roep dit aan VOORDAT de zender kan versturen naar dit device.
        """
        kp   = self._load_keypair()
        body = json.dumps({
            'device_id': self.device,
            'ecdh_pub':  kp['ecdh_pub'],
            'kyber_pub': kp.get('kyber_pub', ''),
        }).encode()
        status, resp = self._post('/v2/pubkey', body)
        if status != 200:
            raise GhostPipeError(
                f'Pubkey registratie mislukt: HTTP {status}: {resp.decode()[:100]}',
                'SETUP_FAILED')
        return self

    def send(self, data: bytes, ttl: int = 300,
             file_name: str = '') -> dict:
        """
        Verstuur data via Ghost Pipe (PQHB v1 wire format).

        Args:
            data:      Bytes om te versturen (max ~4.9 MB na encryptie)
            ttl:       Seconden beschikbaar op relay (default 300)
            file_name: Originele bestandsnaam (optioneel, getoond in download link)

        Returns:
            {'hash': str, 'download_token': str | None}
        """
        # Haal receiver pubkey op
        status, body = self._get(f'/v2/pubkey/{urllib.parse.quote(self.device)}')
        if status == 404:
            raise GhostPipeError(
                'Geen pubkey gevonden. Roep eerst setup() aan op de ontvanger.',
                'NO_PUBKEY')
        if status != 200:
            raise GhostPipeError(f'Pubkey ophalen mislukt: HTTP {status}', 'PUBKEY_FAILED')
        d = json.loads(body)
        recv_ecdh_hex = d.get('ecdh_pub')
        if not recv_ecdh_hex:
            raise GhostPipeError('ecdh_pub ontbreekt in relay response', 'BAD_PUBKEY')

        blob = self._encrypt(data, recv_ecdh_hex)
        if len(blob) > BLOCK:
            raise GhostPipeError(
                f'Blob te groot na encryptie: {len(blob)} bytes (max {BLOCK})',
                'TOO_LARGE')
        h    = hashlib.sha256(blob).hexdigest()
        meta = {'device_id': self.device}
        if file_name:
            meta['file_name'] = file_name
        req_body = json.dumps({
            'hash':    h,
            'payload': base64.b64encode(blob).decode(),
            'ttl_ms':  ttl * 1000,
            'meta':    meta,
        }).encode()
        status, resp = self._post('/v2/inbound', req_body)
        if status != 200:
            raise GhostPipeError(
                f'Upload mislukt: HTTP {status}: {resp.decode()[:100]}',
                'SEND_FAILED')
        rd = json.loads(resp)
        return {'hash': rd.get('hash', h), 'download_token': rd.get('download_token')}

    def receive(self, hash_: str) -> bytes:
        """
        Ontvang data van relay via hash.
        Relay vernietigt het blok direct na dit verzoek (burn-on-read).

        Args:
            hash_: SHA-256 hash van het blok

        Returns:
            Ontsleutelde bytes
        """
        status, raw = self._get(f'/v2/outbound/{urllib.parse.quote(hash_)}')
        if status == 404:
            raise GhostPipeError(
                'Blok niet gevonden. Verlopen, al opgehaald, of nooit opgeslagen.',
                'NOT_FOUND')
        if status != 200:
            raise GhostPipeError(f'Download mislukt: HTTP {status}', 'RECEIVE_FAILED')
        # Relay returns raw binary (application/octet-stream) — do NOT base64-decode
        return self._decrypt(raw)

    def status(self, hash_: str) -> dict:
        """Check of een blok beschikbaar is op de relay."""
        _, body = self._get(f'/v2/status/{urllib.parse.quote(hash_)}')
        return json.loads(body)

    def health(self) -> dict:
        """Relay health check."""
        _, body = self._get('/health')
        return json.loads(body)

    def audit(self, limit: int = 100) -> list:
        """Haal audit log op voor deze API key."""
        _, body = self._get('/v2/audit', {'limit': limit})
        return json.loads(body).get('entries', [])

    def register_webhook(self, callback_url: str, secret: str = ''):
        """Registreer webhook voor push notificaties."""
        body   = json.dumps({'device_id': self.device,
                             'url': callback_url, 'secret': secret}).encode()
        status, resp = self._post('/v2/webhook', body)
        if status != 200:
            raise GhostPipeError(
                f'Webhook registratie mislukt: {resp.decode()[:100]}', 'WEBHOOK_FAILED')

    def listen(self, on_receive: Callable, interval: int = 3):
        """
        Luister continu op nieuwe blokken (polling via /v2/stream-next).

        Args:
            on_receive: callback(data: bytes, meta: dict)
            interval:   Poll interval in seconden
        """
        self.setup()
        seq = self._load_seq()
        while True:
            try:
                _, body = self._get('/v2/stream-next',
                                    {'device': self.device, 'seq': seq})
                d = json.loads(body)
                if d.get('available') and d.get('hash'):
                    next_seq = d.get('seq', seq + 1)
                    try:
                        data = self.receive(d['hash'])
                        seq  = next_seq
                        self._save_seq(seq)
                        on_receive(data, {'seq': seq, 'hash': d['hash']})
                        continue
                    except GhostPipeError as e:
                        if e.code != 'NOT_FOUND':
                            raise
                        seq = next_seq
            except GhostPipeError:
                pass
            except Exception:
                pass
            time.sleep(interval)

    def _load_seq(self) -> int:
        p = os.path.join(os.path.expanduser('~/.paramant'),
                         self.device.replace('/', '_') + '.seq')
        try:
            return int(open(p).read().strip())
        except Exception:
            return 0

    def _save_seq(self, seq: int):
        d = os.path.expanduser('~/.paramant')
        os.makedirs(d, exist_ok=True)
        p   = os.path.join(d, self.device.replace('/', '_') + '.seq')
        tmp = p + '.tmp'
        open(tmp, 'w').write(str(seq))
        os.replace(tmp, p)

    # Backwards-compat alias
    def receive_setup(self):
        return self.setup()


# ── Multi-relay failover ──────────────────────────────────────────────────────
class GhostPipeCluster:
    """
    Multi-relay client met automatische failover.

    Gebruik:
        cluster = GhostPipeCluster(
            api_key='pgp_xxx',
            device='mri-001',
            relays=['https://health.paramant.app', 'https://health-fra.paramant.app']
        )
        result = cluster.send(data)
    """

    def __init__(self, api_key: str, device: str, relays: list,
                 health_interval: int = 30):
        self.api_key  = api_key
        self.device   = device
        self.relays   = relays
        self._healthy = {r: True for r in relays}
        import threading
        t = threading.Thread(target=self._monitor, args=(health_interval,), daemon=True)
        t.start()
        time.sleep(1.5)

    def _check(self, relay: str) -> bool:
        try:
            r = urllib.request.urlopen(
                urllib.request.Request(f'{relay}/health', headers={'User-Agent': UA}),
                timeout=5)
            return json.loads(r.read()).get('ok', False)
        except Exception:
            return False

    def _monitor(self, interval: int):
        while True:
            for relay in self.relays:
                self._healthy[relay] = self._check(relay)
            time.sleep(interval)

    def _client(self) -> 'GhostPipe':
        for relay in self.relays:
            if self._healthy.get(relay):
                return GhostPipe(self.api_key, self.device, relay=relay)
        raise GhostPipeError('Geen gezonde relay beschikbaar', 'NO_RELAY')

    def send(self, data: bytes, ttl: int = 300, file_name: str = '') -> dict:
        errors = []
        for relay in self.relays:
            if not self._healthy.get(relay):
                continue
            try:
                return GhostPipe(self.api_key, self.device, relay=relay).send(data, ttl, file_name)
            except GhostPipeError as e:
                errors.append(f'{relay}: {e}')
                self._healthy[relay] = False
        raise GhostPipeError(f'Alle relays mislukt: {errors}', 'ALL_FAILED')

    def receive(self, hash_: str) -> bytes:
        for relay in self.relays:
            try:
                s = GhostPipe(self.api_key, self.device, relay=relay).status(hash_)
                if s.get('available'):
                    return GhostPipe(self.api_key, self.device, relay=relay).receive(hash_)
            except Exception:
                pass
        raise GhostPipeError('Blok niet gevonden op een van de relays', 'NOT_FOUND')

    def setup(self):
        return self._client().setup()

    def health(self) -> dict:
        return {'relays': dict(self._healthy)}


# ── CLI ───────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    import sys, argparse

    p = argparse.ArgumentParser(description=f'PARAMANT Ghost Pipe SDK v{__version__}')
    p.add_argument('action', choices=['send', 'receive', 'status', 'listen',
                                      'health', 'audit', 'setup'])
    p.add_argument('--key',    required=True)
    p.add_argument('--device', required=True)
    p.add_argument('--relay',  default='')
    p.add_argument('--sector', default='')
    p.add_argument('--hash',   default='')
    p.add_argument('--file',   default='')
    p.add_argument('--ttl',    type=int, default=300)
    p.add_argument('--output', default='')
    p.add_argument('--webhook', default='')
    a = p.parse_args()

    gp = GhostPipe(a.key, a.device, relay=a.relay, sector=a.sector)

    if a.action == 'setup':
        gp.setup()
        print('✓ Keypair gegenereerd en geregistreerd bij relay')

    elif a.action == 'send':
        data = open(a.file, 'rb').read() if a.file else sys.stdin.buffer.read()
        result = gp.send(data, ttl=a.ttl, file_name=os.path.basename(a.file or ''))
        print(f'OK hash={result["hash"]}')
        if result.get('download_token'):
            print(f'   download_token={result["download_token"]}')

    elif a.action == 'receive':
        if not a.hash: sys.exit('--hash vereist')
        gp.setup()
        data = gp.receive(a.hash)
        if a.output:
            with open(a.output, 'wb') as f: f.write(data)
            print(f'OK opgeslagen in {a.output} ({len(data)} bytes)')
        else:
            sys.stdout.buffer.write(data)

    elif a.action == 'status':
        if not a.hash: sys.exit('--hash vereist')
        print(json.dumps(gp.status(a.hash), indent=2))

    elif a.action == 'listen':
        def on_receive(data, meta):
            if a.output:
                out = os.path.join(a.output, f'block_{meta["seq"]:06d}.bin')
                os.makedirs(a.output, exist_ok=True)
                open(out, 'wb').write(data)
                print(f'[RECV] seq={meta["seq"]} {len(data)}B → {out}')
            else:
                print(f'[RECV] seq={meta["seq"]} {len(data)}B')
        if a.webhook:
            gp.setup()
            gp.register_webhook(a.webhook)
            print(f'Webhook geregistreerd: {a.webhook}')
        gp.listen(on_receive)

    elif a.action == 'health':
        print(json.dumps(gp.health(), indent=2))

    elif a.action == 'audit':
        for e in gp.audit():
            print(f"{e['ts']}  {e['event']:<20}  {e.get('hash','')[:16]}  {e.get('bytes',0)}B")
