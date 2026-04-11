"""
PARAMANT Ghost Pipe SDK v1.0.0
Python SDK voor quantum-safe datatransport

pip install cryptography

Gebruik:
  from paramant import GhostPipe

  # Zender
  gp = GhostPipe(api_key='pgp_xxx', device='mri-001')
  hash = gp.send(open('scan.dcm','rb').read())
  print(f'Hash voor ontvanger: {hash}')

  # Ontvanger
  gp = GhostPipe(api_key='pgp_xxx', device='mri-001')
  gp.listen(on_receive=lambda data, meta: save(data))
"""
import base64, ctypes, hashlib, json, os, struct, sys, time, warnings
import urllib.request, urllib.error
from typing import Callable, Optional

__version__ = '1.0.0'

# ── Blokgroottes voor padding ──────────────────────────────────────────────────
BLOCKS = {
    '4k':   4 * 1024,
    '64k':  64 * 1024,
    '512k': 512 * 1024,
    '5m':   5 * 1024 * 1024,
}

# ── Sleutelzeroïsatie ─────────────────────────────────────────────────────────
_ZEROIZE_OK = (sys.implementation.name == 'cpython')
if not _ZEROIZE_OK:
    warnings.warn(
        'paramant-sdk: key zeroization (ctypes) is not supported on '
        f'{sys.implementation.name}. Secret key material may persist in RAM.',
        RuntimeWarning, stacklevel=2,
    )


def _zero(b: bytes) -> None:
    """Overschrijf sleutelmateriaal in geheugen met nullen (CPython, best-effort)."""
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

# ── BIP39 helpers ─────────────────────────────────────────────────────────────
def _bip39_encode(entropy: bytes) -> str:
    """Zet 16 bytes entropy om naar 12-woord BIP39 mnemonic."""
    try:
        from mnemonic import Mnemonic
        return Mnemonic('english').to_mnemonic(entropy)
    except ImportError:
        raise GhostPipeError('pip install mnemonic (vereist voor drop/pickup)')

def _bip39_decode(phrase: str) -> bytes:
    """Zet 12-woord BIP39 mnemonic terug naar 16 bytes entropy."""
    try:
        from mnemonic import Mnemonic
        m = Mnemonic('english')
        if not m.check(phrase):
            raise GhostPipeError('Ongeldige BIP39 mnemonic (checksum fout)')
        return bytes(m.to_entropy(phrase))
    except ImportError:
        raise GhostPipeError('pip install mnemonic (vereist voor drop/pickup)')

def _derive_drop_keys(entropy: bytes) -> tuple:
    """Leid AES sleutel en relay lookup-hash af van entropy."""
    try:
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
        be = default_backend()
        aes_key  = HKDF(algorithm=hashes.SHA256(), length=32,
                        salt=b'paramant-drop-v1', info=b'aes-key', backend=be).derive(entropy)
        id_bytes = HKDF(algorithm=hashes.SHA256(), length=32,
                        salt=b'paramant-drop-v1', info=b'lookup-id', backend=be).derive(entropy)
        lookup_hash = hashlib.sha256(id_bytes).hexdigest()
        return aes_key, lookup_hash
    except ImportError:
        raise GhostPipeError('pip install cryptography')

SECTOR_RELAYS = {
    'health':  'https://health.paramant.app',
    'iot':     'https://iot.paramant.app',
    'legal':   'https://legal.paramant.app',
    'finance': 'https://finance.paramant.app',
    'relay':   'https://relay.paramant.app',
}

EDGE_RELAY = 'https://paramant-ghost-pipe.fly.dev'

def get_relay_url(sector='health', use_edge=False):
    """
    Geef juiste relay URL terug.
    use_edge=True  → via Fly.io edge (geo-routed, 6 regio's)
    use_edge=False → direct naar sector relay (lager latency EU)
    """
    if use_edge:
        return f"{EDGE_RELAY}/{sector}"
    return SECTOR_RELAYS.get(sector, SECTOR_RELAYS['health'])

BLOCK = 5 * 1024 * 1024
UA    = f'paramant-sdk/{__version__}'


class GhostPipeError(Exception):
    pass

class FingerprintMismatchError(GhostPipeError):
    """Raised when a device's pubkey fingerprint differs from the stored (TOFU) value.
    This indicates either a key rotation or a relay MITM attack.
    """
    def __init__(self, device_id: str, stored: str, received: str):
        self.device_id = device_id
        self.stored    = stored
        self.received  = received
        super().__init__(
            f'\n\n  ⚠  FINGERPRINT MISMATCH — device: {device_id}\n'
            f'  Stored:   {stored}\n'
            f'  Received: {received}\n\n'
            f'  This may indicate a compromised relay or legitimate key rotation.\n'
            f'  If the device owner rotated their key, run:\n'
            f'    gp.trust("{device_id}")  — after verifying the new fingerprint out-of-band\n'
        )


class GhostPipe:
    """
    PARAMANT Ghost Pipe client.
    
    Quantum-safe end-to-end encrypted datatransport.
    Relay ziet NOOIT plaintext. Burn-on-read na ophalen.
    
    Args:
        api_key:  pgp_... API key van paramant.app/dashboard
        device:   Uniek apparaat-ID (zender en ontvanger gebruiken hetzelfde)
        relay:    Relay URL (automatisch gedetecteerd op basis van key)
        secret:   Extra geheim voor encryptie (optioneel, default=api_key)
    """

    def __init__(self, api_key: str, device: str, relay: str = '', secret: str = ''):
        if not api_key.startswith('pgp_'):
            raise GhostPipeError('API key moet beginnen met pgp_')
        self.api_key = api_key
        self.device  = device
        self.secret  = secret or api_key
        self.relay   = relay or self._detect_relay()
        if not self.relay:
            raise GhostPipeError('Geen relay bereikbaar. Controleer API key.')
        self._keypair = None

    # ── TOFU / known-keys ─────────────────────────────────────────────────────
    @staticmethod
    def _known_keys_path() -> str:
        return os.path.join(os.path.expanduser('~/.paramant'), 'known_keys')

    def _load_known_keys(self) -> dict:
        """Load ~/.paramant/known_keys → {device_id: {fingerprint, registered_at}}"""
        p = self._known_keys_path()
        if not os.path.exists(p):
            return {}
        result = {}
        with open(p) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    result[parts[0]] = {'fingerprint': parts[1], 'registered_at': parts[2] if len(parts) > 2 else ''}
        return result

    def _save_known_key(self, device_id: str, fingerprint: str, registered_at: str = ''):
        """Append or update a device in known_keys."""
        os.makedirs(os.path.dirname(self._known_keys_path()), exist_ok=True)
        keys = self._load_known_keys()
        keys[device_id] = {'fingerprint': fingerprint, 'registered_at': registered_at or ''}
        tmp = self._known_keys_path() + '.tmp'
        with open(tmp, 'w') as f:
            f.write('# PARAMANT known-keys — Trust On First Use (TOFU)\n')
            f.write('# Format: device_id fingerprint registered_at\n')
            for did, v in keys.items():
                f.write(f'{did} {v["fingerprint"]} {v["registered_at"]}\n')
        os.chmod(tmp, 0o600)
        os.replace(tmp, self._known_keys_path())

    def _remove_known_key(self, device_id: str):
        keys = self._load_known_keys()
        if device_id in keys:
            del keys[device_id]
            tmp = self._known_keys_path() + '.tmp'
            with open(tmp, 'w') as f:
                f.write('# PARAMANT known-keys — Trust On First Use (TOFU)\n')
                f.write('# Format: device_id fingerprint registered_at\n')
                for did, v in keys.items():
                    f.write(f'{did} {v["fingerprint"]} {v["registered_at"]}\n')
            os.chmod(tmp, 0o600)
            os.replace(tmp, self._known_keys_path())

    @staticmethod
    def _compute_fingerprint(kyber_pub_hex: str, ecdh_pub_hex: str) -> str:
        """SHA-256(kyber_pub_bytes || ecdh_pub_bytes) → first 10 bytes → XXXX-XXXX-XXXX-XXXX-XXXX
        Matches parashare.html and ontvang.html exactly for cross-surface consistency.
        """
        buf = bytes.fromhex(kyber_pub_hex or '') + bytes.fromhex(ecdh_pub_hex or '')
        h = hashlib.sha256(buf).hexdigest()[:20].upper()
        return f'{h[0:4]}-{h[4:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}'

    def _tofu_check(self, device_id: str, kyber_pub_hex: str, ecdh_pub_hex: str,
                    registered_at: str = '') -> str:
        """Check TOFU for device. Returns fingerprint. Stores on first use.
        Raises FingerprintMismatchError if stored fingerprint differs."""
        fp = self._compute_fingerprint(kyber_pub_hex, ecdh_pub_hex)
        keys = self._load_known_keys()
        if device_id in keys:
            stored = keys[device_id]['fingerprint']
            if stored.replace('-','').upper() != fp.replace('-','').upper():
                raise FingerprintMismatchError(device_id, stored, fp)
        else:
            # First contact — store fingerprint (TOFU)
            self._save_known_key(device_id, fp, registered_at)
            print(f'[paramant] New device: {device_id}')
            print(f'           Fingerprint: {fp}')
            print(f'           Verify this out-of-band before trusting.')
        return fp

    # ── Relay detectie ────────────────────────────────────────────────────────
    def _detect_relay(self) -> Optional[str]:
        for relay in SECTOR_RELAYS.values():
            try:
                r = urllib.request.urlopen(
                    urllib.request.Request(f'{relay}/v2/check-key?k={self.api_key}',
                                           headers={'User-Agent': UA}), timeout=4)
                if json.loads(r.read()).get('valid'):
                    return relay
            except Exception:
                pass
        return None

    # ── HTTP helpers ──────────────────────────────────────────────────────────
    def _get(self, path: str, params: dict = None):
        import urllib.parse
        url = self.relay + path
        if params: url += '?' + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={'User-Agent': UA, 'X-Api-Key': self.api_key})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    def _post(self, path: str, body: bytes, content_type: str = 'application/json'):
        req = urllib.request.Request(
            self.relay + path, data=body, method='POST',
            headers={'Content-Type': content_type, 'X-Api-Key': self.api_key, 'User-Agent': UA})
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
            return dict(HKDF=HKDF, hsh=hashes, AES=AESGCM, gen=generate_private_key,
                        ECDH=ECDH, curve=SECP256R1, Enc=Encoding, Pub=PublicFormat,
                        Priv=PrivateFormat, NoEnc=NoEncryption,
                        lpub=load_der_public_key, lpriv=load_der_private_key,
                        be=default_backend)
        except ImportError:
            raise GhostPipeError('pip install cryptography')

    def _try_kyber(self):
        try:
            from kyber import Kyber768
            return Kyber768
        except ImportError:
            return None

    def _load_keypair(self):
        """Laad of genereer keypair voor dit device."""
        if self._keypair:
            return self._keypair
        state_dir = os.path.expanduser('~/.paramant')
        path = os.path.join(state_dir, self.device.replace('/','_') + '.keypair.json')
        if os.path.exists(path):
            self._keypair = json.load(open(path))
            return self._keypair
        c = self._get_crypto(); K = self._try_kyber(); be = c['be']()
        os.makedirs(state_dir, exist_ok=True)
        priv = c['gen'](c['curve'](), be)
        pub  = priv.public_key()
        pd   = priv.private_bytes(c['Enc'].DER, c['Priv'].PKCS8, c['NoEnc']())
        pubd = pub.public_bytes(c['Enc'].DER, c['Pub'].SubjectPublicKeyInfo)
        kpub = b''; kpriv = b''
        if K:
            kpub, kpriv = K.keygen()
        kp = {'device': self.device, 'ecdh_priv': pd.hex(), 'ecdh_pub': pubd.hex(),
              'kyber_pub': kpub.hex() if kpub else '', 'kyber_priv': kpriv.hex() if kpriv else ''}
        with open(path, 'w') as f: json.dump(kp, f)
        os.chmod(path, 0o600)
        self._keypair = kp
        return kp

    def _register_pubkeys(self):
        """Registreer pubkeys bij relay."""
        kp = self._load_keypair()
        body = json.dumps({'device_id': self.device, 'ecdh_pub': kp['ecdh_pub'],
                           'kyber_pub': kp.get('kyber_pub', '')}).encode()
        status, resp = self._post('/v2/pubkey', body)
        if status != 200:
            raise GhostPipeError(f'Pubkey registratie mislukt: {resp.decode()[:100]}')

    def _fetch_receiver_pubkeys(self, recipient: str = None):
        """Haal pubkeys op van relay (voor encryptie). Returns (ecdh_pub, kyber_pub, raw_ecdh_hex, raw_kyber_hex, registered_at)."""
        target = recipient or self.device
        status, body = self._get(f'/v2/pubkey/{target}')
        if status == 404:
            raise GhostPipeError('Geen pubkeys voor dit device. Start ontvanger eerst met receive_setup().')
        if status != 200:
            raise GhostPipeError(f'Pubkeys ophalen mislukt: HTTP {status}')
        d = json.loads(body)
        c  = self._get_crypto(); be = c['be']()
        ecdh_pub  = c['lpub'](bytes.fromhex(d['ecdh_pub']), be)
        kyber_pub = bytes.fromhex(d['kyber_pub']) if d.get('kyber_pub') else None
        return ecdh_pub, kyber_pub, d['ecdh_pub'], d.get('kyber_pub',''), d.get('registered_at', '')

    def _encrypt(self, data: bytes, ecdh_pub, kyber_pub, pad_block: int = None,
                 pre_shared_secret: str = '') -> tuple:
        """ML-KEM-768 + ECDH + AES-256-GCM + optional PSS + padding.
        PSS: K = HKDF(ecdh_ss || kem_ss || SHA3-256(pss)) — even a relay MITM can't decrypt.
        """
        c  = self._get_crypto(); K = self._try_kyber(); be = c['be']()
        ecdh_ss = kss = ikm = ss = pss_hash = None
        try:
            # ECDH
            eph     = c['gen'](c['curve'](), be)
            ecdh_ss = eph.exchange(c['ECDH'](), ecdh_pub)
            eph_b   = eph.public_key().public_bytes(c['Enc'].DER, c['Pub'].SubjectPublicKeyInfo)
            # ML-KEM
            kct = b''; kss = b''
            if K and kyber_pub:
                try: kct, kss = K.enc(kyber_pub)
                except Exception: pass
            # HKDF — salt derived from KEM ciphertext (matches browser: cipherText.slice(0,32))
            # When ML-KEM is unavailable, fall back to ECDH shared secret slice as domain separator.
            # Static salt 'paramant-gp-v1' removed (security finding #7).
            pss_hash = hashlib.sha3_256(pre_shared_secret.encode('utf-8')).digest() if pre_shared_secret else b''
            ikm  = ecdh_ss + kss + pss_hash
            salt = kct[:32] if kct else ecdh_ss[:32]
            ss   = c['HKDF'](algorithm=c['hsh'].SHA256(), length=32,
                             salt=salt, info=b'aes-key', backend=be).derive(ikm)
            # AES-256-GCM — AAD binds version+chunk to ciphertext (finding #8)
            nonce  = os.urandom(12)
            aad    = b'\x02\x00\x00\x00\x00'  # version 0x02 + chunk_index 0 (single-chunk)
            ct     = c['AES'](ss).encrypt(nonce, data, aad)
            bundle = struct.pack('>I', len(eph_b)) + eph_b + struct.pack('>I', len(kct)) + kct
            packet = struct.pack('>I', len(bundle)) + bundle + nonce + struct.pack('>I', len(ct)) + ct
            target = pad_block or BLOCK
            if len(packet) > target:
                raise GhostPipeError(f'Data te groot voor dit blok ({len(data)} bytes, max {target} bytes)')
            blob = packet + os.urandom(target - len(packet))
            return blob, hashlib.sha256(blob).hexdigest(), bool(kct)
        finally:
            for b in (ecdh_ss, kss, ikm, ss, pss_hash):
                if b: _zero(b)

    def _decrypt(self, blob: bytes, pre_shared_secret: str = '') -> bytes:
        """Ontsleutel Ghost Pipe blob. PSS must match what sender used."""
        c  = self._get_crypto(); K = self._try_kyber(); be = c['be']()
        kp = self._load_keypair()
        o  = 0
        blen = struct.unpack('>I', blob[o:o+4])[0]; o += 4
        bun  = blob[o:o+blen]; o += blen
        bo   = 0
        eplen = struct.unpack('>I', bun[bo:bo+4])[0]; bo += 4
        epb   = bun[bo:bo+eplen]; bo += eplen
        klen  = struct.unpack('>I', bun[bo:bo+4])[0]; bo += 4
        kct   = bun[bo:bo+klen]
        nonce = blob[o:o+12]; o += 12
        ctlen = struct.unpack('>I', blob[o:o+4])[0]; o += 4
        ct    = blob[o:o+ctlen]
        ecdh_ss = kss = ikm = ss = pss_hash = None
        try:
            priv    = c['lpriv'](bytes.fromhex(kp['ecdh_priv']), None, be)
            ecdh_ss = priv.exchange(c['ECDH'](), c['lpub'](epb, be))
            kss = b''
            if K and kct and kp.get('kyber_priv'):
                try: kss = K.dec(bytes.fromhex(kp['kyber_priv']), kct)
                except Exception: pass
            pss_hash = hashlib.sha3_256(pre_shared_secret.encode('utf-8')).digest() if pre_shared_secret else b''
            ikm  = ecdh_ss + kss + pss_hash
            salt = kct[:32] if kct else ecdh_ss[:32]
            ss   = c['HKDF'](algorithm=c['hsh'].SHA256(), length=32,
                             salt=salt, info=b'aes-key', backend=be).derive(ikm)
            aad  = b'\x02\x00\x00\x00\x00'  # version 0x02 + chunk_index 0
            return c['AES'](ss).decrypt(nonce, ct, aad)
        finally:
            for b in (ecdh_ss, kss, ikm, ss, pss_hash):
                if b: _zero(b)

    # ── Publieke API ──────────────────────────────────────────────────────────

    def send(self, data: bytes, ttl: int = 300, max_views: int = 1,
             pad_block: int = None, recipient: str = None,
             pre_shared_secret: str = '') -> str:
        """
        Verstuur data via Ghost Pipe.

        Args:
            data:               Bytes om te versturen
            ttl:                Seconden beschikbaar op relay (default 300)
            max_views:          Max ophaalverzoeken voor burn (default 1)
            pad_block:          Blokgrootte voor padding in bytes (default 5MB)
            recipient:          Device-ID van ontvanger (default: self.device)
            pre_shared_secret:  Optioneel geheim — toevoeging aan HKDF-IKM.
                                Beide kanten moeten hetzelfde PSS gebruiken.
                                Beschermt ook als relay een verkeerde pubkey serveert.

        Returns:
            hash: SHA-256 hash — geef dit aan de ontvanger
        """
        ecdh_pub, kyber_pub, ecdh_hex, kyber_hex, registered_at = self._fetch_receiver_pubkeys(recipient)
        target_device = recipient or self.device
        # TOFU check — raises FingerprintMismatchError on mismatch
        self._tofu_check(target_device, kyber_hex, ecdh_hex, registered_at)
        blob, h, used_kyber = self._encrypt(data, ecdh_pub, kyber_pub, pad_block=pad_block,
                                            pre_shared_secret=pre_shared_secret)
        body = json.dumps({
            'hash': h,
            'payload': base64.b64encode(blob).decode(),
            'ttl_ms': ttl * 1000,
            'max_views': max_views,
            'meta': {'device_id': self.device},
        }).encode()
        status, resp = self._post('/v2/inbound', body)
        if status != 200:
            raise GhostPipeError(f'Upload mislukt: HTTP {status}: {resp.decode()[:100]}')
        return h

    def drop(self, data: bytes, ttl: int = 3600, pad_block: int = None) -> str:
        """
        Stuur data als anonieme drop met 12-woord BIP39 mnemonic als access token.
        Geen ECDH keypairs nodig — de mnemonic IS de gedeelde sleutel.
        Altijd burn-on-read (max_views=1).

        Args:
            data:      Bytes om te droppen
            ttl:       Seconden beschikbaar (default 3600)
            pad_block: Blokgrootte voor padding (default 5MB)

        Returns:
            12-woord BIP39 mnemonic — geef dit aan de ontvanger
        """
        entropy = os.urandom(16)
        phrase  = _bip39_encode(entropy)
        aes_key, lookup_hash = _derive_drop_keys(entropy)
        try:
            c = self._get_crypto(); be = c['be']()
            nonce  = os.urandom(12)
            ct     = c['AES'](aes_key).encrypt(nonce, data, None)
            packet = nonce + struct.pack('>I', len(ct)) + ct
            target = pad_block or BLOCK
            if len(packet) > target:
                raise GhostPipeError(f'Data te groot voor drop-blok ({len(data)} bytes)')
            blob = packet + os.urandom(target - len(packet))
            body = json.dumps({
                'hash':     lookup_hash,
                'payload':  base64.b64encode(blob).decode(),
                'ttl_ms':   ttl * 1000,
                'max_views': 1,
                'meta':     {'drop': True},
            }).encode()
            status, resp = self._post('/v2/inbound', body)
            if status != 200:
                raise GhostPipeError(f'Drop upload mislukt: HTTP {status}: {resp.decode()[:100]}')
            return phrase
        finally:
            _zero(aes_key); _zero(entropy)

    def pickup(self, phrase: str) -> bytes:
        """
        Ontvang een anonieme drop via 12-woord BIP39 mnemonic.
        Burn-on-read — werkt maar één keer.

        Args:
            phrase: 12-woord BIP39 mnemonic (spaties als scheidingsteken)

        Returns:
            Ontsleutelde data
        """
        entropy = _bip39_decode(phrase.strip())
        aes_key, lookup_hash = _derive_drop_keys(entropy)
        try:
            status, raw = self._get(f'/v2/outbound/{lookup_hash}')
            if status == 404:
                raise GhostPipeError('Drop niet gevonden. Verlopen, al opgehaald, of ongeldige mnemonic.')
            if status != 200:
                raise GhostPipeError(f'Drop ophalen mislukt: HTTP {status}')
            nonce  = raw[:12]
            ct_len = struct.unpack('>I', raw[12:16])[0]
            ct     = raw[16:16 + ct_len]
            c = self._get_crypto(); be = c['be']()
            return c['AES'](aes_key).decrypt(nonce, ct, None)
        finally:
            _zero(aes_key); _zero(entropy)

    def receive(self, hash_: str, pre_shared_secret: str = '') -> bytes:
        """
        Ontvang data van relay via hash.
        Relay vernietigt het blok direct na dit verzoek (burn-on-read).

        Args:
            hash_:              SHA-256 hash van het blok
            pre_shared_secret:  Moet overeenkomen met waarde die zender gebruikte.

        Returns:
            Ontsleutelde data

        Raises:
            GhostPipeError: Blok niet gevonden, verlopen of al opgehaald
        """
        status, raw = self._get(f'/v2/outbound/{hash_}')
        if status == 404:
            raise GhostPipeError('Blok niet gevonden. Verlopen, al opgehaald, of nooit opgeslagen.')
        if status != 200:
            raise GhostPipeError(f'Download mislukt: HTTP {status}')
        return self._decrypt(raw, pre_shared_secret=pre_shared_secret)

    def status(self, hash_: str) -> dict:
        """
        Check of een blok beschikbaar is op de relay.
        
        Returns:
            {'available': bool, 'ttl_remaining_ms': int, 'bytes': int}
        """
        _, body = self._get(f'/v2/status/{hash_}')
        return json.loads(body)

    def fingerprint(self, device_id: str = None) -> str:
        """
        Haal fingerprint op van een device (voor out-of-band verificatie).
        Vraagt relay, berekent fingerprint lokaal, toont resultaat.

        Args:
            device_id: Device ID (default: self.device)

        Returns:
            Fingerprint string in XXXX-XXXX-XXXX-XXXX-XXXX formaat
        """
        target = device_id or self.device
        status, body = self._get(f'/v2/pubkey/{target}')
        if status == 404:
            raise GhostPipeError(f'Geen pubkeys voor device {target}')
        if status != 200:
            raise GhostPipeError(f'Pubkeys ophalen mislukt: HTTP {status}')
        d = json.loads(body)
        fp = self._compute_fingerprint(d.get('kyber_pub',''), d['ecdh_pub'])
        print(f'Device:      {target}')
        print(f'Fingerprint: {fp}')
        if d.get('registered_at'):
            print(f'Registered:  {d["registered_at"]}')
        if d.get('ct_index') is not None:
            print(f'CT log index: {d["ct_index"]}')
        return fp

    def trust(self, device_id: str, fingerprint: str = None) -> str:
        """
        Markeer device als vertrouwd in known_keys.
        Als fingerprint weggelaten: haalt huidige fingerprint op van relay.

        Returns:
            Opgeslagen fingerprint
        """
        if fingerprint:
            self._save_known_key(device_id, fingerprint)
            print(f'[paramant] Trusted: {device_id} ({fingerprint})')
            return fingerprint
        fp = self.fingerprint(device_id)
        self._save_known_key(device_id, fp)
        print(f'[paramant] Trusted: {device_id} ({fp})')
        return fp

    def untrust(self, device_id: str):
        """Verwijder device uit known_keys."""
        self._remove_known_key(device_id)
        print(f'[paramant] Removed: {device_id}')

    def known_devices(self) -> list:
        """Geef lijst van alle trusted devices met fingerprints."""
        keys = self._load_known_keys()
        if not keys:
            print('[paramant] No trusted devices yet.')
            return []
        print(f'{"Device":<36} {"Fingerprint":<26} {"Registered":<24}')
        print('-' * 88)
        for did, v in keys.items():
            print(f'{did:<36} {v["fingerprint"]:<26} {v["registered_at"]:<24}')
        return [{'device_id': k, **v} for k, v in keys.items()]

    def receive_setup(self):
        """
        Initialiseer ontvanger: genereer keypair en registreer pubkeys bij relay.
        Roep dit aan voordat de zender kan versturen.
        """
        self._load_keypair()
        self._register_pubkeys()
        return self

    def register_webhook(self, callback_url: str, secret: str = ''):
        """
        Registreer webhook voor push notificaties.
        Relay POSTt naar callback_url zodra een blok klaarstaat.
        
        Args:
            callback_url: URL die de relay aanroept bij nieuw blok
            secret:       Optioneel HMAC-SHA256 secret voor verificatie
        """
        body = json.dumps({'device_id': self.device, 'url': callback_url, 'secret': secret}).encode()
        status, resp = self._post('/v2/webhook', body)
        if status != 200:
            raise GhostPipeError(f'Webhook registratie mislukt: {resp.decode()[:100]}')

    def listen(self, on_receive: Callable, interval: int = 3):
        """
        Luister continu op nieuwe blokken (polling).
        
        Args:
            on_receive: callback(data: bytes, meta: dict) — aangeroepen bij elk blok
            interval:   Poll interval in seconden
        """
        self.receive_setup()
        seq = self._load_seq()
        while True:
            try:
                _, body = self._get('/v2/stream-next', {'device': self.device, 'seq': seq})
                d = json.loads(body)
                if d.get('available'):
                    next_seq = d.get('seq', seq + 1)
                    try:
                        data = self.receive(d['hash'])
                        seq  = next_seq
                        self._save_seq(seq)
                        on_receive(data, {'seq': seq, 'hash': d['hash']})
                        continue
                    except GhostPipeError:
                        seq = next_seq
            except Exception:
                pass
            time.sleep(interval)

    def audit(self, limit: int = 100) -> list:
        """Haal audit log op voor deze API key."""
        _, body = self._get('/v2/audit', {'limit': limit})
        return json.loads(body).get('entries', [])

    def health(self) -> dict:
        """Relay health check."""
        _, body = self._get('/health')
        return json.loads(body)

    def _load_seq(self) -> int:
        try:
            p = os.path.join(os.path.expanduser('~/.paramant'), self.device.replace('/','_') + '.sdk_seq')
            return int(open(p).read())
        except Exception:
            return 0

    def _save_seq(self, seq: int):
        d = os.path.expanduser('~/.paramant')
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, self.device.replace('/','_') + '.sdk_seq')
        open(p + '.tmp', 'w').write(str(seq))
        os.replace(p + '.tmp', p)


# ── Gebruik als script ────────────────────────────────────────────────────────
if __name__ == '__main__':
    import sys, argparse

    p = argparse.ArgumentParser(description=f'PARAMANT Ghost Pipe SDK v{__version__}')
    p.add_argument('action', choices=['send','receive','status','listen','health','audit',
                                      'drop','pickup'])
    p.add_argument('--key',       required=True)
    p.add_argument('--device',    default='cli')
    p.add_argument('--relay',     default='')
    p.add_argument('--hash',      default='')
    p.add_argument('--mnemonic',  default='', help='12-woord BIP39 mnemonic (pickup)')
    p.add_argument('--file',      default='')
    p.add_argument('--ttl',       type=int, default=300, help='Levensduur in seconden')
    p.add_argument('--max-views', type=int, default=1,   help='Max ophaalverzoeken (burn)')
    p.add_argument('--pad-block', default='5m', choices=list(BLOCKS.keys()),
                   help='Padding blokgrootte (default: 5m)')
    p.add_argument('--output',    default='')
    p.add_argument('--webhook',   default='')
    a = p.parse_args()

    pad = BLOCKS[a.pad_block]
    gp  = GhostPipe(a.key, a.device, relay=a.relay)

    if a.action == 'send':
        data = open(a.file, 'rb').read() if a.file else sys.stdin.buffer.read()
        gp.receive_setup()
        h = gp.send(data, ttl=a.ttl, max_views=a.max_views, pad_block=pad)
        print(f'OK hash={h}')

    elif a.action == 'receive':
        if not a.hash: sys.exit('--hash vereist')
        gp.receive_setup()
        data = gp.receive(a.hash)
        if a.output:
            with open(a.output, 'wb') as f: f.write(data)
            print(f'OK opgeslagen in {a.output} ({len(data)} bytes)')
        else:
            sys.stdout.buffer.write(data)

    elif a.action == 'drop':
        data = open(a.file, 'rb').read() if a.file else sys.stdin.buffer.read()
        phrase = gp.drop(data, ttl=a.ttl, pad_block=pad)
        print(f'Mnemonic: {phrase}')

    elif a.action == 'pickup':
        if not a.mnemonic: sys.exit('--mnemonic vereist')
        data = gp.pickup(a.mnemonic)
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
                path = os.path.join(a.output, f'block_{meta["seq"]:06d}.bin')
                os.makedirs(a.output, exist_ok=True)
                open(path, 'wb').write(data)
                print(f'[RECV] seq={meta["seq"]} {len(data)}B → {path}')
            else:
                print(f'[RECV] seq={meta["seq"]} {len(data)}B')
        if a.webhook:
            gp.receive_setup()
            gp.register_webhook(a.webhook)
            print(f'Webhook geregistreerd: {a.webhook}')
        gp.listen(on_receive)

    elif a.action == 'health':
        print(json.dumps(gp.health(), indent=2))

    elif a.action == 'audit':
        for e in gp.audit():
            print(f"{e['ts']}  {e['event']:<20}  {e.get('hash',''):<20}  {e.get('bytes',0)}B")


# ── Multi-relay failover (gossip light) ───────────────────────────────────────

class GhostPipeCluster:
    """
    Multi-relay client met automatische failover.
    SDK vindt automatisch de dichtstbijzijnde gezonde node.
    
    Equivalent van "gossip protocol light" — SDK pollt health
    en schakelt automatisch over bij uitval.
    
    Gebruik:
        cluster = GhostPipeCluster(
            api_key='pgp_xxx',
            device='mri-001',
            relays=[
                'https://health.paramant.app',
                'https://health-fra.paramant.app',  # Frankfurt backup
                'https://health-sin.paramant.app',  # Singapore backup
            ]
        )
        hash = cluster.send(data)
    """

    def __init__(self, api_key: str, device: str, relays: list,
                 health_interval: int = 30):
        self.api_key   = api_key
        self.device    = device
        self.relays    = relays
        self._healthy  = {}  # relay → last_health
        self._active   = None
        self._lock     = __import__('threading').Lock()
        # Start health monitor
        import threading
        t = threading.Thread(target=self._monitor, daemon=True)
        t.start()
        # Wacht op eerste health check
        time.sleep(2)

    def _check_health(self, relay: str) -> dict:
        try:
            r = urllib.request.urlopen(
                urllib.request.Request(f'{relay}/health', headers={'User-Agent': UA}),
                timeout=5)
            d = json.loads(r.read())
            if d.get('ok'):
                return {'ok': True, 'relay': relay, 'blobs': d.get('blobs', 0),
                        'version': d.get('version'), 'latency_ms': 0}
        except Exception:
            pass
        return {'ok': False, 'relay': relay}

    def _monitor(self):
        """Achtergrond health monitor — pollt alle relays."""
        import time as t
        while True:
            for relay in self.relays:
                health = self._check_health(relay)
                with self._lock:
                    self._healthy[relay] = health
            # Selecteer beste (eerste gezonde)
            for relay in self.relays:
                if self._healthy.get(relay, {}).get('ok'):
                    with self._lock:
                        if self._active != relay:
                            self._active = relay
                    break
            t.sleep(30)

    def _get_client(self) -> 'GhostPipe':
        """Geef GhostPipe client voor actieve relay."""
        with self._lock:
            relay = self._active
        if not relay:
            raise GhostPipeError('Geen gezonde relay beschikbaar')
        return GhostPipe(self.api_key, self.device, relay=relay)

    def send(self, data: bytes, ttl: int = 300) -> str:
        """Verstuur via eerste gezonde relay. Automatische failover."""
        errors = []
        for relay in self.relays:
            if not self._healthy.get(relay, {}).get('ok'):
                continue
            try:
                gp = GhostPipe(self.api_key, self.device, relay=relay)
                return gp.send(data, ttl=ttl)
            except GhostPipeError as e:
                errors.append(f'{relay}: {e}')
                # Markeer als ongezond
                with self._lock:
                    self._healthy[relay] = {'ok': False}
        raise GhostPipeError(f'Alle relays mislukt: {errors}')

    def receive(self, hash_: str) -> bytes:
        """Ontvang van eerste relay die het blok heeft."""
        for relay in self.relays:
            try:
                gp = GhostPipe(self.api_key, self.device, relay=relay)
                status = gp.status(hash_)
                if status.get('available'):
                    return gp.receive(hash_)
            except Exception:
                pass
        raise GhostPipeError('Blok niet gevonden op een van de relays')

    def health(self) -> dict:
        """Status van alle nodes in de cluster."""
        with self._lock:
            return {'active': self._active, 'nodes': dict(self._healthy)}

    def receive_setup(self):
        """Setup op alle gezonde relays."""
        for relay in self.relays:
            if self._healthy.get(relay, {}).get('ok'):
                try:
                    GhostPipe(self.api_key, self.device, relay=relay).receive_setup()
                except Exception:
                    pass
        return self
