"""
PARAMANT Ghost Pipe SDK v2.4.1
================================
Python SDK for Paramant Ghost Pipe — post-quantum encrypted file relay.

Zero plaintext. Burn-on-read. EU/DE jurisdiction.

Install:  pip install paramant-sdk
Docs:     https://paramant.app/docs
"""
import base64
import ctypes
import hashlib
import json
import os
import struct
import sys
import time
import warnings
from typing import Callable, Dict, List, Optional, Union

import urllib.request
import urllib.error
import urllib.parse

__version__ = '2.4.1'
__all__ = [
    'GhostPipe', 'GhostPipeAdmin', 'GhostPipeCluster',
    'GhostPipeError', 'RelayError', 'AuthError', 'BurnedError',
    'FingerprintMismatchError', 'LicenseError', 'RateLimitError',
]

# ── Constants ─────────────────────────────────────────────────────────────────
BLOCK_5M = 5 * 1024 * 1024
UA       = f'paramant-sdk/{__version__} python/{sys.version_info.major}.{sys.version_info.minor}'

SECTOR_RELAYS = {
    'health':  'https://health.paramant.app',
    'iot':     'https://iot.paramant.app',
    'legal':   'https://legal.paramant.app',
    'finance': 'https://finance.paramant.app',
    'relay':   'https://relay.paramant.app',
}

# ── Memory zeroization ────────────────────────────────────────────────────────
_ZEROIZE_OK = (sys.implementation.name == 'cpython')

def _zero(b: Optional[bytes]) -> None:
    """Overwrite key material in memory with zeros (CPython best-effort)."""
    if not b or not _ZEROIZE_OK:
        return
    try:
        offset = sys.getsizeof(b) - len(b) - 1
        ctypes.memset(id(b) + offset, 0, len(b))
    except Exception:
        pass

# ── Exceptions ────────────────────────────────────────────────────────────────

class GhostPipeError(Exception):
    """Base exception for all PARAMANT SDK errors."""

class RelayError(GhostPipeError):
    """Relay returned an unexpected error response."""
    def __init__(self, status: int, body: str):
        self.status = status
        self.body = body
        super().__init__(f'Relay HTTP {status}: {body[:200]}')

class AuthError(GhostPipeError):
    """Invalid or missing API key."""

class BurnedError(GhostPipeError):
    """Blob has already been retrieved (burn-on-read) or expired."""

class FingerprintMismatchError(GhostPipeError):
    """Stored TOFU fingerprint differs from relay-returned value.
    Possible relay MITM or legitimate key rotation.
    """
    def __init__(self, device_id: str, stored: str, received: str):
        self.device_id = device_id
        self.stored    = stored
        self.received  = received
        super().__init__(
            f'\n  ⚠  FINGERPRINT MISMATCH — device: {device_id}\n'
            f'  Stored:   {stored}\n'
            f'  Received: {received}\n'
            f'  Run gp.trust("{device_id}") after out-of-band verification.\n'
        )

class LicenseError(GhostPipeError):
    """License limit reached (key limit, plan restriction, etc.)."""

class RateLimitError(GhostPipeError):
    """Too many requests — relay rate limited this request."""

# ── BIP39 helpers ─────────────────────────────────────────────────────────────

def _bip39_encode(entropy: bytes) -> str:
    try:
        from mnemonic import Mnemonic
        return Mnemonic('english').to_mnemonic(entropy)
    except ImportError:
        raise GhostPipeError('pip install mnemonic (required for drop/pickup)')

def _bip39_decode(phrase: str) -> bytes:
    try:
        from mnemonic import Mnemonic
        m = Mnemonic('english')
        if not m.check(phrase):
            raise GhostPipeError('Invalid BIP39 mnemonic (checksum error)')
        return bytes(m.to_entropy(phrase))
    except ImportError:
        raise GhostPipeError('pip install mnemonic (required for drop/pickup)')

def _derive_drop_keys(entropy: bytes):
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

# ── Fingerprint ───────────────────────────────────────────────────────────────

def _compute_fingerprint(kyber_pub_hex: str, ecdh_pub_hex: str) -> str:
    """SHA-256(kyber_pub_bytes || ecdh_pub_bytes) → first 10 bytes → XXXX-XXXX-XXXX-XXXX-XXXX.
    Consistent with parashare.html and ontvang.html browser implementation.
    """
    buf = bytes.fromhex(kyber_pub_hex or '') + bytes.fromhex(ecdh_pub_hex or '')
    h = hashlib.sha256(buf).hexdigest()[:20].upper()
    return f'{h[0:4]}-{h[4:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}'

# ── Main SDK class ────────────────────────────────────────────────────────────

class GhostPipe:
    """PARAMANT Ghost Pipe client.

    Post-quantum end-to-end encrypted file transport.
    The relay never sees plaintext, keys, or pre-shared secrets.

    Args:
        api_key:             pgp_... API key from paramant.app/dashboard
        device:              Unique device identifier (same for sender & receiver)
        relay:               Relay base URL. Auto-detected from api_key if omitted.
                             For self-hosted: 'http://your-server:3000'
        pre_shared_secret:   Optional PSS — added to HKDF IKM. Both sides must use
                             the same secret. Protects even if relay is compromised.
        verify_fingerprints: Enable TOFU fingerprint verification (default True).
        timeout:             HTTP request timeout in seconds (default 30).

    Example:
        gp = GhostPipe(api_key='pgp_...', device='my-device')
        hash_ = gp.send(b'secret data')
        data  = gp.receive(hash_)

        # Self-hosted relay
        gp = GhostPipe(api_key='pgp_...', device='my-device',
                       relay='http://192.168.1.100:3000')
    """

    def __init__(
        self,
        api_key: str,
        device: str,
        relay: str = '',
        pre_shared_secret: str = '',
        verify_fingerprints: bool = True,
        timeout: int = 30,
    ):
        if not api_key.startswith('pgp_'):
            raise AuthError('API key must start with pgp_')
        self.api_key              = api_key
        self.device               = device
        self.pre_shared_secret    = pre_shared_secret
        self.verify_fingerprints  = verify_fingerprints
        self.timeout              = timeout
        self.relay                = relay or self._detect_relay()
        if not self.relay:
            raise RelayError(0, 'No reachable relay found. Check api_key or set relay= explicitly.')
        self._keypair = None

    # ── Relay detection ───────────────────────────────────────────────────────

    def _detect_relay(self) -> Optional[str]:
        """Try all sector relays in order, return first that validates api_key."""
        for url in SECTOR_RELAYS.values():
            try:
                r = urllib.request.urlopen(
                    urllib.request.Request(
                        f'{url}/v2/check-key?k={self.api_key}',
                        headers={'User-Agent': UA}
                    ), timeout=4)
                if json.loads(r.read()).get('valid'):
                    return url
            except Exception:
                pass
        return None

    # ── HTTP helpers with retry ───────────────────────────────────────────────

    def _request(
        self,
        method: str,
        path: str,
        body: Optional[bytes] = None,
        content_type: str = 'application/json',
        params: Optional[Dict] = None,
        extra_headers: Optional[Dict] = None,
        retries: int = 3,
        raw_response: bool = False,
    ):
        """Execute HTTP request with exponential backoff retry.

        Returns (status_code, response_bytes).
        Raises RelayError / AuthError / RateLimitError on persistent failure.
        """
        url = self.relay + path
        if params:
            url += '?' + urllib.parse.urlencode(params)
        headers = {'User-Agent': UA, 'X-Api-Key': self.api_key}
        if body is not None:
            headers['Content-Type'] = content_type
        if extra_headers:
            headers.update(extra_headers)

        for attempt in range(retries):
            req = urllib.request.Request(url, data=body, method=method, headers=headers)
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as r:
                    return r.status, r.read()
            except urllib.error.HTTPError as e:
                status = e.code
                body_bytes = e.read()
                if status == 401 or status == 403:
                    raise AuthError(f'HTTP {status}: {body_bytes.decode()[:200]}')
                if status == 402:
                    raise LicenseError(f'License limit reached: {body_bytes.decode()[:200]}')
                if status == 404:
                    return 404, body_bytes
                if status == 409:
                    return 409, body_bytes
                if status == 410:
                    raise BurnedError(f'Blob burned or expired: {body_bytes.decode()[:100]}')
                if status == 429:
                    raise RateLimitError(f'Rate limited: {body_bytes.decode()[:100]}')
                if attempt == retries - 1:
                    raise RelayError(status, body_bytes.decode()[:400])
                time.sleep(0.5 * (2 ** attempt))
            except (urllib.error.URLError, OSError) as e:
                if attempt == retries - 1:
                    raise RelayError(0, f'Connection failed: {e}')
                time.sleep(0.5 * (2 ** attempt))

    def _get(self, path: str, params: Dict = None, **kw):
        return self._request('GET', path, params=params, **kw)

    def _post(self, path: str, data: dict, **kw):
        return self._request('POST', path, body=json.dumps(data).encode(), **kw)

    def _delete(self, path: str, **kw):
        return self._request('DELETE', path, **kw)

    # ── Keypair management ────────────────────────────────────────────────────

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

    def _load_keypair(self) -> dict:
        """Load or generate ECDH + ML-KEM-768 keypair for this device."""
        if self._keypair:
            return self._keypair
        state_dir = os.path.expanduser('~/.paramant')
        path = os.path.join(state_dir, self.device.replace('/', '_') + '.keypair.json')
        if os.path.exists(path):
            self._keypair = json.load(open(path))
            return self._keypair
        c = self._get_crypto()
        K = self._try_kyber()
        be = c['be']()
        os.makedirs(state_dir, exist_ok=True)
        priv = c['gen'](c['curve'](), be)
        pub  = priv.public_key()
        pd   = priv.private_bytes(c['Enc'].DER, c['Priv'].PKCS8, c['NoEnc']())
        pubd = pub.public_bytes(c['Enc'].DER, c['Pub'].SubjectPublicKeyInfo)
        kpub = b''; kpriv = b''
        if K:
            kpub, kpriv = K.keygen()
        kp = {
            'device':     self.device,
            'ecdh_priv':  pd.hex(),
            'ecdh_pub':   pubd.hex(),
            'kyber_pub':  kpub.hex() if kpub else '',
            'kyber_priv': kpriv.hex() if kpriv else '',
        }
        with open(path, 'w') as f:
            json.dump(kp, f)
        os.chmod(path, 0o600)
        self._keypair = kp
        return kp

    # ── TOFU known-keys ───────────────────────────────────────────────────────

    @staticmethod
    def _known_keys_path() -> str:
        return os.path.join(os.path.expanduser('~/.paramant'), 'known_keys')

    def _load_known_keys(self) -> dict:
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
                    result[parts[0]] = {
                        'fingerprint':   parts[1],
                        'registered_at': parts[2] if len(parts) > 2 else '',
                    }
        return result

    def _save_known_key(self, device_id: str, fingerprint: str, registered_at: str = ''):
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
        if device_id not in keys:
            return
        del keys[device_id]
        tmp = self._known_keys_path() + '.tmp'
        with open(tmp, 'w') as f:
            f.write('# PARAMANT known-keys — Trust On First Use (TOFU)\n')
            f.write('# Format: device_id fingerprint registered_at\n')
            for did, v in keys.items():
                f.write(f'{did} {v["fingerprint"]} {v["registered_at"]}\n')
        os.chmod(tmp, 0o600)
        os.replace(tmp, self._known_keys_path())

    def _tofu_check(self, device_id: str, kyber_pub_hex: str, ecdh_pub_hex: str,
                    registered_at: str = '') -> str:
        """Verify or store fingerprint for device. Returns fingerprint string.

        Raises:
            FingerprintMismatchError: stored fingerprint differs from current relay value.
        """
        fp = _compute_fingerprint(kyber_pub_hex, ecdh_pub_hex)
        if not self.verify_fingerprints:
            return fp
        keys = self._load_known_keys()
        if device_id in keys:
            stored = keys[device_id]['fingerprint']
            if stored.replace('-', '').upper() != fp.replace('-', '').upper():
                raise FingerprintMismatchError(device_id, stored, fp)
        else:
            self._save_known_key(device_id, fp, registered_at)
            print(f'[paramant] New device: {device_id}')
            print(f'           Fingerprint: {fp}')
            print(f'           Verify out-of-band before trusting sensitive transfers.')
        return fp

    # ── Encryption / decryption ───────────────────────────────────────────────

    def _fetch_pubkeys(self, device_id: str):
        """Fetch public keys for device. Returns (ecdh_pub_obj, kyber_pub_bytes, ecdh_hex, kyber_hex, registered_at)."""
        status, body = self._get(f'/v2/pubkey/{device_id}')
        if status == 404:
            raise GhostPipeError(
                f'No pubkeys for device {device_id!r}. '
                f'Call receive_setup() on the receiver first.'
            )
        d = json.loads(body)
        c = self._get_crypto()
        ecdh_pub  = c['lpub'](bytes.fromhex(d['ecdh_pub']), c['be']())
        kyber_pub = bytes.fromhex(d['kyber_pub']) if d.get('kyber_pub') else None
        return ecdh_pub, kyber_pub, d['ecdh_pub'], d.get('kyber_pub', ''), d.get('registered_at', '')

    def _encrypt(self, data: bytes, ecdh_pub, kyber_pub, pad_block: int = None,
                 pss: str = '') -> tuple:
        """Encrypt with ML-KEM-768 + ECDH P-256 + AES-256-GCM + optional PSS."""
        c  = self._get_crypto()
        K  = self._try_kyber()
        be = c['be']()
        ecdh_ss = kss = ikm = ss = pss_hash = None
        try:
            eph     = c['gen'](c['curve'](), be)
            ecdh_ss = eph.exchange(c['ECDH'](), ecdh_pub)
            eph_b   = eph.public_key().public_bytes(c['Enc'].DER, c['Pub'].SubjectPublicKeyInfo)
            kct = b''
            kss = b''
            if K and kyber_pub:
                try:
                    kct, kss = K.enc(kyber_pub)
                except Exception:
                    pass
            pss_hash = hashlib.sha3_256(pss.encode('utf-8')).digest() if pss else b''
            ikm  = ecdh_ss + kss + pss_hash
            salt = kct[:32] if kct else ecdh_ss[:32]
            ss   = c['HKDF'](algorithm=c['hsh'].SHA256(), length=32,
                             salt=salt, info=b'aes-key', backend=be).derive(ikm)
            nonce  = os.urandom(12)
            aad    = b'\x02\x00\x00\x00\x00'
            ct     = c['AES'](ss).encrypt(nonce, data, aad)
            bundle = struct.pack('>I', len(eph_b)) + eph_b + struct.pack('>I', len(kct)) + kct
            packet = struct.pack('>I', len(bundle)) + bundle + nonce + struct.pack('>I', len(ct)) + ct
            target = pad_block or BLOCK_5M
            if len(packet) > target:
                raise GhostPipeError(f'Data too large: {len(data)} bytes exceeds block size {target}')
            return packet + os.urandom(target - len(packet)), hashlib.sha256(packet + os.urandom(target - len(packet))).hexdigest(), bool(kct)
        finally:
            for b in (ecdh_ss, kss, ikm, ss, pss_hash):
                if b:
                    _zero(b)

    def _encrypt_fixed(self, data: bytes, ecdh_pub, kyber_pub, pad_block: int = None, pss: str = ''):
        """Same as _encrypt but computes hash after padding is applied."""
        c  = self._get_crypto()
        K  = self._try_kyber()
        be = c['be']()
        ecdh_ss = kss = ikm = ss = pss_hash = None
        try:
            eph     = c['gen'](c['curve'](), be)
            ecdh_ss = eph.exchange(c['ECDH'](), ecdh_pub)
            eph_b   = eph.public_key().public_bytes(c['Enc'].DER, c['Pub'].SubjectPublicKeyInfo)
            kct = b''
            kss = b''
            if K and kyber_pub:
                try:
                    kct, kss = K.enc(kyber_pub)
                except Exception:
                    pass
            pss_hash = hashlib.sha3_256(pss.encode('utf-8')).digest() if pss else b''
            ikm  = ecdh_ss + kss + pss_hash
            salt = kct[:32] if kct else ecdh_ss[:32]
            ss   = c['HKDF'](algorithm=c['hsh'].SHA256(), length=32,
                             salt=salt, info=b'aes-key', backend=be).derive(ikm)
            nonce  = os.urandom(12)
            aad    = b'\x02\x00\x00\x00\x00'
            ct     = c['AES'](ss).encrypt(nonce, data, aad)
            bundle = struct.pack('>I', len(eph_b)) + eph_b + struct.pack('>I', len(kct)) + kct
            packet = struct.pack('>I', len(bundle)) + bundle + nonce + struct.pack('>I', len(ct)) + ct
            target = pad_block or BLOCK_5M
            if len(packet) > target:
                raise GhostPipeError(f'Data too large: {len(data)} bytes exceeds block size {target}')
            blob = packet + os.urandom(target - len(packet))
            return blob, hashlib.sha256(blob).hexdigest(), bool(kct)
        finally:
            for b in (ecdh_ss, kss, ikm, ss, pss_hash):
                if b:
                    _zero(b)

    def _decrypt(self, blob: bytes, pss: str = '') -> bytes:
        """Decrypt Ghost Pipe blob. PSS must match what sender used."""
        c  = self._get_crypto()
        K  = self._try_kyber()
        be = c['be']()
        kp = self._load_keypair()
        o  = 0
        blen  = struct.unpack('>I', blob[o:o+4])[0]; o += 4
        bun   = blob[o:o+blen];                       o += blen
        bo    = 0
        eplen = struct.unpack('>I', bun[bo:bo+4])[0]; bo += 4
        epb   = bun[bo:bo+eplen];                     bo += eplen
        klen  = struct.unpack('>I', bun[bo:bo+4])[0]; bo += 4
        kct   = bun[bo:bo+klen]
        nonce = blob[o:o+12];                          o += 12
        ctlen = struct.unpack('>I', blob[o:o+4])[0];   o += 4
        ct    = blob[o:o+ctlen]
        ecdh_ss = kss = ikm = ss = pss_hash = None
        try:
            priv    = c['lpriv'](bytes.fromhex(kp['ecdh_priv']), None, be)
            ecdh_ss = priv.exchange(c['ECDH'](), c['lpub'](epb, be))
            kss = b''
            if K and kct and kp.get('kyber_priv'):
                try:
                    kss = K.dec(bytes.fromhex(kp['kyber_priv']), kct)
                except Exception:
                    pass
            pss_hash = hashlib.sha3_256(pss.encode('utf-8')).digest() if pss else b''
            ikm  = ecdh_ss + kss + pss_hash
            salt = kct[:32] if kct else ecdh_ss[:32]
            ss   = c['HKDF'](algorithm=c['hsh'].SHA256(), length=32,
                             salt=salt, info=b'aes-key', backend=be).derive(ikm)
            aad  = b'\x02\x00\x00\x00\x00'
            return c['AES'](ss).decrypt(nonce, ct, aad)
        finally:
            for b in (ecdh_ss, kss, ikm, ss, pss_hash):
                if b:
                    _zero(b)

    # ── Pubkey registration ───────────────────────────────────────────────────

    def register_pubkeys(self) -> dict:
        """Register ML-KEM-768 + ECDH P-256 public keys with the relay.

        Call this once before a receiver can accept transfers. The keys are
        stored in ~/.paramant/<device>.keypair.json and never leave your machine
        in private form.

        Returns:
            dict: {'ok': True, 'fingerprint': '...', 'ct_index': 42, ...}

        Raises:
            AuthError: Invalid API key.
            LicenseError: Device limit reached for your plan.
            RelayError: Unexpected relay error.

        Example:
            gp = GhostPipe(api_key='pgp_...', device='pacs-001')
            result = gp.register_pubkeys()
            print(f"Fingerprint: {result['fingerprint']}")
        """
        kp   = self._load_keypair()
        status, body = self._post('/v2/pubkey', {
            'device_id': self.device,
            'ecdh_pub':  kp['ecdh_pub'],
            'kyber_pub': kp.get('kyber_pub', ''),
        })
        if status not in (200, 409):
            raise RelayError(status, body.decode()[:400])
        return json.loads(body)

    # Alias for backward compatibility
    receive_setup = register_pubkeys

    # ── Core transfer ─────────────────────────────────────────────────────────

    def send(
        self,
        data: bytes,
        recipient: Optional[str] = None,
        ttl: int = 3600,
        max_views: int = 1,
        pad_block: int = BLOCK_5M,
        pre_shared_secret: str = '',
    ) -> str:
        """Encrypt and upload data to the relay. Returns a burn-on-read hash.

        The relay stores only ciphertext. After one download, the blob is
        permanently deleted. The relay never sees plaintext or private keys.

        Args:
            data:              Bytes to send (any format: PDF, DICOM, binary, etc.)
            recipient:         Device ID of receiver. Defaults to self.device.
            ttl:               Seconds until relay deletes the blob (default 3600).
            max_views:         Max downloads before burn (default 1).
            pad_block:         Padding block size in bytes (default 5 MB).
            pre_shared_secret: Optional PSS — must match what receiver uses in receive().
                               Protects even if relay serves a wrong pubkey.

        Returns:
            str: SHA-256 hash — pass this to the receiver for download.

        Raises:
            FingerprintMismatchError: Receiver's key changed since last contact.
            AuthError: Invalid API key.
            RelayError: Upload failed.

        Example:
            h = gp.send(b'sensitive data', recipient='pacs-001')
            print(f'Give to receiver: {h}')

            # With pre-shared secret (highest security):
            h = gp.send(data, recipient='pacs-001', pre_shared_secret='agreed-secret')
        """
        target    = recipient or self.device
        pss_value = pre_shared_secret or self.pre_shared_secret
        ecdh_pub, kyber_pub, ecdh_hex, kyber_hex, reg_at = self._fetch_pubkeys(target)
        self._tofu_check(target, kyber_hex, ecdh_hex, reg_at)
        blob, h, _ = self._encrypt_fixed(data, ecdh_pub, kyber_pub,
                                          pad_block=pad_block, pss=pss_value)
        status, body = self._post('/v2/inbound', {
            'hash':      h,
            'payload':   base64.b64encode(blob).decode(),
            'ttl_ms':    ttl * 1000,
            'max_views': max_views,
            'meta':      {'device_id': self.device},
        })
        if status != 200:
            raise RelayError(status, body.decode()[:400])
        d = json.loads(body)
        if not d.get('ok'):
            raise RelayError(status, body.decode()[:400])
        return h

    def receive(self, hash_: str, pre_shared_secret: str = '') -> bytes:
        """Download and decrypt a blob. Burn-on-read: works exactly once.

        Args:
            hash_:             SHA-256 hash returned by sender's send() call.
            pre_shared_secret: Must match what sender used in send().

        Returns:
            bytes: Decrypted plaintext.

        Raises:
            BurnedError: Blob already retrieved or expired.
            GhostPipeError: Decryption failed (wrong PSS or corrupted blob).

        Example:
            data = gp.receive('a3f2...')
            open('output.pdf', 'wb').write(data)
        """
        pss_value = pre_shared_secret or self.pre_shared_secret
        status, raw = self._get(f'/v2/outbound/{hash_}')
        if status == 404:
            raise BurnedError('Blob not found: expired, already retrieved, or never stored.')
        if status != 200:
            raise RelayError(status, raw.decode()[:400])
        return self._decrypt(raw, pss=pss_value)

    def status(self, hash_: str) -> dict:
        """Check whether a blob is still available on the relay.

        Args:
            hash_: SHA-256 hash of the blob.

        Returns:
            dict: {'available': bool, 'bytes': int, 'ttl_remaining_ms': int, 'sig_valid': bool}

        Example:
            s = gp.status('a3f2...')
            if s['available']:
                print(f"Available — {s['ttl_remaining_ms']/1000:.0f}s left")
        """
        _, body = self._get(f'/v2/status/{hash_}')
        return json.loads(body)

    def cancel(self, hash_: str) -> dict:
        """Cancel (delete) a blob before it is retrieved.

        Args:
            hash_: SHA-256 hash of the blob.

        Returns:
            dict: {'ok': True}

        Example:
            gp.cancel('a3f2...')
        """
        status, body = self._delete(f'/v2/inbound/{hash_}')
        return json.loads(body)

    # ── Anonymous drop (BIP39 mnemonic) ───────────────────────────────────────

    def drop(self, data: bytes, ttl: int = 3600, pad_block: int = BLOCK_5M) -> str:
        """Send data anonymously using a 12-word BIP39 mnemonic as the key.

        No ECDH keypairs needed. The mnemonic IS the shared secret.
        Always burn-on-read (max_views=1). The relay never sees the key.

        Args:
            data:      Bytes to send.
            ttl:       Seconds until relay deletes the blob (default 3600).
            pad_block: Padding block size (default 5 MB).

        Returns:
            str: 12-word BIP39 mnemonic — share this with the receiver out-of-band.

        Raises:
            GhostPipeError: pip install mnemonic required.
            RelayError: Upload failed.

        Example:
            mnemonic = gp.drop(open('report.pdf', 'rb').read())
            print(f'Mnemonic: {mnemonic}')
            # Share mnemonic via Signal, PGP email, or phone
        """
        entropy = os.urandom(16)
        phrase  = _bip39_encode(entropy)
        aes_key, lookup_hash = _derive_drop_keys(entropy)
        try:
            c = self._get_crypto()
            be = c['be']()
            nonce  = os.urandom(12)
            ct     = c['AES'](aes_key).encrypt(nonce, data, None)
            packet = nonce + struct.pack('>I', len(ct)) + ct
            if len(packet) > pad_block:
                raise GhostPipeError(f'Data too large for drop block ({len(data)} bytes)')
            blob = packet + os.urandom(pad_block - len(packet))
            status, body = self._post('/v2/inbound', {
                'hash':      lookup_hash,
                'payload':   base64.b64encode(blob).decode(),
                'ttl_ms':    ttl * 1000,
                'max_views': 1,
                'meta':      {'drop': True},
            })
            if status != 200:
                raise RelayError(status, body.decode()[:400])
            return phrase
        finally:
            _zero(aes_key)
            _zero(entropy)

    def pickup(self, phrase: str) -> bytes:
        """Retrieve a BIP39 drop. Burn-on-read: works exactly once.

        Args:
            phrase: 12-word BIP39 mnemonic (space-separated).

        Returns:
            bytes: Decrypted data.

        Raises:
            BurnedError: Drop not found, expired, or already retrieved.

        Example:
            data = gp.pickup('word1 word2 ... word12')
        """
        entropy = _bip39_decode(phrase.strip())
        aes_key, lookup_hash = _derive_drop_keys(entropy)
        try:
            status, raw = self._get(f'/v2/outbound/{lookup_hash}')
            if status == 404:
                raise BurnedError('Drop not found: expired, already retrieved, or wrong mnemonic.')
            if status != 200:
                raise RelayError(status, raw.decode()[:400])
            nonce  = raw[:12]
            ct_len = struct.unpack('>I', raw[12:16])[0]
            ct     = raw[16:16 + ct_len]
            c = self._get_crypto()
            be = c['be']()
            return c['AES'](aes_key).decrypt(nonce, ct, None)
        finally:
            _zero(aes_key)
            _zero(entropy)

    def drop_status(self, phrase: str) -> dict:
        """Check whether a drop is still available.

        Args:
            phrase: 12-word BIP39 mnemonic.

        Returns:
            dict: {'available': bool, 'ttl_remaining_ms': int} or {'available': False}
        """
        entropy = _bip39_decode(phrase.strip())
        _, lookup_hash = _derive_drop_keys(entropy)
        _, body = self._get(f'/v2/status/{lookup_hash}')
        return json.loads(body)

    # ── Fingerprint & TOFU ────────────────────────────────────────────────────

    def fingerprint(self, device_id: Optional[str] = None) -> str:
        """Fetch and display the fingerprint for a device.

        Use for out-of-band key verification: call or Signal the device owner
        and ask them to read their fingerprint aloud.

        Args:
            device_id: Device to check. Defaults to self.device.

        Returns:
            str: Fingerprint in XXXX-XXXX-XXXX-XXXX-XXXX format.

        Example:
            fp = gp.fingerprint('pacs-001')
            # → Device:      pacs-001
            # → Fingerprint: A3F2-19BE-C441-8D07-F2A0
        """
        target = device_id or self.device
        status, body = self._get(f'/v2/fingerprint/{target}')
        if status == 404:
            raise GhostPipeError(f'No pubkeys registered for device {target!r}')
        d = json.loads(body)
        fp = d.get('fingerprint') or _compute_fingerprint(d.get('kyber_pub', ''), d['ecdh_pub'])
        print(f'Device:       {target}')
        print(f'Fingerprint:  {fp}')
        if d.get('registered_at'):
            print(f'Registered:   {d["registered_at"]}')
        if d.get('ct_index') is not None:
            print(f'CT log index: {d["ct_index"]}')
        return fp

    def verify_fingerprint(self, device_id: str, fingerprint: str) -> bool:
        """Verify a fingerprint against the relay's stored pubkey.

        Args:
            device_id:   Device ID to check.
            fingerprint: Expected fingerprint string (XXXX-XXXX-XXXX-XXXX-XXXX).

        Returns:
            bool: True if match, False if mismatch.

        Example:
            ok = gp.verify_fingerprint('pacs-001', 'A3F2-19BE-C441-8D07-F2A0')
        """
        status, body = self._post('/v2/pubkey/verify', {
            'device_id':   device_id,
            'fingerprint': fingerprint,
        })
        return json.loads(body).get('match', False)

    def trust(self, device_id: str, fingerprint: Optional[str] = None) -> str:
        """Mark a device as trusted in the local known_keys store.

        If fingerprint is omitted, fetches it from the relay.

        Args:
            device_id:   Device to trust.
            fingerprint: Fingerprint to store. If None: fetched from relay.

        Returns:
            str: Stored fingerprint.

        Example:
            gp.trust('pacs-001')           # fetch + store
            gp.trust('pacs-001', 'A3F2-...')  # store specific fingerprint
        """
        if not fingerprint:
            fingerprint = self.fingerprint(device_id)
        self._save_known_key(device_id, fingerprint)
        print(f'[paramant] Trusted: {device_id} ({fingerprint})')
        return fingerprint

    def untrust(self, device_id: str):
        """Remove a device from the local known_keys store.

        Args:
            device_id: Device to remove.
        """
        self._remove_known_key(device_id)
        print(f'[paramant] Removed: {device_id}')

    def known_devices(self) -> List[dict]:
        """List all trusted devices from the local known_keys store.

        Returns:
            list: [{'device_id': '...', 'fingerprint': '...', 'registered_at': '...'}]

        Example:
            for d in gp.known_devices():
                print(d['device_id'], d['fingerprint'])
        """
        keys = self._load_known_keys()
        if not keys:
            print('[paramant] No trusted devices.')
            return []
        print(f'{"Device":<36} {"Fingerprint":<26} {"Registered":<24}')
        print('-' * 88)
        for did, v in keys.items():
            print(f'{did:<36} {v["fingerprint"]:<26} {v["registered_at"]:<24}')
        return [{'device_id': k, **v} for k, v in keys.items()]

    # ── PSS session (relay-mediated pre-shared secret) ────────────────────────

    def session_create(self, pss: str, ttl_ms: int = 600_000) -> dict:
        """Create a PSS session on the relay. Sender creates this.

        The relay stores only SHA-256(pss) — it cannot reconstruct the secret.
        The receiver must join with the same PSS before sender can fetch their pubkeys.

        Args:
            pss:    Pre-shared secret (agreed out-of-band).
            ttl_ms: Session lifetime in ms (60s–1h, default 10min).

        Returns:
            dict: {'ok': True, 'session_id': 'pss_...', 'expires_ms': ..., 'ttl_ms': ...}

        Example:
            sess = gp.session_create('shared-secret-2026')
            print(sess['session_id'])  # share this ID with receiver
        """
        commitment = hashlib.sha256(pss.encode()).hexdigest()
        status, body = self._post('/v2/session/create', {
            'commitment': commitment,
            'ttl_ms':     ttl_ms,
        })
        if status != 200:
            raise RelayError(status, body.decode()[:400])
        return json.loads(body)

    def session_join(self, session_id: str, pss: str) -> dict:
        """Join a PSS session. Receiver calls this.

        Args:
            session_id: Session ID from sender's session_create().
            pss:        Pre-shared secret (must match sender's).

        Returns:
            dict: {'ok': True, 'session_id': '...', 'joined_at': '...'}

        Raises:
            AuthError: PSS mismatch.
        """
        kp = self._load_keypair()
        status, body = self._request('POST', '/v2/session/join', body=json.dumps({
            'session_id': session_id,
            'pss':        pss,
            'ecdh_pub':   kp['ecdh_pub'],
            'kyber_pub':  kp.get('kyber_pub', ''),
        }).encode())
        if status == 403:
            raise AuthError('PSS mismatch: incorrect pre-shared secret')
        if status != 200:
            raise RelayError(status, body.decode()[:400])
        return json.loads(body)

    def session_pubkey(self, session_id: str) -> Optional[dict]:
        """Fetch receiver pubkeys from a PSS session. Sender calls this.

        Returns None if receiver has not joined yet (poll again).

        Args:
            session_id: Session ID from session_create().

        Returns:
            dict or None: {'ecdh_pub': '...', 'kyber_pub': '...', 'joined_at': '...'} or None
        """
        status, body = self._get(f'/v2/session/{session_id}/pubkey')
        if status == 202:
            return None  # Not joined yet
        if status != 200:
            raise RelayError(status, body.decode()[:400])
        return json.loads(body)

    def session_status(self, session_id: str) -> dict:
        """Check whether receiver has joined a PSS session.

        Returns:
            dict: {'ok': True, 'joined': bool, 'expires_ms': ...}
        """
        _, body = self._get(f'/v2/session/{session_id}/status')
        return json.loads(body)

    # ── Webhooks ──────────────────────────────────────────────────────────────

    def webhook_register(self, callback_url: str, secret: str = '') -> dict:
        """Register a webhook for push notifications when a blob arrives.

        The relay POSTs to callback_url with {'hash': '...', 'device_id': '...'}.
        If secret is set, the relay signs the POST body with HMAC-SHA256.

        Args:
            callback_url: Public HTTPS URL to receive notifications.
            secret:       Optional HMAC-SHA256 signing secret.

        Returns:
            dict: {'ok': True}

        Example:
            gp.webhook_register('https://hospital.example/paramant-hook', secret='abc')
        """
        status, body = self._post('/v2/webhook', {
            'device_id': self.device,
            'url':       callback_url,
            'secret':    secret,
        })
        if status != 200:
            raise RelayError(status, body.decode()[:400])
        return json.loads(body)

    # ── Acknowledgment ────────────────────────────────────────────────────────

    def ack(self, hash_: str) -> dict:
        """Acknowledge successful receipt of a blob.

        Args:
            hash_: SHA-256 hash of the blob.

        Returns:
            dict: {'ok': True, 'hash': '...'}
        """
        status, body = self._post('/v2/ack', {'hash': hash_, 'device_id': self.device})
        return json.loads(body)

    # ── WebSocket streaming ───────────────────────────────────────────────────

    def get_ws_ticket(self) -> str:
        """Get a one-time WebSocket ticket (avoids API key in URL).

        Returns:
            str: Ticket string (valid 30 seconds).
        """
        status, body = self._post('/v2/ws-ticket', {})
        if status != 200:
            raise RelayError(status, body.decode()[:400])
        return json.loads(body)['ticket']

    def stream(self, on_blob: Callable[[str], None], auto_receive: bool = False):
        """Listen for new blobs in real-time via WebSocket.

        Requires: pip install websocket-client

        Args:
            on_blob:      Callback(hash: str) — called when a new blob is ready.
            auto_receive: If True, automatically download + decrypt each blob
                          and pass bytes to on_blob instead of hash.

        Example:
            def on_receive(hash_):
                data = gp.receive(hash_)
                print(f'Received {len(data)} bytes')

            gp.stream(on_receive)  # blocks until interrupted
        """
        try:
            import websocket
        except ImportError:
            raise GhostPipeError('pip install websocket-client (required for stream())')
        ticket = self.get_ws_ticket()
        ws_url = self.relay.replace('https://', 'wss://').replace('http://', 'ws://')
        ws_url += f'/v2/stream?ticket={ticket}'

        def on_message(ws, message):
            try:
                d = json.loads(message)
                if d.get('type') == 'blob_ready':
                    h = d.get('hash')
                    if h:
                        if auto_receive:
                            on_blob(self.receive(h))
                        else:
                            on_blob(h)
            except Exception as e:
                print(f'[paramant] stream error: {e}')

        ws = websocket.WebSocketApp(ws_url, on_message=on_message)
        ws.run_forever()

    # ── Polling fallback ──────────────────────────────────────────────────────

    def listen(self, on_receive: Callable, interval: int = 3):
        """Poll relay for new blobs (HTTP fallback when WebSocket is unavailable).

        Args:
            on_receive: callback(data: bytes, meta: dict) — called for each blob.
            interval:   Poll interval in seconds (default 3).

        Example:
            gp.listen(lambda data, meta: print(f'Received {len(data)}B seq={meta["seq"]}'))
        """
        self.register_pubkeys()
        seq = self._load_seq()
        while True:
            try:
                _, body = self._get('/v2/stream-next',
                                    {'device': self.device, 'seq': seq})
                d = json.loads(body)
                if d.get('available'):
                    next_seq = d.get('seq', seq + 1)
                    try:
                        data = self.receive(d['hash'])
                        seq  = next_seq
                        self._save_seq(seq)
                        on_receive(data, {'seq': seq, 'hash': d['hash']})
                        continue
                    except (BurnedError, GhostPipeError):
                        seq = next_seq
            except Exception:
                pass
            time.sleep(interval)

    def _load_seq(self) -> int:
        try:
            p = os.path.join(os.path.expanduser('~/.paramant'),
                             self.device.replace('/', '_') + '.sdk_seq')
            return int(open(p).read())
        except Exception:
            return 0

    def _save_seq(self, seq: int):
        d = os.path.expanduser('~/.paramant')
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, self.device.replace('/', '_') + '.sdk_seq')
        open(p + '.tmp', 'w').write(str(seq))
        os.replace(p + '.tmp', p)

    # ── Health & monitoring ───────────────────────────────────────────────────

    def health(self) -> dict:
        """Relay health check.

        Returns:
            dict: {'ok': True, 'version': '2.4.1', 'sector': '...', 'edition': '...', ...}
        """
        _, body = self._request('GET', '/health')
        return json.loads(body)

    def monitor(self) -> dict:
        """Relay monitoring stats for your API key.

        Returns:
            dict: {'ok': True, 'plan': '...', 'blobs_in_flight': N, 'delivery': {...}, ...}
        """
        _, body = self._get('/v2/monitor')
        return json.loads(body)

    def check_key(self) -> dict:
        """Validate this API key and return plan info.

        Returns:
            dict: {'valid': True, 'plan': 'pro'}
        """
        _, body = self._get('/v2/check-key')
        return json.loads(body)

    def key_sector(self) -> dict:
        """Return sector and team info for this API key.

        Returns:
            dict: {'sector': '...', 'plan': '...', 'team_id': '...'}
        """
        _, body = self._get('/v2/key-sector')
        return json.loads(body)

    # ── Audit log ────────────────────────────────────────────────────────────

    def audit(self, limit: int = 100, fmt: str = 'json') -> Union[list, str]:
        """Fetch audit log for this API key.

        Args:
            limit: Max entries (default 100, max 1000).
            fmt:   'json' or 'csv'.

        Returns:
            list (json) or str (csv).

        Example:
            for e in gp.audit(limit=50):
                print(e['ts'], e['event'], e.get('hash',''))
        """
        _, body = self._get('/v2/audit', {'limit': limit, 'format': fmt})
        if fmt == 'csv':
            return body.decode()
        return json.loads(body).get('entries', [])

    # ── CT Log ────────────────────────────────────────────────────────────────

    def ct_log(self, from_index: int = 0, limit: int = 100) -> dict:
        """Fetch Certificate Transparency log entries.

        Args:
            from_index: Start index (default 0).
            limit:      Max entries (default 100, max 1000).

        Returns:
            dict: {'ok': True, 'size': N, 'root': '...', 'entries': [...]}
        """
        _, body = self._get('/v2/ct', {'from': from_index, 'limit': limit})
        return json.loads(body)

    def ct_proof(self, index: int) -> dict:
        """Get Merkle inclusion proof for a CT log entry.

        Args:
            index: CT log index.

        Returns:
            dict: {'ok': True, 'index': N, 'leaf_hash': '...', 'proof': [...]}
        """
        _, body = self._get(f'/v2/ct/{index}')
        return json.loads(body)

    # ── DID ───────────────────────────────────────────────────────────────────

    def did_register(self, dsa_pub: str = '') -> dict:
        """Register a DID (Decentralized Identifier) for this device.

        Associates device_id + ecdh_pub + kyber_pub with a did:paramant:... identifier.
        CT log entry created at registration time.

        Args:
            dsa_pub: Optional ML-DSA-65 public key for signature verification.

        Returns:
            dict: {'ok': True, 'did': 'did:paramant:...', 'document': {...}, 'ct_index': N}
        """
        kp = self._load_keypair()
        status, body = self._post('/v2/did/register', {
            'device_id': self.device,
            'ecdh_pub':  kp['ecdh_pub'],
            'kyber_pub': kp.get('kyber_pub', ''),
            'dsa_pub':   dsa_pub,
        })
        if status != 200:
            raise RelayError(status, body.decode()[:400])
        return json.loads(body)

    def did_resolve(self, did: str) -> dict:
        """Resolve a DID document.

        Args:
            did: DID string (did:paramant:...)

        Returns:
            dict: DID document.
        """
        status, body = self._request('GET', f'/v2/did/{did}')
        if status == 404:
            raise GhostPipeError(f'DID not found: {did}')
        return json.loads(body)

    def did_list(self) -> list:
        """List all DIDs registered by this API key.

        Returns:
            list: [{'did': '...', 'device': '...', 'ts': '...'}]
        """
        _, body = self._get('/v2/did')
        return json.loads(body).get('dids', [])

    # ── Attestation ───────────────────────────────────────────────────────────

    def attest(self, attestation: dict) -> dict:
        """Submit hardware attestation for this device.

        Args:
            attestation: dict with 'method' ('tpm2', 'apple', 'software') and method-specific fields.

        Returns:
            dict: Attestation verification result.
        """
        status, body = self._post('/v2/attest', {
            'device_id':   self.device,
            'attestation': attestation,
        })
        return json.loads(body)

    def attestation_status(self, device_id: Optional[str] = None) -> dict:
        """Get attestation status for a device.

        Args:
            device_id: Device to check. Defaults to self.device.
        """
        target = device_id or self.device
        _, body = self._get(f'/v2/attest/{target}')
        return json.loads(body)

    # ── Team management ───────────────────────────────────────────────────────

    def team_devices(self) -> dict:
        """List all devices in your team.

        Returns:
            dict: {'team_id': '...', 'devices': [...], 'count': N}
        """
        _, body = self._get('/v2/team/devices')
        return json.loads(body)

    def team_add_device(self, label: str) -> dict:
        """Add a new device key to your team (Pro/Enterprise).

        Args:
            label: Human-readable device label.

        Returns:
            dict: {'ok': True, 'key': 'pgp_...', 'label': '...', 'team_id': '...'}
        """
        status, body = self._post('/v2/team/add-device', {'label': label})
        if status != 200:
            raise RelayError(status, body.decode()[:400])
        return json.loads(body)

    # ── Admin access ──────────────────────────────────────────────────────────

    def admin(self, token: str) -> 'GhostPipeAdmin':
        """Return an admin client for this relay.

        Args:
            token: Admin token (set in ADMIN_TOKEN env var on relay).

        Returns:
            GhostPipeAdmin: Admin client.

        Example:
            admin = gp.admin('my-admin-token')
            keys  = admin.keys()
        """
        return GhostPipeAdmin(relay=self.relay, token=token, timeout=self.timeout)


# ── Admin client ──────────────────────────────────────────────────────────────

class GhostPipeAdmin:
    """Admin client for relay management operations.

    Requires ADMIN_TOKEN set on the relay.

    Example:
        admin = gp.admin('my-admin-token')
        print(admin.stats())
    """

    def __init__(self, relay: str, token: str, timeout: int = 30):
        self.relay   = relay
        self.token   = token
        self.timeout = timeout

    def _request(self, method: str, path: str, body: Optional[bytes] = None,
                 params: Optional[Dict] = None):
        url = self.relay + path
        if params:
            url += '?' + urllib.parse.urlencode(params)
        headers = {
            'User-Agent':    UA,
            'X-Admin-Token': self.token,
            'Authorization': f'Bearer {self.token}',
        }
        if body is not None:
            headers['Content-Type'] = 'application/json'
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            if e.code == 401:
                raise AuthError('Invalid ADMIN_TOKEN')
            return e.code, e.read()

    def _get(self, path, params=None):
        return self._request('GET', path, params=params)

    def _post(self, path, data):
        return self._request('POST', path, body=json.dumps(data).encode())

    def stats(self) -> dict:
        """Full relay health + stats (admin view).

        Returns:
            dict: Full health response including RAM, keys, editions, etc.
        """
        _, body = self._get('/health')
        return json.loads(body)

    def keys(self) -> dict:
        """List all API keys.

        Returns:
            dict: {'ok': True, 'count': N, 'keys': [...], 'license': {...}}
        """
        _, body = self._get('/v2/admin/keys')
        return json.loads(body)

    def key_add(self, label: str = '', plan: str = 'pro', email: str = '') -> dict:
        """Create a new API key.

        Args:
            label: Human-readable label.
            plan:  'pro' or 'enterprise'.
            email: Optional email for welcome message.

        Returns:
            dict: {'ok': True, 'key': 'pgp_...', 'plan': '...', 'label': '...'}

        Raises:
            LicenseError: Key limit reached.
        """
        status, body = self._post('/v2/admin/keys', {
            'label': label, 'plan': plan, 'email': email,
        })
        if status == 402:
            raise LicenseError(f'Key limit reached: {body.decode()[:200]}')
        if status != 200:
            raise RelayError(status, body.decode()[:400])
        return json.loads(body)

    def key_revoke(self, key: str) -> dict:
        """Revoke an API key.

        Args:
            key: pgp_... key to revoke.

        Returns:
            dict: {'ok': True}
        """
        status, body = self._post('/v2/admin/keys/revoke', {'key': key})
        if status == 404:
            raise GhostPipeError(f'Key not found: {key}')
        return json.loads(body)

    def license_status(self) -> dict:
        """Return license and edition info.

        Returns:
            dict: {'edition': '...', 'active_keys': N, 'key_limit': N, 'license_expires': '...'}
        """
        _, body = self._get('/health')
        d = json.loads(body)
        return {
            'edition':         d.get('edition'),
            'active_keys':     d.get('active_keys'),
            'key_limit':       d.get('key_limit'),
            'license_expires': d.get('license_expires'),
            'license_issued_to': d.get('license_issued_to'),
        }

    def reload(self) -> dict:
        """Reload API keys from users.json without restart (zero-downtime).

        Returns:
            dict: {'ok': True, 'loaded': N}
        """
        status, body = self._post('/v2/reload-users', {})
        return json.loads(body)

    def send_welcome(self, email: str, key: str, plan: str = 'pro', label: str = '') -> dict:
        """Send welcome email with API key via Resend.

        Args:
            email: Recipient email address.
            key:   pgp_... API key to include.
            plan:  Plan name.
            label: Optional key label.

        Returns:
            dict: {'ok': True, 'id': '...'}
        """
        status, body = self._post('/v2/admin/send-welcome', {
            'email': email, 'key': key, 'plan': plan, 'label': label,
        })
        return json.loads(body)


# ── Multi-relay cluster ───────────────────────────────────────────────────────

class GhostPipeCluster:
    """Multi-relay client with automatic failover.

    Example:
        cluster = GhostPipeCluster(
            api_key='pgp_xxx', device='mri-001',
            relays=['https://health.paramant.app', 'https://iot.paramant.app']
        )
        h = cluster.send(data)
    """

    def __init__(self, api_key: str, device: str, relays: list,
                 health_interval: int = 30, **kwargs):
        self.api_key  = api_key
        self.device   = device
        self.relays   = relays
        self._healthy = {}
        self._active  = None
        self._lock    = __import__('threading').Lock()
        self._kwargs  = kwargs
        import threading
        threading.Thread(target=self._monitor, daemon=True).start()
        time.sleep(1)

    def _check(self, relay):
        try:
            r = urllib.request.urlopen(
                urllib.request.Request(f'{relay}/health', headers={'User-Agent': UA}), timeout=5)
            d = json.loads(r.read())
            return d.get('ok', False)
        except Exception:
            return False

    def _monitor(self):
        while True:
            for relay in self.relays:
                ok = self._check(relay)
                with self._lock:
                    self._healthy[relay] = ok
            for relay in self.relays:
                if self._healthy.get(relay):
                    with self._lock:
                        self._active = relay
                    break
            time.sleep(30)

    def _client(self):
        with self._lock:
            relay = self._active
        if not relay:
            raise RelayError(0, 'No healthy relay available')
        return GhostPipe(self.api_key, self.device, relay=relay, **self._kwargs)

    def send(self, data: bytes, **kwargs) -> str:
        for relay in self.relays:
            if not self._healthy.get(relay):
                continue
            try:
                return GhostPipe(self.api_key, self.device, relay=relay, **self._kwargs).send(data, **kwargs)
            except (RelayError, GhostPipeError):
                with self._lock:
                    self._healthy[relay] = False
        raise RelayError(0, 'All relays failed')

    def receive(self, hash_: str, **kwargs) -> bytes:
        for relay in self.relays:
            try:
                gp = GhostPipe(self.api_key, self.device, relay=relay, **self._kwargs)
                if gp.status(hash_).get('available'):
                    return gp.receive(hash_, **kwargs)
            except Exception:
                pass
        raise BurnedError(f'Blob {hash_[:12]}... not found on any relay')

    def health(self) -> dict:
        with self._lock:
            return {'active': self._active, 'nodes': dict(self._healthy)}


# ── CLI entry point ───────────────────────────────────────────────────────────

if __name__ == '__main__':
    import argparse

    p = argparse.ArgumentParser(description=f'PARAMANT Ghost Pipe SDK v{__version__}')
    p.add_argument('action', choices=[
        'send', 'receive', 'status', 'cancel', 'listen', 'health', 'audit',
        'drop', 'pickup', 'fingerprint', 'known-devices', 'trust', 'untrust',
        'ct-log', 'did-register', 'monitor', 'check-key',
    ])
    p.add_argument('--key',       required=True,  help='pgp_... API key')
    p.add_argument('--device',    default='cli',  help='Device ID')
    p.add_argument('--relay',     default='',     help='Relay URL (auto-detect if omitted)')
    p.add_argument('--hash',      default='',     help='SHA-256 hash')
    p.add_argument('--file',      default='',     help='Input/output file path')
    p.add_argument('--output',    default='',     help='Output file for receive')
    p.add_argument('--mnemonic',  default='',     help='BIP39 mnemonic (pickup)')
    p.add_argument('--recipient', default='',     help='Recipient device ID')
    p.add_argument('--ttl',       type=int, default=3600)
    p.add_argument('--pss',       default='',     help='Pre-shared secret')
    p.add_argument('--no-tofu',   action='store_true', help='Disable TOFU checks')
    a = p.parse_args()

    gp = GhostPipe(a.key, a.device, relay=a.relay,
                   pre_shared_secret=a.pss,
                   verify_fingerprints=not a.no_tofu)

    if a.action == 'send':
        data = open(a.file, 'rb').read() if a.file else sys.stdin.buffer.read()
        gp.register_pubkeys()
        h = gp.send(data, recipient=a.recipient or None, ttl=a.ttl)
        print(f'hash={h}')

    elif a.action == 'receive':
        if not a.hash: sys.exit('--hash required')
        data = gp.receive(a.hash)
        if a.output:
            open(a.output, 'wb').write(data)
            print(f'saved to {a.output} ({len(data)} bytes)')
        else:
            sys.stdout.buffer.write(data)

    elif a.action == 'status':
        if not a.hash: sys.exit('--hash required')
        print(json.dumps(gp.status(a.hash), indent=2))

    elif a.action == 'cancel':
        if not a.hash: sys.exit('--hash required')
        print(json.dumps(gp.cancel(a.hash), indent=2))

    elif a.action == 'drop':
        data = open(a.file, 'rb').read() if a.file else sys.stdin.buffer.read()
        phrase = gp.drop(data, ttl=a.ttl)
        print(f'mnemonic={phrase}')

    elif a.action == 'pickup':
        if not a.mnemonic: sys.exit('--mnemonic required')
        data = gp.pickup(a.mnemonic)
        if a.output:
            open(a.output, 'wb').write(data)
            print(f'saved to {a.output} ({len(data)} bytes)')
        else:
            sys.stdout.buffer.write(data)

    elif a.action == 'health':
        print(json.dumps(gp.health(), indent=2))

    elif a.action == 'monitor':
        print(json.dumps(gp.monitor(), indent=2))

    elif a.action == 'check-key':
        print(json.dumps(gp.check_key(), indent=2))

    elif a.action == 'audit':
        for e in gp.audit():
            print(f"{e['ts']}  {e['event']:<20}  {e.get('hash','')[:16]}  {e.get('bytes',0)}B")

    elif a.action == 'ct-log':
        d = gp.ct_log()
        print(f"Size: {d['size']}  Root: {d.get('root','')[:16]}...")
        for e in d.get('entries', [])[:10]:
            print(f"  [{e['index']}] {e['ts']}  {e['leaf_hash'][:16]}...")

    elif a.action == 'did-register':
        print(json.dumps(gp.did_register(), indent=2))

    elif a.action == 'fingerprint':
        gp.fingerprint(a.recipient or a.device)

    elif a.action == 'known-devices':
        gp.known_devices()

    elif a.action == 'trust':
        if not a.recipient: sys.exit('--recipient required')
        gp.trust(a.recipient)

    elif a.action == 'untrust':
        if not a.recipient: sys.exit('--recipient required')
        gp.untrust(a.recipient)

    elif a.action == 'listen':
        def on_receive(data, meta):
            if a.output:
                path = os.path.join(a.output, f'block_{meta["seq"]:06d}.bin')
                os.makedirs(a.output, exist_ok=True)
                open(path, 'wb').write(data)
                print(f'[recv] seq={meta["seq"]} {len(data)}B → {path}')
            else:
                print(f'[recv] seq={meta["seq"]} {len(data)}B')
        gp.listen(on_receive)
