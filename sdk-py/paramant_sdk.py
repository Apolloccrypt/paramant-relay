"""
PARAMANT SDK v3.0.0 — post-quantum file relay client.

Replaces the v2.x _try_kyber() helper (which fell back to ECDH silently when
kyber-py was missing) with pqcrypto (ML-KEM-768 + ML-DSA-65). Blobs follow
wire format v1 (PQHB magic) and the client negotiates wire version + algorithm
support via /v2/capabilities before sending.

Public surface kept for compatibility with v2.x callers:
    - GhostPipe(api_key, device, relay=..., sector=..., secret=...)
      .send() / .receive() / .drop() / .pickup() / .receive_setup()
      .fingerprint() / .trust() / .untrust() / .known_devices()
      .status() / .audit() / .health() / .verify_receipt()
      .register_webhook() / .listen()
    - GhostPipeCluster(api_key, device, relays, health_interval)
    - GhostPipeError, FingerprintMismatchError
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
from typing import Callable, Optional, Tuple

import urllib.error
import urllib.parse
import urllib.request

from paramant import capabilities, crypto, wire_format
from paramant.errors import CapabilityMismatch, ParamantError

__version__ = "3.0.0"

# ── Padding block sizes ────────────────────────────────────────────────────────
BLOCKS = {
    "4k":   4 * 1024,
    "64k":  64 * 1024,
    "512k": 512 * 1024,
    "5m":   5 * 1024 * 1024,
}
BLOCK = 5 * 1024 * 1024
UA = f"paramant-sdk/{__version__}"

SECTOR_RELAYS = {
    "health":  "https://health.paramant.app",
    "iot":     "https://iot.paramant.app",
    "legal":   "https://legal.paramant.app",
    "finance": "https://finance.paramant.app",
    "relay":   "https://relay.paramant.app",
}
EDGE_RELAY = "https://paramant-ghost-pipe.fly.dev"


def get_relay_url(sector: str = "health", use_edge: bool = False) -> str:
    if use_edge:
        return f"{EDGE_RELAY}/{sector}"
    return SECTOR_RELAYS.get(sector, SECTOR_RELAYS["health"])


# ── Key zeroization ───────────────────────────────────────────────────────────
_ZEROIZE_OK = sys.implementation.name == "cpython"
if not _ZEROIZE_OK:
    warnings.warn(
        "paramant-sdk: key zeroization (ctypes) is not supported on "
        f"{sys.implementation.name}. Secret key material may persist in RAM.",
        RuntimeWarning, stacklevel=2,
    )


def _zero(b: Optional[bytes]) -> None:
    if not b:
        return
    try:
        offset = sys.getsizeof(b) - len(b) - 1
        ctypes.memset(id(b) + offset, 0, len(b))
    except Exception as exc:
        warnings.warn(
            f"paramant-sdk: _zero() failed — key material may persist in RAM: {exc}",
            RuntimeWarning, stacklevel=2,
        )


# ── BIP39 helpers (drop / pickup) ─────────────────────────────────────────────
def _bip39_encode(entropy: bytes) -> str:
    try:
        from mnemonic import Mnemonic
    except ImportError as exc:
        raise GhostPipeError("pip install mnemonic (required for drop/pickup)") from exc
    return Mnemonic("english").to_mnemonic(entropy)


def _bip39_decode(phrase: str) -> bytes:
    try:
        from mnemonic import Mnemonic
    except ImportError as exc:
        raise GhostPipeError("pip install mnemonic (required for drop/pickup)") from exc
    m = Mnemonic("english")
    if not m.check(phrase):
        raise GhostPipeError("Invalid BIP39 mnemonic (checksum failure)")
    return bytes(m.to_entropy(phrase))


def _derive_drop_keys(entropy: bytes) -> Tuple[bytes, str]:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    aes_key = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=b"paramant-drop-v1", info=b"aes-key",
    ).derive(entropy)
    id_bytes = HKDF(
        algorithm=hashes.SHA256(), length=32,
        salt=b"paramant-drop-v1", info=b"lookup-id",
    ).derive(entropy)
    return aes_key, hashlib.sha256(id_bytes).hexdigest()


# ── Errors ────────────────────────────────────────────────────────────────────
class GhostPipeError(ParamantError):
    pass


class FingerprintMismatchError(GhostPipeError):
    """Raised when a device's key fingerprint differs from the stored TOFU value."""
    def __init__(self, device_id: str, stored: str, received: str):
        self.device_id = device_id
        self.stored = stored
        self.received = received
        super().__init__(
            f"\n\n  !  FINGERPRINT MISMATCH — device: {device_id}\n"
            f"  Stored:   {stored}\n"
            f"  Received: {received}\n\n"
            f"  This may indicate a compromised relay or legitimate key rotation.\n"
            f"  If the device owner rotated their key, run:\n"
            f'    gp.trust("{device_id}")  — after verifying the new fingerprint out-of-band\n'
        )


# ── Canonical message signed inside a v1 blob ─────────────────────────────────
def _canonical_sign_input(aad: bytes, ct_kem: bytes, sender_pub: bytes,
                          nonce: bytes, ciphertext: bytes) -> bytes:
    """SHA-256 over the unsigned portion of the blob (AAD + ct_kem + sender_pub + nonce + ct).

    This is the message fed to ML-DSA-65 for sender authentication. A downstream
    verifier (sdk-js, another sdk-py, or a relay that adopts signature
    verification) reproduces the same hash from the parsed blob fields.
    """
    h = hashlib.sha256()
    h.update(aad)
    h.update(ct_kem)
    h.update(sender_pub)
    h.update(nonce)
    h.update(ciphertext)
    return h.digest()


# ── Main client ───────────────────────────────────────────────────────────────
class GhostPipe:
    """
    PARAMANT post-quantum encrypted relay client.

    Args:
        api_key:  pgp_... API key from paramant.app/dashboard
        device:   Device ID (sender and receiver use the same value)
        relay:    Relay URL (auto-detected from api_key if omitted)
        secret:   Additional secret, defaults to api_key
        relay_url: Alias for relay
        sector:   Sector name for relay URL resolution
        kem_id:   Override KEM algorithm (default 0x0002 = ML-KEM-768)
        sig_id:   Override signature algorithm (default 0x0002 = ML-DSA-65;
                  pass 0x0000 for anonymous blobs)
        negotiate_on_init: If True, fetches /v2/capabilities and validates
                  kem_id/sig_id against what the relay supports before the
                  first send. Default True. Disable only for offline testing.
    """

    def __init__(
        self,
        api_key: str,
        device: str,
        relay: str = "",
        secret: str = "",
        relay_url: str = "",
        sector: str = "",
        kem_id: int = crypto.DEFAULT_KEM_ID,
        sig_id: int = crypto.DEFAULT_SIG_ID,
        negotiate_on_init: bool = True,
    ):
        if not api_key.startswith("pgp_"):
            raise GhostPipeError("API key must start with pgp_")
        self.api_key = api_key
        self.device = device
        self.secret = secret or api_key
        self.kem_id = int(kem_id)
        self.sig_id = int(sig_id)
        _relay = (
            relay or relay_url
            or (get_relay_url(sector) if sector else "")
            or self._detect_relay()
        )
        self.relay = _relay
        if not self.relay:
            raise GhostPipeError("No relay reachable. Check your API key.")
        self._keypair: Optional[dict] = None
        self._capabilities: Optional[capabilities.RelayCapabilities] = None
        self._skip_negotiation = not negotiate_on_init
        if negotiate_on_init:
            self._negotiate()

    # ── Capability negotiation ────────────────────────────────────────────────
    def _negotiate(self) -> Optional[capabilities.RelayCapabilities]:
        """Fetch /v2/capabilities and validate. Returns None if negotiation was
        opted out at construction (negotiate_on_init=False)."""
        if self._skip_negotiation:
            return None
        if self._capabilities is not None:
            return self._capabilities
        caps = capabilities.fetch_capabilities(self.relay, user_agent=UA)
        capabilities.validate(caps, kem_id=self.kem_id, sig_id=self.sig_id)
        self._capabilities = caps
        return caps

    def capabilities(self) -> capabilities.RelayCapabilities:
        """Return the relay's advertised capabilities (cached after first call)."""
        return self._negotiate()

    # ── TOFU / known-keys ─────────────────────────────────────────────────────
    @staticmethod
    def _known_keys_path() -> str:
        return os.path.join(os.path.expanduser("~/.paramant"), "known_keys")

    def _load_known_keys(self) -> dict:
        p = self._known_keys_path()
        if not os.path.exists(p):
            return {}
        result = {}
        with open(p) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    result[parts[0]] = {
                        "fingerprint": parts[1],
                        "registered_at": parts[2] if len(parts) > 2 else "",
                    }
        return result

    def _save_known_key(self, device_id: str, fingerprint: str, registered_at: str = ""):
        os.makedirs(os.path.dirname(self._known_keys_path()), exist_ok=True)
        keys = self._load_known_keys()
        keys[device_id] = {"fingerprint": fingerprint, "registered_at": registered_at or ""}
        tmp = self._known_keys_path() + ".tmp"
        with open(tmp, "w") as f:
            f.write("# PARAMANT known-keys — Trust On First Use (TOFU)\n")
            f.write("# Format: device_id fingerprint registered_at\n")
            for did, v in keys.items():
                f.write(f'{did} {v["fingerprint"]} {v["registered_at"]}\n')
        os.chmod(tmp, 0o600)
        os.replace(tmp, self._known_keys_path())

    def _remove_known_key(self, device_id: str):
        keys = self._load_known_keys()
        if device_id in keys:
            del keys[device_id]
            tmp = self._known_keys_path() + ".tmp"
            with open(tmp, "w") as f:
                f.write("# PARAMANT known-keys — Trust On First Use (TOFU)\n")
                f.write("# Format: device_id fingerprint registered_at\n")
                for did, v in keys.items():
                    f.write(f'{did} {v["fingerprint"]} {v["registered_at"]}\n')
            os.chmod(tmp, 0o600)
            os.replace(tmp, self._known_keys_path())

    @staticmethod
    def _compute_fingerprint(kyber_pub_hex: str, ecdh_pub_hex: str) -> str:
        """Retained from v2.x for wire compatibility with the relay's
        computeFingerprint(kyber_pub, ecdh_pub) helper. ecdh_pub_hex is the
        server-stored identity anchor; in v3 it is not used for encryption."""
        buf = bytes.fromhex(kyber_pub_hex or "") + bytes.fromhex(ecdh_pub_hex or "")
        h = hashlib.sha256(buf).hexdigest()[:20].upper()
        return f"{h[0:4]}-{h[4:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}"

    def _tofu_check(self, device_id: str, kyber_pub_hex: str, ecdh_pub_hex: str,
                    registered_at: str = "") -> str:
        fp = self._compute_fingerprint(kyber_pub_hex, ecdh_pub_hex)
        keys = self._load_known_keys()
        if device_id in keys:
            stored = keys[device_id]["fingerprint"]
            if stored.replace("-", "").upper() != fp.replace("-", "").upper():
                raise FingerprintMismatchError(device_id, stored, fp)
        else:
            self._save_known_key(device_id, fp, registered_at)
            print(f"[paramant] New device: {device_id}")
            print(f"           Fingerprint: {fp}")
            print(f"           Verify this out-of-band before trusting.")
        return fp

    # ── Relay detection ───────────────────────────────────────────────────────
    def _detect_relay(self) -> Optional[str]:
        for relay in SECTOR_RELAYS.values():
            try:
                r = urllib.request.urlopen(
                    urllib.request.Request(
                        f"{relay}/v2/check-key",
                        headers={"User-Agent": UA, "X-Api-Key": self.api_key},
                    ), timeout=4,
                )
                if json.loads(r.read()).get("valid"):
                    return relay
            except Exception:
                pass
        return None

    # ── HTTP helpers ──────────────────────────────────────────────────────────
    def _get(self, path: str, params: dict = None):
        url = self.relay + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(
            url, headers={"User-Agent": UA, "X-Api-Key": self.api_key}
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(), {}

    def _post(self, path: str, body: bytes, content_type: str = "application/json"):
        req = urllib.request.Request(
            self.relay + path, data=body, method="POST",
            headers={
                "Content-Type": content_type,
                "X-Api-Key": self.api_key,
                "User-Agent": UA,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()

    # ── Keypair management ────────────────────────────────────────────────────
    def _load_keypair(self) -> dict:
        """Load or generate this device's keypair.

        v3.0.0 layout:
            ml_kem_pub/ml_kem_priv  — ML-KEM-768 (FIPS 203) for KEM
            ml_dsa_pub/ml_dsa_priv  — ML-DSA-65 (FIPS 204) for signatures
            ecdh_pub                — legacy relay-registration anchor, not used for crypto
        """
        if self._keypair:
            return self._keypair
        state_dir = os.path.expanduser("~/.paramant")
        path = os.path.join(state_dir, self.device.replace("/", "_") + ".keypair.json")
        if os.path.exists(path):
            kp = json.load(open(path))
            # Transparent upgrade from v2.x keypair files is out of scope: v2
            # blobs were wire-incompatible anyway. A v2 file missing ml_kem_pub
            # forces a regen.
            if not kp.get("ml_kem_pub") or not kp.get("ml_dsa_pub"):
                os.rename(path, path + ".v2.bak")
            else:
                self._keypair = kp
                return kp
        os.makedirs(state_dir, exist_ok=True)
        kem_kp = crypto.kem_keygen()
        sig_kp = crypto.sig_keygen()
        # The relay's /v2/pubkey endpoint still requires a non-empty ecdh_pub
        # field for historical reasons. Register a stable identity anchor (the
        # SHA-256 of the ML-KEM public key, as a DER-looking blob) so the
        # server's computeFingerprint stays stable across v3 clients.
        identity_anchor = hashlib.sha256(kem_kp.public_key).digest()
        kp = {
            "device": self.device,
            "version": 3,
            "ml_kem_pub": kem_kp.public_key.hex(),
            "ml_kem_priv": kem_kp.secret_key.hex(),
            "ml_dsa_pub": sig_kp.public_key.hex(),
            "ml_dsa_priv": sig_kp.secret_key.hex(),
            "ecdh_pub": identity_anchor.hex(),
            "kyber_pub": kem_kp.public_key.hex(),  # server model uses "kyber_pub" as the KEM pubkey slot
        }
        with open(path, "w") as f:
            json.dump(kp, f)
        os.chmod(path, 0o600)
        self._keypair = kp
        return kp

    def _register_pubkeys(self):
        kp = self._load_keypair()
        body = json.dumps({
            "device_id": self.device,
            "ecdh_pub":  kp["ecdh_pub"],
            "kyber_pub": kp["ml_kem_pub"],
            "dsa_pub":   kp["ml_dsa_pub"],
        }).encode()
        status, resp = self._post("/v2/pubkey", body)
        if status != 200:
            raise GhostPipeError(f"Pubkey registration failed: {resp.decode()[:120]}")

    def _fetch_receiver_pubkeys(self, recipient: str = None):
        target = recipient or self.device
        status, body, _ = self._get(f"/v2/pubkey/{target}")
        if status == 404:
            raise GhostPipeError(
                "No pubkeys for this device. Start the receiver with receive_setup() first."
            )
        if status != 200:
            raise GhostPipeError(f"Pubkey fetch failed: HTTP {status}")
        d = json.loads(body)
        ml_kem_pub = bytes.fromhex(d["kyber_pub"]) if d.get("kyber_pub") else None
        if not ml_kem_pub:
            raise GhostPipeError(
                f"Receiver {target} has no ML-KEM public key. Upgrade the receiver to paramant-sdk>=3."
            )
        return {
            "ml_kem_pub": ml_kem_pub,
            "ml_dsa_pub": bytes.fromhex(d["dsa_pub"]) if d.get("dsa_pub") else b"",
            "kyber_hex":  d.get("kyber_pub", ""),
            "ecdh_hex":   d.get("ecdh_pub", ""),
            "registered_at": d.get("registered_at", ""),
        }

    # ── Wire format v1 encrypt / decrypt ──────────────────────────────────────
    def _encrypt(self, data: bytes, recipient_ml_kem_pub: bytes,
                 pad_block: int = None, pre_shared_secret: str = "") -> Tuple[bytes, str]:
        """ML-KEM-768 -> AES-256-GCM over data, with header bound in AAD.

        No ECDH hybrid, no silent fallback. The recipient's ML-KEM-768 public
        key is the only secret-derivation input, plus the per-blob nonce. An
        optional `pre_shared_secret` is mixed into the HKDF input for domain
        separation; both sides must pass the same value.
        """
        self._negotiate()
        kp = self._load_keypair()
        sender_pub = bytes.fromhex(kp["ml_dsa_pub"]) if self.sig_id != 0x0000 else b""
        sender_priv = bytes.fromhex(kp["ml_dsa_priv"]) if self.sig_id != 0x0000 else b""

        ct_kem, shared_secret = crypto.kem_encapsulate(recipient_ml_kem_pub)
        aes_key, pss_bytes = self._derive_payload_key(shared_secret, ct_kem, pre_shared_secret)

        aad = wire_format.build_aad(kem_id=self.kem_id, sig_id=self.sig_id, chunk_index=0)
        nonce, ciphertext = crypto.aes_gcm_encrypt(aes_key, data, aad)

        signature = None
        if self.sig_id != 0x0000:
            sign_input = _canonical_sign_input(aad, ct_kem, sender_pub, nonce, ciphertext)
            signature = crypto.sig_sign(sender_priv, sign_input)

        try:
            blob = wire_format.encode(
                kem_id=self.kem_id, sig_id=self.sig_id,
                ct_kem=ct_kem, sender_pub=sender_pub, signature=signature,
                nonce=nonce, ciphertext=ciphertext,
            )
            target = pad_block or BLOCK
            if len(blob) > target:
                raise GhostPipeError(
                    f"Payload too large for padding block ({len(data)} bytes of "
                    f"plaintext -> {len(blob)} bytes encoded, max {target} bytes)"
                )
            padded = blob + os.urandom(target - len(blob))
            return padded, hashlib.sha256(padded).hexdigest()
        finally:
            _zero(shared_secret); _zero(aes_key); _zero(pss_bytes)

    @staticmethod
    def _derive_payload_key(shared_secret: bytes, ct_kem: bytes,
                             pre_shared_secret: str = "") -> Tuple[bytes, bytes]:
        """HKDF from KEM shared secret; optional PSS mixed via a distinct info label."""
        if pre_shared_secret:
            pss_hash = hashlib.sha3_256(pre_shared_secret.encode("utf-8")).digest()
            ikm = shared_secret + pss_hash
            info = b"paramant-v1-aes-key-pss"
        else:
            pss_hash = b""
            ikm = shared_secret
            info = b"paramant-v1-aes-key"
        key = crypto.derive_key(ikm, salt=ct_kem[:32], info=info)
        return key, pss_hash

    def _decrypt(self, padded_blob: bytes, pre_shared_secret: str = "") -> bytes:
        kp = self._load_keypair()
        secret_key = bytes.fromhex(kp["ml_kem_priv"])

        if not wire_format.is_v1(padded_blob):
            raise GhostPipeError(
                "Blob is not wire format v1 (missing PQHB magic). v2.x blobs are "
                "incompatible with paramant-sdk 3.x — re-encrypt with a v3 sender."
            )
        parsed = wire_format.decode(padded_blob)
        if parsed["kem_id"] != self.kem_id:
            raise CapabilityMismatch(
                f"blob KEM id 0x{parsed['kem_id']:04x} != client KEM id 0x{self.kem_id:04x}"
            )
        if parsed["sig_id"] != 0x0000 and parsed["sig_id"] != self.sig_id:
            raise CapabilityMismatch(
                f"blob SIG id 0x{parsed['sig_id']:04x} != client SIG id 0x{self.sig_id:04x}"
            )

        shared = crypto.kem_decapsulate(secret_key, parsed["ct_kem"])
        aes_key, pss_bytes = self._derive_payload_key(shared, parsed["ct_kem"], pre_shared_secret)
        aad = wire_format.build_aad(
            kem_id=parsed["kem_id"], sig_id=parsed["sig_id"], chunk_index=0
        )
        try:
            return crypto.aes_gcm_decrypt(aes_key, parsed["nonce"], parsed["ciphertext"], aad)
        finally:
            _zero(shared); _zero(aes_key); _zero(pss_bytes)

    # ── Public API ────────────────────────────────────────────────────────────
    def send(self, data: bytes, ttl: int = 300, max_views: int = 1,
             pad_block: int = None, recipient: str = None,
             pre_shared_secret: str = "") -> Tuple[str, Optional[dict]]:
        """Encrypt `data` to the recipient's device and upload to the relay.

        Returns (blob_sha256_hex, merkle_inclusion_proof_or_None). The
        `pre_shared_secret` argument is accepted for v2.x call-site compat
        and folded into the AES key via HKDF info.
        """
        rec = self._fetch_receiver_pubkeys(recipient)
        target_device = recipient or self.device
        self._tofu_check(target_device, rec["kyber_hex"], rec["ecdh_hex"], rec["registered_at"])
        padded, h = self._encrypt(
            data, rec["ml_kem_pub"], pad_block=pad_block, pre_shared_secret=pre_shared_secret,
        )

        body = json.dumps({
            "hash": h,
            "payload": base64.b64encode(padded).decode(),
            "ttl_ms": ttl * 1000,
            "max_views": max_views,
            "meta": {"device_id": self.device},
        }).encode()
        status, resp = self._post("/v2/inbound", body)
        if status != 200:
            raise GhostPipeError(f"Upload failed: HTTP {status}: {resp.decode()[:120]}")
        try:
            resp_json = json.loads(resp)
        except json.JSONDecodeError:
            resp_json = {}
        return h, resp_json.get("merkle_proof")

    def drop(self, data: bytes, ttl: int = 3600, pad_block: int = None) -> str:
        """Anonymous drop using a 12-word BIP39 mnemonic as the symmetric key."""
        entropy = os.urandom(16)
        phrase = _bip39_encode(entropy)
        aes_key, lookup_hash = _derive_drop_keys(entropy)
        try:
            nonce = os.urandom(12)
            ct = crypto.aes_gcm_encrypt(aes_key, data, b"", nonce=nonce)[1]
            packet = nonce + struct.pack(">I", len(ct)) + ct
            target = pad_block or BLOCK
            if len(packet) > target:
                raise GhostPipeError(f"Data too large for drop block ({len(data)} bytes)")
            blob = packet + os.urandom(target - len(packet))
            body = json.dumps({
                "hash": lookup_hash,
                "payload": base64.b64encode(blob).decode(),
                "ttl_ms": ttl * 1000,
                "max_views": 1,
                "meta": {"drop": True},
            }).encode()
            status, resp = self._post("/v2/inbound", body)
            if status != 200:
                raise GhostPipeError(f"Drop upload failed: HTTP {status}: {resp.decode()[:120]}")
            return phrase
        finally:
            _zero(aes_key); _zero(entropy)

    def pickup(self, phrase: str) -> bytes:
        entropy = _bip39_decode(phrase.strip())
        aes_key, lookup_hash = _derive_drop_keys(entropy)
        try:
            status, raw, _ = self._get(f"/v2/outbound/{lookup_hash}")
            if status == 404:
                raise GhostPipeError("Drop not found. Expired, already retrieved, or invalid mnemonic.")
            if status != 200:
                raise GhostPipeError(f"Drop fetch failed: HTTP {status}")
            nonce = raw[:12]
            ct_len = struct.unpack(">I", raw[12:16])[0]
            ct = raw[16:16 + ct_len]
            return crypto.aes_gcm_decrypt(aes_key, nonce, ct, b"")
        finally:
            _zero(aes_key); _zero(entropy)

    def receive(self, hash_: str, pre_shared_secret: str = "") -> Tuple[bytes, Optional[dict]]:
        """Retrieve data from the relay by blob hash. Burn-on-read."""
        status, raw, headers = self._get(f"/v2/outbound/{hash_}")
        if status == 404:
            raise GhostPipeError("Blob not found. Expired, already retrieved, or never stored.")
        if status != 200:
            raise GhostPipeError(f"Download failed: HTTP {status}")
        receipt = None
        receipt_b64 = headers.get("x-paramant-receipt") or headers.get("X-Paramant-Receipt")
        if receipt_b64:
            try:
                padded = receipt_b64.replace("-", "+").replace("_", "/")
                padded += "=" * ((4 - len(padded) % 4) % 4)
                receipt = json.loads(base64.b64decode(padded).decode("utf-8"))
            except Exception:
                pass
        data = self._decrypt(raw, pre_shared_secret=pre_shared_secret)
        return data, receipt

    def status(self, hash_: str) -> dict:
        _, body, _ = self._get(f"/v2/status/{hash_}")
        return json.loads(body)

    def fingerprint(self, device_id: str = None) -> str:
        target = device_id or self.device
        status, body, _ = self._get(f"/v2/pubkey/{target}")
        if status == 404:
            raise GhostPipeError(f"No pubkeys for device {target}")
        if status != 200:
            raise GhostPipeError(f"Pubkey fetch failed: HTTP {status}")
        d = json.loads(body)
        fp = self._compute_fingerprint(d.get("kyber_pub", ""), d.get("ecdh_pub", ""))
        print(f"Device:      {target}")
        print(f"Fingerprint: {fp}")
        if d.get("registered_at"):
            print(f"Registered:  {d['registered_at']}")
        if d.get("ct_index") is not None:
            print(f"CT log index: {d['ct_index']}")
        return fp

    def trust(self, device_id: str, fingerprint: str = None) -> str:
        if fingerprint:
            self._save_known_key(device_id, fingerprint)
            print(f"[paramant] Trusted: {device_id} ({fingerprint})")
            return fingerprint
        fp = self.fingerprint(device_id)
        self._save_known_key(device_id, fp)
        print(f"[paramant] Trusted: {device_id} ({fp})")
        return fp

    def untrust(self, device_id: str):
        self._remove_known_key(device_id)
        print(f"[paramant] Removed: {device_id}")

    def known_devices(self) -> list:
        keys = self._load_known_keys()
        if not keys:
            print("[paramant] No trusted devices yet.")
            return []
        print(f'{"Device":<36} {"Fingerprint":<26} {"Registered":<24}')
        print("-" * 88)
        for did, v in keys.items():
            print(f'{did:<36} {v["fingerprint"]:<26} {v["registered_at"]:<24}')
        return [{"device_id": k, **v} for k, v in keys.items()]

    def receive_setup(self):
        """Generate keypair (if needed) and register public keys with the relay."""
        self._load_keypair()
        self._register_pubkeys()
        return self

    def register_webhook(self, callback_url: str, secret: str = ""):
        body = json.dumps({
            "device_id": self.device, "url": callback_url, "secret": secret
        }).encode()
        status, resp = self._post("/v2/webhook", body)
        if status != 200:
            raise GhostPipeError(f"Webhook registration failed: {resp.decode()[:120]}")

    def listen(self, on_receive: Callable, interval: int = 3):
        self.receive_setup()
        seq = self._load_seq()
        while True:
            try:
                _, body, _ = self._get("/v2/stream-next", {"device": self.device, "seq": seq})
                d = json.loads(body)
                if d.get("available"):
                    next_seq = d.get("seq", seq + 1)
                    try:
                        data, _ = self.receive(d["hash"])
                        seq = next_seq
                        self._save_seq(seq)
                        on_receive(data, {"seq": seq, "hash": d["hash"]})
                        continue
                    except GhostPipeError:
                        seq = next_seq
            except Exception:
                pass
            time.sleep(interval)

    def audit(self, limit: int = 100) -> list:
        _, body, _ = self._get("/v2/audit", {"limit": limit})
        return json.loads(body).get("entries", [])

    def health(self) -> dict:
        _, body, _ = self._get("/health")
        return json.loads(body)

    def verify_receipt(self, receipt) -> dict:
        if isinstance(receipt, dict):
            receipt_b64 = base64.b64encode(json.dumps(receipt).encode()).decode()
        else:
            receipt_b64 = receipt
        body = json.dumps({"receipt": receipt_b64}).encode()
        status, resp = self._post("/v2/verify-receipt", body)
        if status != 200:
            raise GhostPipeError(f"Receipt verification failed: HTTP {status}: {resp.decode()[:120]}")
        result = json.loads(resp)
        if not result.get("valid"):
            raise GhostPipeError(f'Receipt invalid: {result.get("reason", "unknown")}')
        return result

    def _load_seq(self) -> int:
        try:
            p = os.path.join(
                os.path.expanduser("~/.paramant"),
                self.device.replace("/", "_") + ".sdk_seq",
            )
            return int(open(p).read())
        except Exception:
            return 0

    def _save_seq(self, seq: int):
        d = os.path.expanduser("~/.paramant")
        os.makedirs(d, exist_ok=True)
        p = os.path.join(d, self.device.replace("/", "_") + ".sdk_seq")
        open(p + ".tmp", "w").write(str(seq))
        os.replace(p + ".tmp", p)


# ── Multi-relay failover (gossip-light) ───────────────────────────────────────
class GhostPipeCluster:
    """Multi-relay client with automatic failover.

    Polls /health on every configured relay and routes sends through the
    first healthy one. Each send() constructs a GhostPipe against the active
    relay, which in turn negotiates capabilities before the first blob.
    """

    def __init__(self, api_key: str, device: str, relays: list,
                 health_interval: int = 30):
        self.api_key = api_key
        self.device = device
        self.relays = relays
        self._healthy: dict = {}
        self._active: Optional[str] = None
        import threading
        self._lock = threading.Lock()
        t = threading.Thread(target=self._monitor, daemon=True)
        t.start()
        time.sleep(2)

    def _check_health(self, relay: str) -> dict:
        try:
            r = urllib.request.urlopen(
                urllib.request.Request(f"{relay}/health", headers={"User-Agent": UA}),
                timeout=5,
            )
            d = json.loads(r.read())
            if d.get("ok"):
                return {"ok": True, "relay": relay, "blobs": d.get("blobs", 0),
                        "version": d.get("version"), "latency_ms": 0}
        except Exception:
            pass
        return {"ok": False, "relay": relay}

    def _monitor(self):
        while True:
            for relay in self.relays:
                h = self._check_health(relay)
                with self._lock:
                    self._healthy[relay] = h
            for relay in self.relays:
                if self._healthy.get(relay, {}).get("ok"):
                    with self._lock:
                        if self._active != relay:
                            self._active = relay
                    break
            time.sleep(30)

    def _get_client(self) -> "GhostPipe":
        with self._lock:
            relay = self._active
        if not relay:
            raise GhostPipeError("No healthy relay available")
        return GhostPipe(self.api_key, self.device, relay=relay)

    def send(self, data: bytes, ttl: int = 300) -> Tuple[str, Optional[dict]]:
        errors = []
        for relay in self.relays:
            if not self._healthy.get(relay, {}).get("ok"):
                continue
            try:
                gp = GhostPipe(self.api_key, self.device, relay=relay)
                return gp.send(data, ttl=ttl)
            except GhostPipeError as e:
                errors.append(f"{relay}: {e}")
                with self._lock:
                    self._healthy[relay] = {"ok": False}
        raise GhostPipeError(f"All relays failed: {errors}")

    def receive(self, hash_: str) -> Tuple[bytes, Optional[dict]]:
        for relay in self.relays:
            try:
                gp = GhostPipe(self.api_key, self.device, relay=relay)
                if gp.status(hash_).get("available"):
                    return gp.receive(hash_)
            except Exception:
                pass
        raise GhostPipeError("Blob not found on any relay")

    def health(self) -> dict:
        with self._lock:
            return {"active": self._active, "nodes": dict(self._healthy)}

    def receive_setup(self):
        for relay in self.relays:
            if self._healthy.get(relay, {}).get("ok"):
                try:
                    GhostPipe(self.api_key, self.device, relay=relay).receive_setup()
                except Exception:
                    pass
        return self


# ── CLI entry point ───────────────────────────────────────────────────────────
def _cli_main():
    import argparse

    p = argparse.ArgumentParser(description=f"PARAMANT SDK v{__version__}")
    p.add_argument("action", choices=[
        "send", "receive", "status", "listen", "health", "audit",
        "drop", "pickup", "verify-receipt", "capabilities",
    ])
    p.add_argument("--key",       required=True)
    p.add_argument("--device",    default="cli")
    p.add_argument("--relay",     default="")
    p.add_argument("--hash",      default="")
    p.add_argument("--mnemonic",  default="")
    p.add_argument("--file",      default="")
    p.add_argument("--ttl",       type=int, default=300)
    p.add_argument("--max-views", type=int, default=1)
    p.add_argument("--pad-block", default="5m", choices=list(BLOCKS.keys()))
    p.add_argument("--output",    default="")
    p.add_argument("--webhook",   default="")
    p.add_argument("--receipt",   default="")
    p.add_argument("--no-negotiate", action="store_true",
                   help="Skip /v2/capabilities negotiation (offline mode, not recommended)")
    a = p.parse_args()

    pad = BLOCKS[a.pad_block]
    gp = GhostPipe(a.key, a.device, relay=a.relay, negotiate_on_init=not a.no_negotiate)

    if a.action == "capabilities":
        caps = gp.capabilities()
        print(json.dumps(caps.raw, indent=2))
        return

    if a.action == "send":
        data = open(a.file, "rb").read() if a.file else sys.stdin.buffer.read()
        gp.receive_setup()
        h, proof = gp.send(data, ttl=a.ttl, max_views=a.max_views, pad_block=pad)
        print(f"OK hash={h}")
        if proof:
            print(f'   leaf_index={proof.get("leaf_index")} tree_size={proof.get("tree_size")} root={str(proof.get("root",""))[:16]}...')

    elif a.action == "receive":
        if not a.hash:
            sys.exit("--hash required")
        gp.receive_setup()
        data, receipt = gp.receive(a.hash)
        if a.output:
            with open(a.output, "wb") as f:
                f.write(data)
            print(f"OK saved to {a.output} ({len(data)} bytes)")
        else:
            sys.stdout.buffer.write(data)
        if receipt:
            print(f'[receipt] burn_confirmed={receipt.get("burn_confirmed")} sector={receipt.get("sector")}',
                  file=sys.stderr)

    elif a.action == "drop":
        data = open(a.file, "rb").read() if a.file else sys.stdin.buffer.read()
        phrase = gp.drop(data, ttl=a.ttl, pad_block=pad)
        print(f"Mnemonic: {phrase}")

    elif a.action == "pickup":
        if not a.mnemonic:
            sys.exit("--mnemonic required")
        data = gp.pickup(a.mnemonic)
        if a.output:
            with open(a.output, "wb") as f:
                f.write(data)
            print(f"OK saved to {a.output} ({len(data)} bytes)")
        else:
            sys.stdout.buffer.write(data)

    elif a.action == "status":
        if not a.hash:
            sys.exit("--hash required")
        print(json.dumps(gp.status(a.hash), indent=2))

    elif a.action == "listen":
        def on_receive(data, meta):
            if a.output:
                path = os.path.join(a.output, f'block_{meta["seq"]:06d}.bin')
                os.makedirs(a.output, exist_ok=True)
                open(path, "wb").write(data)
                print(f'[RECV] seq={meta["seq"]} {len(data)}B -> {path}')
            else:
                print(f'[RECV] seq={meta["seq"]} {len(data)}B')
        if a.webhook:
            gp.receive_setup()
            gp.register_webhook(a.webhook)
            print(f"Webhook registered: {a.webhook}")
        gp.listen(on_receive)

    elif a.action == "health":
        print(json.dumps(gp.health(), indent=2))

    elif a.action == "audit":
        for e in gp.audit():
            print(f"{e['ts']}  {e['event']:<20}  {e.get('hash',''):<20}  {e.get('bytes',0)}B")

    elif a.action == "verify-receipt":
        if not a.receipt and not a.file:
            sys.exit("--receipt <base64url> or --file <receipt.json> required")
        if a.file:
            with open(a.file) as f:
                receipt_raw = f.read().strip()
            try:
                receipt_data = json.loads(receipt_raw)
            except json.JSONDecodeError:
                receipt_data = receipt_raw
        else:
            receipt_data = a.receipt
        result = gp.verify_receipt(receipt_data)
        print(json.dumps(result, indent=2))


if __name__ == "__main__":
    _cli_main()
