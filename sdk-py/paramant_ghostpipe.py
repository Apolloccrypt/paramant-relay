#!/usr/bin/env python3
"""
PARAMANT Ghost Pipe — Python SDK
Hybrid KEM: ML-KEM-768 (NIST FIPS 203) + ECDH P-256

Installatie:
    pip install paramant-ghostpipe

Of handmatig:
    pip install requests cryptography

Voor ML-KEM-768:
    pip install liboqs-python
    OF pip install pqcrypto
"""

import os, struct, hashlib, base64, json, warnings
from typing import Optional

import requests
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, generate_private_key, SECP256R1, EllipticCurvePublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RELAY      = "https://relay.paramant.app"
BLOCK_SIZE = 5 * 1024 * 1024  # 5MB vaste blokgrootte
GP_MAGIC   = b"PQHB"          # Post-Quantum Hybrid
INFO       = b"paramant-ghost-pipe-hybrid-v1"

# ML-KEM-768 constanten
MLKEM_PUB_LEN  = 1184
MLKEM_PRIV_LEN = 2400
MLKEM_CT_LEN   = 1088
ECDH_PUB_LEN   = 65


# ─── ML-KEM-768 backend ─────────────────────────────────────
def _load_mlkem():
    """Laad ML-KEM-768 via liboqs of pqcrypto."""
    # Poging 1: liboqs-python (aanbevolen, officieel NIST)
    try:
        import oqs
        return "liboqs", oqs
    except ImportError:
        pass
    # Poging 2: pqcrypto (alternatief)
    try:
        import pqcrypto.kem.kyber768 as kyber
        return "pqcrypto", kyber
    except ImportError:
        pass
    return None, None

ML_BACKEND, ML_LIB = _load_mlkem()


class MLKem768:
    """ML-KEM-768 wrapper voor liboqs en pqcrypto."""

    @staticmethod
    def keygen() -> tuple[bytes, bytes]:
        """Genereer (public_key, secret_key)."""
        if ML_BACKEND == "liboqs":
            with ML_LIB.KeyEncapsulation("Kyber768") as kem:
                pub = kem.generate_keypair()
                priv = kem.export_secret_key()
            return pub, priv
        elif ML_BACKEND == "pqcrypto":
            pub, priv = ML_LIB.generate_keypair()
            return pub, priv
        else:
            raise RuntimeError(
                "ML-KEM-768 niet beschikbaar.\n"
                "Installeer: pip install liboqs-python\n"
                "Of: pip install pqcrypto"
            )

    @staticmethod
    def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
        """Encapsuleer → (ciphertext, shared_secret)."""
        if ML_BACKEND == "liboqs":
            with ML_LIB.KeyEncapsulation("Kyber768") as kem:
                ct, ss = kem.encap_secret(public_key)
            return ct, ss
        elif ML_BACKEND == "pqcrypto":
            ct, ss = ML_LIB.encrypt(public_key)
            return ct, ss
        else:
            raise RuntimeError("ML-KEM-768 niet beschikbaar")

    @staticmethod
    def decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
        """Decapsuleer → shared_secret."""
        if ML_BACKEND == "liboqs":
            with ML_LIB.KeyEncapsulation("Kyber768", secret_key) as kem:
                ss = kem.decap_secret(ciphertext)
            return ss
        elif ML_BACKEND == "pqcrypto":
            ss = ML_LIB.decrypt(secret_key, ciphertext)
            return ss
        else:
            raise RuntimeError("ML-KEM-768 niet beschikbaar")


# ─── Hybrid keypair ──────────────────────────────────────────
class HybridKeypair:
    """ML-KEM-768 + ECDH P-256 hybrid keypair."""

    def __init__(self):
        # ECDH P-256
        self._ec_priv = generate_private_key(SECP256R1())
        self._ec_pub  = self._ec_priv.public_key()
        # ML-KEM-768
        self._pq_pub, self._pq_priv = MLKem768.keygen()

    @property
    def public_key_hex(self) -> str:
        """Gecombineerde publieke sleutel als hex."""
        ec_pub_bytes = self._ec_pub.public_bytes(
            serialization.Encoding.X962,
            serialization.PublicFormat.UncompressedPoint
        )
        combined = ec_pub_bytes + self._pq_pub  # 65 + 1184 = 1249 bytes
        return combined.hex()

    @property
    def private_key_hex(self) -> str:
        """Gecombineerde privé sleutel als hex."""
        ec_priv_bytes = self._ec_priv.private_bytes(
            serialization.Encoding.DER,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        )
        # Format: [2B len_ec] [ec_priv] [pq_priv]
        length_prefix = struct.pack(">H", len(ec_priv_bytes))
        combined = length_prefix + ec_priv_bytes + self._pq_priv
        return combined.hex()

    def save(self, path: str):
        """Sla keypair op als JSON bestand."""
        with open(path, "w") as f:
            json.dump({
                "public_key":  self.public_key_hex,
                "private_key": self.private_key_hex,
                "algorithm":   "ML-KEM-768+ECDH-P256-hybrid-v1"
            }, f, indent=2)

    @classmethod
    def load(cls, path: str) -> "HybridKeypair":
        """Laad keypair van JSON bestand."""
        obj = cls.__new__(cls)
        with open(path) as f:
            data = json.load(f)
        obj._pub_hex  = data["public_key"]
        obj._priv_hex = data["private_key"]
        return obj


# ─── Encryptie / Decryptie ───────────────────────────────────
def _derive_hybrid_key(ec_ss: bytes, pq_ss: bytes, salt: bytes) -> AESGCM:
    """Leid AES-256 sleutel af van beide shared secrets via HKDF."""
    combined = ec_ss + pq_ss
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=INFO,
    ).derive(combined)
    return AESGCM(key)


def encrypt(data: bytes, recipient_pub_hex: str) -> bytes:
    """
    Versleutel data met ML-KEM-768 + ECDH P-256 hybrid KEM.
    
    Args:
        data: Bestandsinhoud als bytes
        recipient_pub_hex: Gecombineerde publieke sleutel als hex
    
    Returns:
        Encrypted blob (wire format PQHB)
    """
    pub_bytes = bytes.fromhex(recipient_pub_hex)
    ec_pub_bytes = pub_bytes[:ECDH_PUB_LEN]
    pq_pub_bytes = pub_bytes[ECDH_PUB_LEN:ECDH_PUB_LEN + MLKEM_PUB_LEN]

    # 1. ECDH ephemeral
    eph_priv = generate_private_key(SECP256R1())
    eph_pub  = eph_priv.public_key()
    eph_pub_bytes = eph_pub.public_bytes(
        serialization.Encoding.X962,
        serialization.PublicFormat.UncompressedPoint
    )
    ec_recip = serialization.load_der_public_key(
        b"\x30\x59\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01"
        b"\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07\x03\x42\x00"
        + ec_pub_bytes
    ) if len(ec_pub_bytes) == 65 else None

    # Alternatieve methode voor ECDH
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, SECP256R1 as _R1
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
    import struct as _struct

    # Laad publieke sleutel correct
    recip_key = eph_pub.__class__.from_encoded_point(
        SECP256R1(), ec_pub_bytes
    ) if hasattr(eph_pub.__class__, 'from_encoded_point') else None

    # Gebruik cryptography library correct
    from cryptography.hazmat.primitives.asymmetric.ec import (
        EllipticCurvePublicNumbers, SECP256R1
    )
    x = int.from_bytes(ec_pub_bytes[1:33], "big")
    y = int.from_bytes(ec_pub_bytes[33:65], "big")
    recip_ec_pub = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key()

    ec_ss = eph_priv.exchange(ECDH(), recip_ec_pub)

    # 2. ML-KEM-768 encapsulate
    pq_ct, pq_ss = MLKem768.encapsulate(pq_pub_bytes)

    # 3. Hybrid AES key
    aesgcm = _derive_hybrid_key(ec_ss, pq_ss, eph_pub_bytes)

    # 4. Encrypt
    iv = os.urandom(12)
    ct = aesgcm.encrypt(iv, data, None)

    # 5. Wire format: magic(4) + eph_pub(65) + pq_ct(1088) + iv(12) + ct
    return GP_MAGIC + eph_pub_bytes + pq_ct + iv + ct


def decrypt(encrypted: bytes, private_key_hex: str) -> bytes:
    """
    Ontsleutel data met ML-KEM-768 + ECDH P-256 hybrid KEM.
    
    Args:
        encrypted: Encrypted blob (wire format)
        private_key_hex: Gecombineerde privé sleutel als hex
    
    Returns:
        Originele bestandsinhoud
    """
    if not encrypted.startswith(GP_MAGIC):
        raise ValueError("Ongeldige wire format — verwacht PQHB magic")

    priv_bytes = bytes.fromhex(private_key_hex)
    ec_priv_len = struct.unpack(">H", priv_bytes[:2])[0]
    ec_priv_bytes = priv_bytes[2:2 + ec_priv_len]
    pq_priv_bytes = priv_bytes[2 + ec_priv_len:]

    # Parse wire format
    off = 4
    eph_pub_bytes = encrypted[off:off+65];           off += 65
    pq_ct         = encrypted[off:off+MLKEM_CT_LEN]; off += MLKEM_CT_LEN
    iv            = encrypted[off:off+12];           off += 12
    ct            = encrypted[off:]

    # 1. ECDH
    ec_priv = serialization.load_der_private_key(ec_priv_bytes, password=None)
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers, SECP256R1
    x = int.from_bytes(eph_pub_bytes[1:33], "big")
    y = int.from_bytes(eph_pub_bytes[33:65], "big")
    eph_ec_pub = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key()
    ec_ss = ec_priv.exchange(ECDH(), eph_ec_pub)

    # 2. ML-KEM-768 decapsulate
    pq_ss = MLKem768.decapsulate(pq_ct, pq_priv_bytes)

    # 3. Hybrid decrypt
    aesgcm = _derive_hybrid_key(ec_ss, pq_ss, eph_pub_bytes)
    return aesgcm.decrypt(iv, ct, None)


# ─── Padding (5MB vaste blokken) ─────────────────────────────
def pad(data: bytes) -> bytes:
    """Pad naar vaste 5MB blok (metadata masking)."""
    if len(data) > BLOCK_SIZE - 8:
        raise ValueError(f"Data te groot (max {BLOCK_SIZE - 8} bytes)")
    block = bytearray(BLOCK_SIZE)
    struct.pack_into(">Q", block, 0, len(data))
    block[8:8+len(data)] = data
    block[8+len(data):] = os.urandom(BLOCK_SIZE - 8 - len(data))
    return bytes(block)


def unpad(block: bytes) -> bytes:
    """Verwijder padding van 5MB blok."""
    length = struct.unpack(">Q", block[:8])[0]
    return block[8:8+length]


# ─── Routing hash ─────────────────────────────────────────────
def pubkey_hash(pub_hex: str) -> str:
    """SHA-256 van publieke sleutel als routing hash."""
    return hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()


# ─── Ghost Pipe API ──────────────────────────────────────────
def send(
    data: bytes,
    recipient_pub_hex: str,
    api_key: str = "",
    relay_url: str = RELAY
) -> dict:
    """
    Versleutel en verstuur bestand via Ghost Pipe relay.
    
    Args:
        data: Bestandsinhoud
        recipient_pub_hex: Publieke sleutel ontvanger (hex)
        api_key: PARAMANT API key (pgp_...) voor Pro/Kantoor
        relay_url: Relay URL (default: relay.paramant.app)
    
    Returns:
        dict met hash, ttl_ms, expires_at
    
    Voorbeeld:
        result = send(open("doc.pdf","rb").read(), pub_hex, "pgp_...")
        print(f"Hash: {result['hash']}")
    """
    encrypted = encrypt(data, recipient_pub_hex)
    padded    = pad(encrypted)
    hash_val  = pubkey_hash(recipient_pub_hex)
    payload   = base64.b64encode(padded).decode()

    body = {"hash": hash_val, "payload": payload}
    if api_key:
        body["api_key"] = api_key

    resp = requests.post(
        f"{relay_url}/v2/inbound",
        json=body,
        headers={"Content-Type": "application/json"},
        timeout=30
    )
    resp.raise_for_status()
    return resp.json()


def receive(
    hash_val: str,
    private_key_hex: str,
    relay_url: str = RELAY
) -> bytes:
    """
    Haal bestand op en ontsleutel (burn-on-read).
    
    Args:
        hash_val: Hash van de relay (van verzender ontvangen)
        private_key_hex: Eigen privé sleutel (hex)
        relay_url: Relay URL
    
    Returns:
        Originele bestandsinhoud
    
    Voorbeeld:
        data = receive(hash_val, priv_hex)
        open("ontvangen.pdf","wb").write(data)
    """
    resp = requests.get(
        f"{relay_url}/v2/outbound/{hash_val}",
        timeout=30
    )
    if resp.status_code == 404:
        raise FileNotFoundError("Bestand niet gevonden of al opgehaald (burn-on-read)")
    resp.raise_for_status()

    raw      = resp.content
    unpacked = unpad(raw)
    return decrypt(unpacked, private_key_hex)


def check_status(hash_val: str, relay_url: str = RELAY) -> dict:
    """Controleer of bestand nog beschikbaar is (zonder burn)."""
    resp = requests.get(f"{relay_url}/v2/status/{hash_val}", timeout=10)
    return resp.json()


def verify_key(api_key: str, relay_url: str = RELAY) -> dict:
    """Valideer een API key."""
    resp = requests.post(
        f"{relay_url}/v2/verify-key",
        json={"api_key": api_key},
        timeout=10
    )
    return resp.json()
