#!/usr/bin/env python3
import os, struct, hashlib, base64, json, warnings
from typing import Optional

import requests
from cryptography.hazmat.primitives.asymmetric.ec import (
    ECDH, generate_private_key, SECP256R1, EllipticCurvePublicNumbers
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

RELAY      = "https://relay.paramant.app"
BLOCK_SIZE = 5 * 1024 * 1024
GP_MAGIC   = b"PQHB"
INFO       = b"paramant-ghost-pipe-hybrid-v1"

MLKEM_PUB_LEN  = 1184
MLKEM_PRIV_LEN = 2400
MLKEM_CT_LEN   = 1088
ECDH_PUB_LEN   = 65


def _load_mlkem():
    try:
        import oqs
        return "liboqs", oqs
    except ImportError:
        pass
    try:
        import pqcrypto.kem.kyber768 as kyber
        return "pqcrypto", kyber
    except ImportError:
        pass
    return None, None

ML_BACKEND, ML_LIB = _load_mlkem()


class MLKem768:
    @staticmethod
    def keygen() -> tuple[bytes, bytes]:
        if ML_BACKEND == "liboqs":
            with ML_LIB.KeyEncapsulation("Kyber768") as kem:
                pub = kem.generate_keypair()
                priv = kem.export_secret_key()
            return pub, priv
        elif ML_BACKEND == "pqcrypto":
            return ML_LIB.generate_keypair()
        raise RuntimeError("ML-KEM-768 not available. Install: pip install liboqs-python  OR  pip install pqcrypto")

    @staticmethod
    def encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
        if ML_BACKEND == "liboqs":
            with ML_LIB.KeyEncapsulation("Kyber768") as kem:
                return kem.encap_secret(public_key)
        elif ML_BACKEND == "pqcrypto":
            return ML_LIB.encrypt(public_key)
        raise RuntimeError("ML-KEM-768 not available")

    @staticmethod
    def decapsulate(ciphertext: bytes, secret_key: bytes) -> bytes:
        if ML_BACKEND == "liboqs":
            with ML_LIB.KeyEncapsulation("Kyber768", secret_key) as kem:
                return kem.decap_secret(ciphertext)
        elif ML_BACKEND == "pqcrypto":
            return ML_LIB.decrypt(secret_key, ciphertext)
        raise RuntimeError("ML-KEM-768 not available")


class HybridKeypair:
    def __init__(self):
        self._ec_priv = generate_private_key(SECP256R1())
        self._ec_pub  = self._ec_priv.public_key()
        self._pq_pub, self._pq_priv = MLKem768.keygen()

    @property
    def public_key_hex(self) -> str:
        ec_pub_bytes = self._ec_pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
        return (ec_pub_bytes + self._pq_pub).hex()

    @property
    def private_key_hex(self) -> str:
        ec_priv_bytes = self._ec_priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        return (struct.pack(">H", len(ec_priv_bytes)) + ec_priv_bytes + self._pq_priv).hex()

    def save(self, path: str):
        with open(path, "w") as f:
            json.dump({"public_key": self.public_key_hex, "private_key": self.private_key_hex, "algorithm": "ML-KEM-768+ECDH-P256-hybrid-v1"}, f, indent=2)

    @classmethod
    def load(cls, path: str) -> "HybridKeypair":
        obj = cls.__new__(cls)
        with open(path) as f:
            data = json.load(f)
        obj._pub_hex  = data["public_key"]
        obj._priv_hex = data["private_key"]
        return obj


def _derive_hybrid_key(ec_ss: bytes, pq_ss: bytes, salt: bytes) -> AESGCM:
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=INFO).derive(ec_ss + pq_ss)
    return AESGCM(key)


def encrypt(data: bytes, recipient_pub_hex: str) -> bytes:
    pub_bytes    = bytes.fromhex(recipient_pub_hex)
    ec_pub_bytes = pub_bytes[:ECDH_PUB_LEN]
    pq_pub_bytes = pub_bytes[ECDH_PUB_LEN:ECDH_PUB_LEN + MLKEM_PUB_LEN]

    eph_priv     = generate_private_key(SECP256R1())
    eph_pub      = eph_priv.public_key()
    eph_pub_bytes = eph_pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    x = int.from_bytes(ec_pub_bytes[1:33], "big")
    y = int.from_bytes(ec_pub_bytes[33:65], "big")
    recip_ec_pub = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key()
    ec_ss = eph_priv.exchange(ECDH(), recip_ec_pub)

    pq_ct, pq_ss = MLKem768.encapsulate(pq_pub_bytes)
    aesgcm = _derive_hybrid_key(ec_ss, pq_ss, eph_pub_bytes)
    iv = os.urandom(12)
    ct = aesgcm.encrypt(iv, data, None)
    return GP_MAGIC + eph_pub_bytes + pq_ct + iv + ct


def decrypt(encrypted: bytes, private_key_hex: str) -> bytes:
    if not encrypted.startswith(GP_MAGIC):
        raise ValueError("Invalid wire format — expected PQHB magic")

    priv_bytes    = bytes.fromhex(private_key_hex)
    ec_priv_len   = struct.unpack(">H", priv_bytes[:2])[0]
    ec_priv_bytes = priv_bytes[2:2 + ec_priv_len]
    pq_priv_bytes = priv_bytes[2 + ec_priv_len:]

    off = 4
    eph_pub_bytes = encrypted[off:off+65];           off += 65
    pq_ct         = encrypted[off:off+MLKEM_CT_LEN]; off += MLKEM_CT_LEN
    iv            = encrypted[off:off+12];           off += 12
    ct            = encrypted[off:]

    ec_priv = serialization.load_der_private_key(ec_priv_bytes, password=None)
    x = int.from_bytes(eph_pub_bytes[1:33], "big")
    y = int.from_bytes(eph_pub_bytes[33:65], "big")
    eph_ec_pub = EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key()
    ec_ss = ec_priv.exchange(ECDH(), eph_ec_pub)

    pq_ss  = MLKem768.decapsulate(pq_ct, pq_priv_bytes)
    aesgcm = _derive_hybrid_key(ec_ss, pq_ss, eph_pub_bytes)
    return aesgcm.decrypt(iv, ct, None)


def pad(data: bytes) -> bytes:
    if len(data) > BLOCK_SIZE - 8:
        raise ValueError(f"Data too large (max {BLOCK_SIZE - 8} bytes)")
    block = bytearray(BLOCK_SIZE)
    struct.pack_into(">Q", block, 0, len(data))
    block[8:8+len(data)] = data
    block[8+len(data):] = os.urandom(BLOCK_SIZE - 8 - len(data))
    return bytes(block)


def unpad(block: bytes) -> bytes:
    return block[8:8 + struct.unpack(">Q", block[:8])[0]]


def pubkey_hash(pub_hex: str) -> str:
    return hashlib.sha256(bytes.fromhex(pub_hex)).hexdigest()


def send(data: bytes, recipient_pub_hex: str, api_key: str = "", relay_url: str = RELAY) -> dict:
    encrypted = encrypt(data, recipient_pub_hex)
    padded    = pad(encrypted)
    hash_val  = pubkey_hash(recipient_pub_hex)
    body = {"hash": hash_val, "payload": base64.b64encode(padded).decode()}
    if api_key:
        body["api_key"] = api_key
    resp = requests.post(f"{relay_url}/v2/inbound", json=body, headers={"Content-Type": "application/json"}, timeout=30)
    resp.raise_for_status()
    return resp.json()


def receive(hash_val: str, private_key_hex: str, relay_url: str = RELAY) -> bytes:
    resp = requests.get(f"{relay_url}/v2/outbound/{hash_val}", timeout=30)
    if resp.status_code == 404:
        raise FileNotFoundError("File not found or already retrieved (burn-on-read)")
    resp.raise_for_status()
    return decrypt(unpad(resp.content), private_key_hex)


def check_status(hash_val: str, relay_url: str = RELAY) -> dict:
    return requests.get(f"{relay_url}/v2/status/{hash_val}", timeout=10).json()


def verify_key(api_key: str, relay_url: str = RELAY) -> dict:
    return requests.post(f"{relay_url}/v2/verify-key", json={"api_key": api_key}, timeout=10).json()
