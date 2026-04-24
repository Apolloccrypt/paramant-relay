"""
Post-quantum crypto primitives backed by pqcrypto (backbone-hq, Apache-2.0).

pqcrypto is a thin CFFI wrapper over PQClean's audited C implementations. It
ships pre-built wheels for Linux, macOS and Windows, so no compiler is needed
on end-user machines.

Default algorithm IDs match docs/wire-format-v1.md:
    KEM: ML-KEM-768 (0x0002, FIPS 203)
    SIG: ML-DSA-65  (0x0002, FIPS 204)

The v2.x helper _try_kyber() and the silent ECDH fallback are gone. If
pqcrypto cannot be imported, module load raises ImportError with a clear
message — we never silently degrade.
"""
from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from typing import Tuple

try:
    from pqcrypto.kem.ml_kem_768 import (
        generate_keypair as _kem_keypair,
        encrypt as _kem_encaps,
        decrypt as _kem_decaps,
        PUBLIC_KEY_SIZE as ML_KEM_768_PUBLIC_KEY_SIZE,
        SECRET_KEY_SIZE as ML_KEM_768_SECRET_KEY_SIZE,
        CIPHERTEXT_SIZE as ML_KEM_768_CIPHERTEXT_SIZE,
    )
    from pqcrypto.sign.ml_dsa_65 import (
        generate_keypair as _sig_keypair,
        sign as _sig_sign,
        verify as _sig_verify,
        PUBLIC_KEY_SIZE as ML_DSA_65_PUBLIC_KEY_SIZE,
        SECRET_KEY_SIZE as ML_DSA_65_SECRET_KEY_SIZE,
        SIGNATURE_SIZE as ML_DSA_65_SIGNATURE_SIZE,
    )
except ImportError as exc:  # pragma: no cover - exercised only without pqcrypto
    raise ImportError(
        "pqcrypto >= 0.4 is required. The silent ECDH fallback was removed in "
        "paramant-sdk 3.0.0 because it did not provide post-quantum protection "
        "despite the SDK's marketing claim. Install with: pip install 'pqcrypto>=0.4'"
    ) from exc

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from .errors import ParamantError

KEM_ID_ML_KEM_768 = 0x0002
SIG_ID_NONE = 0x0000
SIG_ID_ML_DSA_65 = 0x0002

DEFAULT_KEM_ID = KEM_ID_ML_KEM_768
DEFAULT_SIG_ID = SIG_ID_ML_DSA_65


@dataclass(frozen=True)
class KemKeypair:
    public_key: bytes
    secret_key: bytes


@dataclass(frozen=True)
class SigKeypair:
    public_key: bytes
    secret_key: bytes


def kem_keygen() -> KemKeypair:
    pk, sk = _kem_keypair()
    return KemKeypair(public_key=bytes(pk), secret_key=bytes(sk))


def kem_encapsulate(recipient_pub: bytes) -> Tuple[bytes, bytes]:
    """Return (ct_kem, shared_secret). shared_secret is 32 bytes."""
    if len(recipient_pub) != ML_KEM_768_PUBLIC_KEY_SIZE:
        raise ParamantError(
            f"recipient ML-KEM-768 public key must be {ML_KEM_768_PUBLIC_KEY_SIZE} bytes, "
            f"got {len(recipient_pub)}"
        )
    ct, ss = _kem_encaps(recipient_pub)
    return bytes(ct), bytes(ss)


def kem_decapsulate(secret_key: bytes, ct_kem: bytes) -> bytes:
    if len(secret_key) != ML_KEM_768_SECRET_KEY_SIZE:
        raise ParamantError(
            f"ML-KEM-768 secret key must be {ML_KEM_768_SECRET_KEY_SIZE} bytes"
        )
    if len(ct_kem) != ML_KEM_768_CIPHERTEXT_SIZE:
        raise ParamantError(
            f"ML-KEM-768 ciphertext must be {ML_KEM_768_CIPHERTEXT_SIZE} bytes, got {len(ct_kem)}"
        )
    return bytes(_kem_decaps(secret_key, ct_kem))


def sig_keygen() -> SigKeypair:
    pk, sk = _sig_keypair()
    return SigKeypair(public_key=bytes(pk), secret_key=bytes(sk))


def sig_sign(secret_key: bytes, message: bytes) -> bytes:
    return bytes(_sig_sign(secret_key, message))


def sig_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    return bool(_sig_verify(public_key, message, signature))


def derive_key(shared_secret: bytes, salt: bytes, info: bytes = b"paramant-v1-aes-key") -> bytes:
    """HKDF-SHA256 from a KEM shared secret. 32 bytes output for AES-256-GCM."""
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(shared_secret)


def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes, nonce: bytes = None) -> Tuple[bytes, bytes]:
    """Encrypt with AES-256-GCM. Returns (nonce, ciphertext_with_tag)."""
    if nonce is None:
        nonce = os.urandom(12)
    if len(nonce) != 12:
        raise ValueError("AES-GCM nonce must be 12 bytes")
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ct


def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return AESGCM(key).decrypt(nonce, ciphertext, aad)


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


__all__ = [
    "KEM_ID_ML_KEM_768",
    "SIG_ID_NONE",
    "SIG_ID_ML_DSA_65",
    "DEFAULT_KEM_ID",
    "DEFAULT_SIG_ID",
    "ML_KEM_768_PUBLIC_KEY_SIZE",
    "ML_KEM_768_SECRET_KEY_SIZE",
    "ML_KEM_768_CIPHERTEXT_SIZE",
    "ML_DSA_65_PUBLIC_KEY_SIZE",
    "ML_DSA_65_SECRET_KEY_SIZE",
    "ML_DSA_65_SIGNATURE_SIZE",
    "KemKeypair",
    "SigKeypair",
    "kem_keygen",
    "kem_encapsulate",
    "kem_decapsulate",
    "sig_keygen",
    "sig_sign",
    "sig_verify",
    "derive_key",
    "aes_gcm_encrypt",
    "aes_gcm_decrypt",
    "sha256",
]
