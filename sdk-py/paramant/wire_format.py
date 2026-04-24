"""
Paramant wire format v1 (PQHB) — Python encoder / decoder.

Implements the spec in docs/wire-format-v1.md byte-for-byte. The relay's
Node implementation in relay/crypto/wire-format.js is authoritative; this
module MUST produce blobs that decode cleanly there.

Public API:
    encode(kem_id, sig_id, ct_kem, sender_pub, signature, nonce, ciphertext) -> bytes
    decode(blob) -> dict
    build_aad(kem_id, sig_id, flags=0, chunk_index=0) -> bytes
    is_v1(blob) -> bool
"""
from __future__ import annotations

from typing import Optional

from .errors import InvalidFlags, InvalidMagic, InvalidVersion, MalformedBlob

MAGIC = b"PQHB"
VERSION = 1
SUPPORTED_VERSIONS = (VERSION,)
HEADER_SIZE = 10
NONCE_SIZE = 12
_U16_MAX = 0xFFFF
_U32_MAX = 0xFFFFFFFF


def _u16_be(v: int) -> bytes:
    if not (0 <= v <= _U16_MAX):
        raise ValueError(f"value {v} out of range for uint16")
    return v.to_bytes(2, "big")


def _u32_be(v: int) -> bytes:
    if not (0 <= v <= _U32_MAX):
        raise ValueError(f"value {v} out of range for uint32")
    return v.to_bytes(4, "big")


def encode(
    kem_id: int,
    sig_id: int,
    ct_kem: bytes,
    sender_pub: bytes,
    signature: Optional[bytes],
    nonce: bytes,
    ciphertext: bytes,
    flags: int = 0x00,
) -> bytes:
    """Produce a v1 blob. See docs/wire-format-v1.md."""
    if not (0 <= kem_id <= _U16_MAX):
        raise ValueError("kem_id must be uint16")
    if not (0 <= sig_id <= _U16_MAX):
        raise ValueError("sig_id must be uint16")
    if flags != 0x00:
        raise InvalidFlags(flags)
    if not isinstance(ct_kem, (bytes, bytearray)):
        raise TypeError("ct_kem must be bytes")
    if not isinstance(sender_pub, (bytes, bytearray)):
        raise TypeError("sender_pub must be bytes")
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != NONCE_SIZE:
        raise ValueError(f"nonce must be exactly {NONCE_SIZE} bytes")
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise TypeError("ciphertext must be bytes")

    has_signature = sig_id != 0x0000
    if has_signature and signature is None:
        raise ValueError("signature is required when sig_id != 0x0000")
    if not has_signature and signature:
        raise ValueError("signature must be absent when sig_id == 0x0000")

    header = b"".join((
        MAGIC,
        bytes([VERSION]),
        _u16_be(kem_id),
        _u16_be(sig_id),
        bytes([flags]),
    ))
    # Invariant: the spec requires exactly 10 bytes of header.
    assert len(header) == HEADER_SIZE

    parts = [
        header,
        _u32_be(len(ct_kem)), bytes(ct_kem),
        _u32_be(len(sender_pub)), bytes(sender_pub),
    ]
    if has_signature:
        parts.append(_u32_be(len(signature)))
        parts.append(bytes(signature))
    parts.append(bytes(nonce))
    parts.append(_u32_be(len(ciphertext)))
    parts.append(bytes(ciphertext))

    return b"".join(parts)


def decode(blob: bytes) -> dict:
    """Parse a v1 blob. Raises InvalidMagic/InvalidVersion/InvalidFlags/MalformedBlob.

    Returns a dict with keys: version, kem_id, sig_id, flags, ct_kem, sender_pub,
    signature (None if sig_id==0), nonce, ciphertext, aad, consumed_bytes.
    """
    if not isinstance(blob, (bytes, bytearray)):
        raise TypeError("blob must be bytes")
    if len(blob) < HEADER_SIZE:
        raise MalformedBlob("blob too short for header")

    if blob[0:4] != MAGIC:
        raise InvalidMagic(bytes(blob[0:4]))

    version = blob[4]
    if version not in SUPPORTED_VERSIONS:
        raise InvalidVersion(version, SUPPORTED_VERSIONS)

    kem_id = int.from_bytes(blob[5:7], "big")
    sig_id = int.from_bytes(blob[7:9], "big")
    flags = blob[9]
    if flags != 0x00:
        raise InvalidFlags(flags)

    off = HEADER_SIZE

    def read_lp(label: str) -> bytes:
        nonlocal off
        if len(blob) < off + 4:
            raise MalformedBlob(f"truncated at {label} length")
        n = int.from_bytes(blob[off:off + 4], "big")
        off += 4
        if len(blob) < off + n:
            raise MalformedBlob(f"truncated at {label} body (need {n}, have {len(blob) - off})")
        out = bytes(blob[off:off + n])
        off += n
        return out

    ct_kem = read_lp("ct_kem")
    sender_pub = read_lp("sender_pub")

    signature = None
    if sig_id != 0x0000:
        signature = read_lp("signature")

    if len(blob) < off + NONCE_SIZE:
        raise MalformedBlob("truncated at nonce")
    nonce = bytes(blob[off:off + NONCE_SIZE])
    off += NONCE_SIZE

    ciphertext = read_lp("ciphertext")

    return {
        "version": version,
        "kem_id": kem_id,
        "sig_id": sig_id,
        "flags": flags,
        "ct_kem": ct_kem,
        "sender_pub": sender_pub,
        "signature": signature,
        "nonce": nonce,
        "ciphertext": ciphertext,
        "aad": bytes(blob[0:HEADER_SIZE]),
        "consumed_bytes": off,
    }


def build_aad(kem_id: int, sig_id: int, flags: int = 0x00, chunk_index: int = 0) -> bytes:
    """Build the AES-256-GCM AAD per spec: header(10) || chunk_index_be32."""
    if flags != 0x00:
        raise InvalidFlags(flags)
    return b"".join((
        MAGIC,
        bytes([VERSION]),
        _u16_be(kem_id),
        _u16_be(sig_id),
        bytes([flags]),
        _u32_be(chunk_index),
    ))


def is_v1(blob: bytes) -> bool:
    """Return True iff blob starts with the PQHB magic."""
    return isinstance(blob, (bytes, bytearray)) and len(blob) >= 4 and blob[0:4] == MAGIC
