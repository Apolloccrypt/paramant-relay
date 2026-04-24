"""
Wire format v1 conformance tests.

The SHA-256 vectors come from docs/wire-format-v1.md § Test vectors and are
the single point of interop truth. If either hash fails, the encoder is wrong
and the blob will NOT decode on the relay.
"""
import hashlib

import pytest

from paramant import wire_format
from paramant.errors import InvalidFlags, InvalidMagic, InvalidVersion, MalformedBlob


ML_KEM_768 = 0x0002
ML_DSA_65 = 0x0002
NO_SIG = 0x0000


def _repeat(pattern_hex: str, count: int) -> bytes:
    return bytes.fromhex(pattern_hex) * count


# Test-vector inputs from docs/wire-format-v1.md.
CT_KEM = _repeat("00112233445566778899aabbccddeeff", 68)       # 1088 bytes
SENDER_PUB = _repeat("cafe", 296)                              # 592 bytes
SIGNATURE = _repeat("babe", 1654)                              # 3308 bytes
NONCE = bytes.fromhex("000102030405060708090a0b")              # 12 bytes
CIPHERTEXT = _repeat("deadbeef", 16)                           # 64 bytes

VECTOR_SIGNED_SHA256 = "002b4f6aad4fa992804a3e94c46d514b4f842e9f5c283f7a31d7c76722d0476a"
VECTOR_ANON_SHA256 = "46bce75b12e90ed312420fafcbead4108d55aa25273aee3ce4f2b4f61b3d19ef"


def test_lengths_match_spec():
    assert len(CT_KEM) == 1088
    assert len(SENDER_PUB) == 592
    assert len(SIGNATURE) == 3308
    assert len(NONCE) == 12
    assert len(CIPHERTEXT) == 64


def test_vector_1_signed_ml_kem_768_ml_dsa_65():
    blob = wire_format.encode(
        kem_id=ML_KEM_768, sig_id=ML_DSA_65,
        ct_kem=CT_KEM, sender_pub=SENDER_PUB, signature=SIGNATURE,
        nonce=NONCE, ciphertext=CIPHERTEXT,
    )
    assert len(blob) == 5090
    assert blob[:10].hex() == "50514842010002000200"
    assert blob[:64].hex() == (
        "505148420100020002000000044000112233445566778899aabbccddeeff"
        "00112233445566778899aabbccddeeff00112233445566778899aabbccdd"
        "eeff0011"
    )
    assert hashlib.sha256(blob).hexdigest() == VECTOR_SIGNED_SHA256


def test_vector_2_anonymous_no_signature_section():
    blob = wire_format.encode(
        kem_id=ML_KEM_768, sig_id=NO_SIG,
        ct_kem=CT_KEM, sender_pub=SENDER_PUB, signature=None,
        nonce=NONCE, ciphertext=CIPHERTEXT,
    )
    assert len(blob) == 1778
    assert blob[:10].hex() == "50514842010002000000"
    assert blob[:64].hex() == (
        "505148420100020000000000044000112233445566778899aabbccddeeff"
        "00112233445566778899aabbccddeeff00112233445566778899aabbccdd"
        "eeff0011"
    )
    assert hashlib.sha256(blob).hexdigest() == VECTOR_ANON_SHA256


def test_anonymous_omits_signature_section_entirely():
    """sig_id=0x0000 must not emit a 4-byte zero-length prefix for the signature."""
    signed_blob = wire_format.encode(
        kem_id=ML_KEM_768, sig_id=ML_DSA_65,
        ct_kem=CT_KEM, sender_pub=SENDER_PUB, signature=SIGNATURE,
        nonce=NONCE, ciphertext=CIPHERTEXT,
    )
    anon_blob = wire_format.encode(
        kem_id=ML_KEM_768, sig_id=NO_SIG,
        ct_kem=CT_KEM, sender_pub=SENDER_PUB, signature=None,
        nonce=NONCE, ciphertext=CIPHERTEXT,
    )
    # A zero-length prefix would add exactly 4 bytes; the real omission drops 4 + len(sig).
    assert len(signed_blob) - len(anon_blob) == 4 + len(SIGNATURE)


def test_round_trip_signed():
    blob = wire_format.encode(
        kem_id=ML_KEM_768, sig_id=ML_DSA_65,
        ct_kem=CT_KEM, sender_pub=SENDER_PUB, signature=SIGNATURE,
        nonce=NONCE, ciphertext=CIPHERTEXT,
    )
    d = wire_format.decode(blob)
    assert d["version"] == 1
    assert d["kem_id"] == ML_KEM_768
    assert d["sig_id"] == ML_DSA_65
    assert d["flags"] == 0x00
    assert d["ct_kem"] == CT_KEM
    assert d["sender_pub"] == SENDER_PUB
    assert d["signature"] == SIGNATURE
    assert d["nonce"] == NONCE
    assert d["ciphertext"] == CIPHERTEXT
    assert d["aad"] == blob[:10]
    assert d["consumed_bytes"] == len(blob)


def test_round_trip_anonymous():
    blob = wire_format.encode(
        kem_id=ML_KEM_768, sig_id=NO_SIG,
        ct_kem=CT_KEM, sender_pub=SENDER_PUB, signature=None,
        nonce=NONCE, ciphertext=CIPHERTEXT,
    )
    d = wire_format.decode(blob)
    assert d["sig_id"] == NO_SIG
    assert d["signature"] is None
    assert d["ct_kem"] == CT_KEM
    assert d["ciphertext"] == CIPHERTEXT


def test_is_v1_positive_and_negative():
    blob = wire_format.encode(
        kem_id=ML_KEM_768, sig_id=NO_SIG,
        ct_kem=CT_KEM, sender_pub=SENDER_PUB, signature=None,
        nonce=NONCE, ciphertext=CIPHERTEXT,
    )
    assert wire_format.is_v1(blob) is True
    assert wire_format.is_v1(b"PQHB") is True  # exactly the magic
    assert wire_format.is_v1(b"PQH") is False  # too short
    assert wire_format.is_v1(b"NOPE" + blob[4:]) is False
    assert wire_format.is_v1("PQHB not bytes") is False


def test_decode_rejects_bad_magic():
    blob = bytearray(wire_format.encode(
        kem_id=ML_KEM_768, sig_id=NO_SIG,
        ct_kem=CT_KEM, sender_pub=SENDER_PUB, signature=None,
        nonce=NONCE, ciphertext=CIPHERTEXT,
    ))
    blob[0] = ord("X")
    with pytest.raises(InvalidMagic):
        wire_format.decode(bytes(blob))


def test_decode_rejects_bad_version():
    blob = bytearray(wire_format.encode(
        kem_id=ML_KEM_768, sig_id=NO_SIG,
        ct_kem=CT_KEM, sender_pub=SENDER_PUB, signature=None,
        nonce=NONCE, ciphertext=CIPHERTEXT,
    ))
    blob[4] = 0x02
    with pytest.raises(InvalidVersion):
        wire_format.decode(bytes(blob))


def test_decode_rejects_nonzero_flags():
    blob = bytearray(wire_format.encode(
        kem_id=ML_KEM_768, sig_id=NO_SIG,
        ct_kem=CT_KEM, sender_pub=SENDER_PUB, signature=None,
        nonce=NONCE, ciphertext=CIPHERTEXT,
    ))
    blob[9] = 0x01
    with pytest.raises(InvalidFlags):
        wire_format.decode(bytes(blob))


def test_decode_rejects_truncated():
    blob = wire_format.encode(
        kem_id=ML_KEM_768, sig_id=NO_SIG,
        ct_kem=CT_KEM, sender_pub=SENDER_PUB, signature=None,
        nonce=NONCE, ciphertext=CIPHERTEXT,
    )
    with pytest.raises(MalformedBlob):
        wire_format.decode(blob[: len(blob) - 10])


def test_encode_requires_signature_when_signed():
    with pytest.raises(ValueError):
        wire_format.encode(
            kem_id=ML_KEM_768, sig_id=ML_DSA_65,
            ct_kem=CT_KEM, sender_pub=SENDER_PUB, signature=None,
            nonce=NONCE, ciphertext=CIPHERTEXT,
        )


def test_encode_rejects_signature_when_anonymous():
    with pytest.raises(ValueError):
        wire_format.encode(
            kem_id=ML_KEM_768, sig_id=NO_SIG,
            ct_kem=CT_KEM, sender_pub=SENDER_PUB, signature=SIGNATURE,
            nonce=NONCE, ciphertext=CIPHERTEXT,
        )


def test_build_aad_binds_header_bytes_and_chunk_index():
    aad = wire_format.build_aad(kem_id=ML_KEM_768, sig_id=ML_DSA_65, chunk_index=0)
    assert aad.hex() == "5051484201000200020000000000"
    aad7 = wire_format.build_aad(kem_id=ML_KEM_768, sig_id=ML_DSA_65, chunk_index=7)
    assert aad7[:10] == aad[:10]
    assert aad7[10:] == (7).to_bytes(4, "big")
