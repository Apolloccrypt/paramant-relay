"""
End-to-end crypto tests: pqcrypto primitives + AES-256-GCM with v1 AAD.

These tests intentionally use real pqcrypto (no mocks) because the v2.x
tests passed with a mocked kyber stub while production used the ECDH
fallback. Real crypto, or it doesn't ship.
"""
import hashlib
import os

import pytest

from paramant import crypto, wire_format


def test_ml_kem_768_round_trip():
    kp = crypto.kem_keygen()
    assert len(kp.public_key) == crypto.ML_KEM_768_PUBLIC_KEY_SIZE == 1184
    assert len(kp.secret_key) == crypto.ML_KEM_768_SECRET_KEY_SIZE
    ct, ss1 = crypto.kem_encapsulate(kp.public_key)
    assert len(ct) == crypto.ML_KEM_768_CIPHERTEXT_SIZE == 1088
    assert len(ss1) == 32
    ss2 = crypto.kem_decapsulate(kp.secret_key, ct)
    assert ss1 == ss2


def test_ml_dsa_65_sign_verify():
    kp = crypto.sig_keygen()
    assert len(kp.public_key) == crypto.ML_DSA_65_PUBLIC_KEY_SIZE == 1952
    msg = b"paramant v3 smoke"
    sig = crypto.sig_sign(kp.secret_key, msg)
    assert crypto.sig_verify(kp.public_key, msg, sig) is True
    assert crypto.sig_verify(kp.public_key, msg + b"!", sig) is False


def test_kem_encapsulate_rejects_wrong_key_length():
    with pytest.raises(Exception):
        crypto.kem_encapsulate(b"\x00" * 100)


def test_end_to_end_encrypt_decrypt_via_v1_blob():
    """Full send/receive simulation: keygen -> encaps -> AEAD -> encode -> decode -> decaps -> AEAD."""
    plaintext = b"the quick brown fox jumps over the lazy dog" * 50

    recipient = crypto.kem_keygen()
    sender = crypto.sig_keygen()

    ct_kem, shared_secret = crypto.kem_encapsulate(recipient.public_key)
    aes_key = crypto.derive_key(shared_secret, salt=ct_kem[:32])

    aad = wire_format.build_aad(
        kem_id=crypto.DEFAULT_KEM_ID,
        sig_id=crypto.DEFAULT_SIG_ID,
        chunk_index=0,
    )
    nonce, ciphertext = crypto.aes_gcm_encrypt(aes_key, plaintext, aad)

    # Sign over a canonical message that binds every field in the blob.
    sign_input = hashlib.sha256(
        aad + ct_kem + sender.public_key + nonce + ciphertext
    ).digest()
    signature = crypto.sig_sign(sender.secret_key, sign_input)

    assert aad[:10] == bytes.fromhex("50514842010002000200")  # header
    assert aad[10:] == (0).to_bytes(4, "big")                  # chunk_index

    blob = wire_format.encode(
        kem_id=crypto.DEFAULT_KEM_ID,
        sig_id=crypto.DEFAULT_SIG_ID,
        ct_kem=ct_kem,
        sender_pub=sender.public_key,
        signature=signature,
        nonce=nonce,
        ciphertext=ciphertext,
    )
    assert wire_format.is_v1(blob)

    parsed = wire_format.decode(blob)
    assert parsed["kem_id"] == crypto.DEFAULT_KEM_ID
    assert parsed["sig_id"] == crypto.DEFAULT_SIG_ID

    # Verify sender's signature: rebuild the 14-byte GCM AAD and feed it in.
    rebuilt_aad = wire_format.build_aad(
        kem_id=parsed["kem_id"], sig_id=parsed["sig_id"], chunk_index=0
    )
    verify_input = hashlib.sha256(
        rebuilt_aad + parsed["ct_kem"] + parsed["sender_pub"] + parsed["nonce"] + parsed["ciphertext"]
    ).digest()
    assert crypto.sig_verify(parsed["sender_pub"], verify_input, parsed["signature"])

    # Recover the shared secret and decrypt.
    recovered_ss = crypto.kem_decapsulate(recipient.secret_key, parsed["ct_kem"])
    assert recovered_ss == shared_secret
    recovered_key = crypto.derive_key(recovered_ss, salt=parsed["ct_kem"][:32])
    recovered_aad = rebuilt_aad
    recovered_plain = crypto.aes_gcm_decrypt(
        recovered_key, parsed["nonce"], parsed["ciphertext"], recovered_aad
    )
    assert recovered_plain == plaintext


def test_aad_tampering_breaks_decryption():
    """Spec guarantee: a bit-flip in KEM_ID or SIG_ID must fail GCM verification."""
    recipient = crypto.kem_keygen()
    ct_kem, ss = crypto.kem_encapsulate(recipient.public_key)
    key = crypto.derive_key(ss, salt=ct_kem[:32])
    aad = wire_format.build_aad(kem_id=0x0002, sig_id=0x0002, chunk_index=0)
    nonce, ciphertext = crypto.aes_gcm_encrypt(key, b"secret", aad)
    bad_aad = wire_format.build_aad(kem_id=0x0001, sig_id=0x0002, chunk_index=0)
    with pytest.raises(Exception):
        crypto.aes_gcm_decrypt(key, nonce, ciphertext, bad_aad)


def test_import_error_message_is_clear(monkeypatch):
    """The module docstring promises a clear message when pqcrypto is missing.
    We can't unimport it, but we can check the crypto module's documented claim
    is present in-tree."""
    import importlib.util
    spec = importlib.util.find_spec("paramant.crypto")
    src = open(spec.origin).read()
    assert "pqcrypto >= 0.4 is required" in src
    assert "ECDH fallback was removed" in src
