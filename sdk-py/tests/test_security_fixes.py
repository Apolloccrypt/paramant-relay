"""
Regression tests for the 3.1.0 security fixes (audit 2026-05-23).

These pin behaviour that was exploitable/broken in 3.0.0:
  F1  sdk-py never verified the sender signature on receive
  F3  sdk-py and sdk-js used different sign-inputs + fingerprints (cross-SDK
      signed blobs did not verify)
  F4  kem_id/sig_id were cosmetic (header could claim an unused algorithm)
  F5  zeroization ran ctypes.memset on immutable bytes (UB)
  F2  receipts were verified by the untrusted relay
"""
import tempfile

import pytest

from paramant_sdk import GhostPipe, GhostPipeError, SignatureError, _zero, _secret, _canonical_sign_input
from paramant import crypto, wire_format
from paramant.errors import UnsupportedAlgorithm

API_KEY = "pgp_testkey_0123456789abcdef"


@pytest.fixture
def home_tmp(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def _gp(device, **kw):
    return GhostPipe(API_KEY, device, relay="https://offline.invalid",
                     negotiate_on_init=False, **kw)


def _signed_blob(sender, receiver):
    rec_pub = bytes.fromhex(receiver._load_keypair()["ml_kem_pub"])
    return sender._encrypt(b"authentic payload" * 8, rec_pub, pad_block=64 * 1024)[0]


# ── F3: canonical sign-input matches the sdk-js convention ────────────────────
def test_f3_sign_input_is_js_compatible():
    aad, ct, sp, nonce, pt = b"AAD!", b"CT", b"SENDER", b"N" * 12, b"CIPHER"
    assert _canonical_sign_input(aad, ct, sp, nonce, pt) == ct + sp + nonce + pt + aad


# ── F1: signature verification is enforced ────────────────────────────────────
def test_f1_tampered_signature_rejected(home_tmp):
    sender, receiver = _gp("snd"), _gp("rcv"); receiver._load_keypair()
    p = wire_format.decode(_signed_blob(sender, receiver))
    bad = bytearray(p["signature"]); bad[0] ^= 0xFF
    forged = wire_format.encode(kem_id=p["kem_id"], sig_id=p["sig_id"], ct_kem=p["ct_kem"],
        sender_pub=p["sender_pub"], signature=bytes(bad), nonce=p["nonce"], ciphertext=p["ciphertext"])
    with pytest.raises(SignatureError):
        receiver._decrypt(forged)


def test_f1_swapped_sender_rejected_when_pinned(home_tmp):
    sender, receiver = _gp("snd"), _gp("rcv"); receiver._load_keypair()
    p = wire_format.decode(_signed_blob(sender, receiver))
    atk = crypto.sig_keygen()
    aad = wire_format.build_aad(kem_id=p["kem_id"], sig_id=p["sig_id"])
    si = _canonical_sign_input(aad, p["ct_kem"], atk.public_key, p["nonce"], p["ciphertext"])
    forged = wire_format.encode(kem_id=p["kem_id"], sig_id=p["sig_id"], ct_kem=p["ct_kem"],
        sender_pub=atk.public_key, signature=crypto.sig_sign(atk.secret_key, si),
        nonce=p["nonce"], ciphertext=p["ciphertext"])
    assert receiver._decrypt(forged) == b"authentic payload" * 8           # valid for attacker key
    real = bytes.fromhex(sender._load_keypair()["ml_dsa_pub"])
    with pytest.raises(SignatureError):
        receiver._decrypt(forged, expected_sender_sig_pub=real)            # rejected when pinned


def test_f1_honest_round_trip(home_tmp):
    sender, receiver = _gp("snd"), _gp("rcv"); receiver._load_keypair()
    real = bytes.fromhex(sender._load_keypair()["ml_dsa_pub"])
    assert receiver._decrypt(_signed_blob(sender, receiver),
                             expected_sender_sig_pub=real) == b"authentic payload" * 8


# ── F3: fingerprint binds the signing key, 5 groups / 20 hex ──────────────────
def test_f3_fingerprint_binds_signing_key(home_tmp):
    kp = _gp("dev")._load_keypair()
    fp1 = GhostPipe._compute_fingerprint(kp["ml_kem_pub"], kp["ml_dsa_pub"])
    fp2 = GhostPipe._compute_fingerprint(kp["ml_kem_pub"], crypto.sig_keygen().public_key.hex())
    assert fp1 != fp2
    assert len(fp1.replace("-", "")) == 20 and fp1.count("-") == 4


# ── F4: unimplemented algorithm ids are rejected (no cosmetic header) ─────────
def test_f4_unimplemented_kem_rejected(home_tmp):
    with pytest.raises(UnsupportedAlgorithm):
        _gp("dev", kem_id=0x0003)   # ML-KEM-1024 not performed by this build


def test_f4_unimplemented_sig_rejected(home_tmp):
    with pytest.raises(UnsupportedAlgorithm):
        _gp("dev", sig_id=0x0003)   # ML-DSA-87 not performed by this build


# ── F5: zeroization is defined and wipes ──────────────────────────────────────
def test_f5_secret_wipes(home_tmp):
    buf = _secret(b"\x01\x02\x03"); _zero(buf)
    assert bytes(buf) == b"\x00\x00\x00"
    _zero(b"immutable"); _zero(None)   # no UB, no raise


# ── F2: receipts verified locally against a pinned relay key ──────────────────
def test_f2_receipt_local_verify(home_tmp):
    import json
    relay_id = crypto.sig_keygen()
    receipt = {"hash": "abc", "burn_confirmed": True, "sector": "health"}
    payload = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
    signed = {**receipt, "sig": crypto.sig_sign(relay_id.secret_key, payload).hex()}
    gp = _gp("rcv", relay_identity_pub=relay_id.public_key.hex())
    assert gp.verify_receipt(signed)["verified_locally"]
    with pytest.raises(GhostPipeError):
        gp.verify_receipt({**receipt, "burn_confirmed": False, "sig": signed["sig"]})
    with pytest.raises(GhostPipeError):
        _gp("rcv2").verify_receipt({"hash": "x", "sig": "00"})   # no pinned key
