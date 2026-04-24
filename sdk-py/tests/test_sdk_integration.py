"""
SDK-level integration tests. Exercise the GhostPipe class in offline mode
(negotiate_on_init=False, no real relay) to prove the v1 encrypt / decrypt
round trip works end to end through the same code path users hit in production.
"""
import hashlib
import tempfile
from unittest import mock

import pytest

import paramant_sdk
from paramant import wire_format
from paramant_sdk import GhostPipe, GhostPipeError


API_KEY = "pgp_testkey_0123456789abcdef"


@pytest.fixture
def home_tmp(tmp_path, monkeypatch):
    """Isolate ~/.paramant per test."""
    monkeypatch.setenv("HOME", str(tmp_path))
    return tmp_path


def _make_gp(home_tmp, device: str, kem_id=0x0002, sig_id=0x0002):
    return GhostPipe(
        api_key=API_KEY, device=device,
        relay="https://offline.invalid",
        kem_id=kem_id, sig_id=sig_id,
        negotiate_on_init=False,
    )


def test_version_is_3_0_0():
    assert paramant_sdk.__version__ == "3.0.0"


def test_encrypt_decrypt_round_trip_signed(home_tmp):
    sender = _make_gp(home_tmp, "sender-001")
    receiver = _make_gp(home_tmp, "receiver-001")
    receiver._load_keypair()

    plaintext = b"PARAMANT v3 integration check" * 37
    padded, h = sender._encrypt(
        plaintext,
        bytes.fromhex(receiver._load_keypair()["ml_kem_pub"]),
        pad_block=64 * 1024,
    )
    assert wire_format.is_v1(padded)
    assert len(h) == 64
    assert hashlib.sha256(padded).hexdigest() == h

    # The receiver must use its own keypair path to decrypt.
    recovered = receiver._decrypt(padded)
    assert recovered == plaintext


def test_encrypt_decrypt_round_trip_anonymous(home_tmp):
    sender = _make_gp(home_tmp, "sender-anon", sig_id=0x0000)
    receiver = _make_gp(home_tmp, "receiver-anon", sig_id=0x0000)
    receiver._load_keypair()

    plaintext = b"anonymous drop"
    padded, _ = sender._encrypt(
        plaintext,
        bytes.fromhex(receiver._load_keypair()["ml_kem_pub"]),
        pad_block=4 * 1024,  # no signature section -> fits in 4K
    )
    parsed = wire_format.decode(padded[:2000])  # header-area enough to inspect
    assert parsed["sig_id"] == 0x0000
    assert parsed["signature"] is None
    assert receiver._decrypt(padded) == plaintext


def test_pss_round_trip(home_tmp):
    sender = _make_gp(home_tmp, "sender-pss")
    receiver = _make_gp(home_tmp, "receiver-pss")
    receiver._load_keypair()

    plaintext = b"top secret"
    padded, _ = sender._encrypt(
        plaintext,
        bytes.fromhex(receiver._load_keypair()["ml_kem_pub"]),
        pad_block=64 * 1024,  # signed ML-DSA-65 blobs are ~5.5kB with overhead
        pre_shared_secret="correct horse battery staple",
    )
    # Correct PSS works.
    assert receiver._decrypt(padded, pre_shared_secret="correct horse battery staple") == plaintext
    # Wrong PSS fails (GCM tag mismatch).
    with pytest.raises(Exception):
        receiver._decrypt(padded, pre_shared_secret="wrong")
    # No PSS also fails.
    with pytest.raises(Exception):
        receiver._decrypt(padded)


def test_v2_blob_rejected_with_clear_error(home_tmp):
    receiver = _make_gp(home_tmp, "receiver-legacy")
    fake_legacy_blob = b"\x00\x00\x00\x40" + b"\x00" * 4092  # starts with a length prefix, no PQHB
    with pytest.raises(GhostPipeError) as exc:
        receiver._decrypt(fake_legacy_blob)
    assert "not wire format v1" in str(exc.value)
    assert "PQHB" in str(exc.value)


def test_v3_keypair_file_has_pq_fields(home_tmp):
    gp = _make_gp(home_tmp, "kp-device")
    kp = gp._load_keypair()
    assert kp["version"] == 3
    assert len(bytes.fromhex(kp["ml_kem_pub"])) == 1184
    assert len(bytes.fromhex(kp["ml_dsa_pub"])) == 1952
    # The legacy ecdh_pub slot holds a server-compat identity anchor, not a real ECDH key.
    assert len(bytes.fromhex(kp["ecdh_pub"])) == 32


def test_unsupported_kem_id_raises_on_negotiation():
    """An offline-created client sidesteps negotiation; with it enabled against a mock
    relay that doesn't support our algorithms, the constructor must raise."""
    import http.server, threading, json as _json
    body = _json.dumps({
        "wire_version": 1,
        "kem": [{"id": 1, "name": "ML-KEM-512", "loaded": True}],
        "sig": [{"id": 2, "name": "ML-DSA-65", "loaded": True}],
    }).encode()

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        def log_message(self, *a, **kw): pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        from paramant.errors import CapabilityMismatch
        with pytest.raises(CapabilityMismatch):
            GhostPipe(API_KEY, "dev", relay=url, kem_id=0x0002, sig_id=0x0002)
    finally:
        srv.shutdown()
