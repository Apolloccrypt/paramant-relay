#!/usr/bin/env python3
"""sdk-py crypto adapter. PQ ops via the REAL pqcrypto (PQClean) through
sdk-py's own paramant.crypto module; wire-format via the REAL
sdk-py/paramant/wire_format.py; HKDF + AES-256-GCM via sdk-py's
paramant.crypto (pyca/cryptography); canonical JSON via the exact form
sdk-py uses for receipts (paramant_sdk.py:800).

Reads one JSON request from stdin, writes one JSON response to stdout.
On a missing real dependency: {"ok": false, "error": ...} + exit 3. No mock.
"""
import json
import os
import sys


def emit_ok(**kw):
    sys.stdout.write(json.dumps({"ok": True, **kw}))
    sys.exit(0)


def emit_fail(msg):
    sys.stdout.write(json.dumps({"ok": False, "error": msg}))
    sys.exit(3)


def main():
    req = json.loads(sys.stdin.read())
    op = req.get("op")

    sdk_py_dir = os.environ.get("PARAMANT_SDK_PY_DIR")
    if not sdk_py_dir:
        emit_fail("PARAMANT_SDK_PY_DIR not set — cannot locate the real sdk-py package.")
    if sdk_py_dir not in sys.path:
        sys.path.insert(0, sdk_py_dir)

    try:
        from paramant import crypto, wire_format
    except Exception as e:  # noqa: BLE001 — surface the exact missing piece
        emit_fail(
            "could not import the real sdk-py crypto/wire_format (pqcrypto or "
            f"cryptography unavailable in this interpreter {sys.executable}): {e!r}"
        )
        return

    def hx(b):
        return bytes(b).hex()

    def unhx(h):
        return bytes.fromhex(h)

    if op == "kem-keygen":
        kp = crypto.kem_keygen()
        emit_ok(pubHex=hx(kp.public_key), skHex=hx(kp.secret_key))
    elif op == "kem-encaps":
        ct, ss = crypto.kem_encapsulate(unhx(req["pubHex"]))
        emit_ok(ctHex=hx(ct), ssHex=hx(ss))
    elif op == "kem-decaps":
        ss = crypto.kem_decapsulate(unhx(req["skHex"]), unhx(req["ctHex"]))
        emit_ok(ssHex=hx(ss))
    elif op == "sig-keygen":
        kp = crypto.sig_keygen()
        emit_ok(pubHex=hx(kp.public_key), skHex=hx(kp.secret_key))
    elif op == "sig-sign":
        sig = crypto.sig_sign(unhx(req["skHex"]), unhx(req["msgHex"]))
        emit_ok(sigHex=hx(sig))
    elif op == "sig-verify":
        valid = crypto.sig_verify(unhx(req["pubHex"]), unhx(req["msgHex"]), unhx(req["sigHex"]))
        emit_ok(valid=bool(valid))
    elif op == "hkdf":
        key = crypto.derive_key(unhx(req["ssHex"]), unhx(req["saltHex"]), req["info"].encode())
        emit_ok(keyHex=hx(key))
    elif op == "aead-encrypt":
        # crypto.aes_gcm_encrypt(key, plaintext, aad, nonce) -> (nonce, ct)
        _, ct = crypto.aes_gcm_encrypt(unhx(req["keyHex"]), unhx(req["ptHex"]),
                                       unhx(req["aadHex"]), unhx(req["nonceHex"]))
        emit_ok(ctHex=hx(ct))
    elif op == "aead-decrypt":
        pt = crypto.aes_gcm_decrypt(unhx(req["keyHex"]), unhx(req["nonceHex"]),
                                    unhx(req["ctHex"]), unhx(req["aadHex"]))
        emit_ok(ptHex=hx(pt))
    elif op == "wire-encode":
        sig = unhx(req["signatureHex"]) if req.get("signatureHex") else None
        blob = wire_format.encode(
            kem_id=req["kemId"], sig_id=req["sigId"],
            ct_kem=unhx(req["ctKemHex"]), sender_pub=unhx(req["senderPubHex"]),
            signature=sig, nonce=unhx(req["nonceHex"]),
            ciphertext=unhx(req["ciphertextHex"]),
        )
        import hashlib
        emit_ok(blobHex=hx(blob), sha256Hex=hashlib.sha256(blob).hexdigest(), len=len(blob))
    elif op == "canonical":
        # The exact form sdk-py signs/verifies receipts with (paramant_sdk.py:800):
        # json.dumps(r, sort_keys=True, separators=(",", ":")).encode()
        payload = json.dumps(req["value"], sort_keys=True, separators=(",", ":")).encode()
        emit_ok(bytesHex=hx(payload))
    else:
        emit_fail(f"unknown op: {op}")


if __name__ == "__main__":
    try:
        main()
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        emit_fail(repr(e))
