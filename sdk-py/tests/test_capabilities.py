"""
Capability negotiation tests. Uses an in-process HTTP server so the tests
run without a live relay.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from paramant import capabilities
from paramant.errors import CapabilityMismatch, ParamantError


def _make_server(body: bytes, status: int = 200, content_type: str = "application/json"):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/v2/capabilities":
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_error(404)

        def log_message(self, *a, **kw):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}"


def test_fetch_capabilities_parses_registry_shape():
    body = json.dumps({
        "wire_version": 1,
        "kem": [{"id": 2, "name": "ML-KEM-768", "loaded": True}],
        "sig": [
            {"id": 0, "name": "none", "loaded": True},
            {"id": 2, "name": "ML-DSA-65", "loaded": True},
        ],
    }).encode()
    srv, url = _make_server(body)
    try:
        caps = capabilities.fetch_capabilities(url)
        assert caps.wire_version == 1
        assert caps.supports_kem(0x0002)
        assert caps.supports_sig(0x0000)
        assert caps.supports_sig(0x0002)
        assert not caps.supports_kem(0x0003)
        assert "ML-KEM-768" in caps.kem_names()
        assert "none" in caps.sig_names()
    finally:
        srv.shutdown()


def test_validate_raises_on_wire_version_mismatch():
    caps = capabilities.RelayCapabilities(
        wire_version=2,
        kem=[capabilities.AlgorithmEntry(id=2, name="ML-KEM-768", loaded=True)],
        sig=[capabilities.AlgorithmEntry(id=2, name="ML-DSA-65", loaded=True)],
    )
    with pytest.raises(CapabilityMismatch):
        capabilities.validate(caps, kem_id=0x0002, sig_id=0x0002)


def test_validate_raises_on_unsupported_kem():
    caps = capabilities.RelayCapabilities(
        wire_version=1,
        kem=[capabilities.AlgorithmEntry(id=1, name="ML-KEM-512", loaded=True)],
        sig=[capabilities.AlgorithmEntry(id=2, name="ML-DSA-65", loaded=True)],
    )
    with pytest.raises(CapabilityMismatch):
        capabilities.validate(caps, kem_id=0x0002, sig_id=0x0002)


def test_validate_raises_on_unsupported_sig():
    caps = capabilities.RelayCapabilities(
        wire_version=1,
        kem=[capabilities.AlgorithmEntry(id=2, name="ML-KEM-768", loaded=True)],
        sig=[capabilities.AlgorithmEntry(id=0, name="none", loaded=True)],
    )
    with pytest.raises(CapabilityMismatch):
        capabilities.validate(caps, kem_id=0x0002, sig_id=0x0002)


def test_validate_accepts_matching_combo():
    caps = capabilities.RelayCapabilities(
        wire_version=1,
        kem=[capabilities.AlgorithmEntry(id=2, name="ML-KEM-768", loaded=True)],
        sig=[capabilities.AlgorithmEntry(id=2, name="ML-DSA-65", loaded=True)],
    )
    capabilities.validate(caps, kem_id=0x0002, sig_id=0x0002)  # no raise


def test_fetch_capabilities_rejects_non_json():
    srv, url = _make_server(b"<html>oops</html>", content_type="text/html")
    try:
        with pytest.raises(ParamantError):
            capabilities.fetch_capabilities(url)
    finally:
        srv.shutdown()


def test_fetch_capabilities_rejects_5xx():
    srv, url = _make_server(b'{"error":"boom"}', status=500)
    try:
        with pytest.raises(ParamantError):
            capabilities.fetch_capabilities(url)
    finally:
        srv.shutdown()


def test_negotiate_does_both_steps():
    body = json.dumps({
        "wire_version": 1,
        "kem": [{"id": 2, "name": "ML-KEM-768", "loaded": True}],
        "sig": [{"id": 2, "name": "ML-DSA-65", "loaded": True}],
    }).encode()
    srv, url = _make_server(body)
    try:
        caps = capabilities.negotiate(url, kem_id=0x0002, sig_id=0x0002)
        assert caps.wire_version == 1
    finally:
        srv.shutdown()


def test_negotiate_rejects_unsupported_combination():
    body = json.dumps({
        "wire_version": 1,
        "kem": [{"id": 2, "name": "ML-KEM-768", "loaded": True}],
        "sig": [{"id": 0, "name": "none", "loaded": True}],
    }).encode()
    srv, url = _make_server(body)
    try:
        with pytest.raises(CapabilityMismatch):
            capabilities.negotiate(url, kem_id=0x0002, sig_id=0x0002)
    finally:
        srv.shutdown()
