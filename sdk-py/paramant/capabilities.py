"""
/v2/capabilities client — negotiate wire version and algorithm set with the relay
before sending. No silent fallback: if the relay cannot handle what the SDK is
about to produce, the call raises CapabilityMismatch.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

from .errors import CapabilityMismatch, ParamantError

SUPPORTED_WIRE_VERSION = 1


@dataclass(frozen=True)
class AlgorithmEntry:
    id: int
    name: str
    loaded: bool


@dataclass(frozen=True)
class RelayCapabilities:
    wire_version: int
    kem: List[AlgorithmEntry] = field(default_factory=list)
    sig: List[AlgorithmEntry] = field(default_factory=list)
    raw: dict = field(default_factory=dict)

    def supports_kem(self, kem_id: int) -> bool:
        return any(e.id == kem_id and e.loaded for e in self.kem)

    def supports_sig(self, sig_id: int) -> bool:
        return any(e.id == sig_id and e.loaded for e in self.sig)

    def kem_names(self) -> List[str]:
        return [e.name for e in self.kem if e.loaded]

    def sig_names(self) -> List[str]:
        return [e.name for e in self.sig if e.loaded]


def _parse_entries(raw: Iterable) -> List[AlgorithmEntry]:
    out: List[AlgorithmEntry] = []
    for item in raw or ():
        try:
            out.append(AlgorithmEntry(
                id=int(item.get("id")),
                name=str(item.get("name") or ""),
                loaded=bool(item.get("loaded", True)),
            ))
        except (TypeError, ValueError):
            continue
    return out


def fetch_capabilities(
    relay_url: str,
    timeout: float = 10.0,
    user_agent: str = "paramant-sdk/3.0.0",
) -> RelayCapabilities:
    """GET {relay_url}/v2/capabilities and parse the response."""
    if not relay_url:
        raise ParamantError("relay_url is required")
    url = relay_url.rstrip("/") + "/v2/capabilities"
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read()
    except urllib.error.HTTPError as e:
        raise ParamantError(f"/v2/capabilities returned HTTP {e.code}") from e
    except urllib.error.URLError as e:
        raise ParamantError(f"could not reach {url}: {e.reason}") from e

    try:
        data = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        raise ParamantError(f"/v2/capabilities returned non-JSON: {e}") from e

    wire_version = int(data.get("wire_version", 0) or 0)
    return RelayCapabilities(
        wire_version=wire_version,
        kem=_parse_entries(data.get("kem")),
        sig=_parse_entries(data.get("sig")),
        raw=data,
    )


def validate(
    caps: RelayCapabilities,
    kem_id: int,
    sig_id: int,
    wire_version: int = SUPPORTED_WIRE_VERSION,
) -> None:
    """Raise CapabilityMismatch if caps cannot handle this combination."""
    if caps.wire_version != wire_version:
        raise CapabilityMismatch(
            f"relay advertises wire_version={caps.wire_version}, "
            f"this SDK produces wire_version={wire_version}"
        )
    if not caps.supports_kem(kem_id):
        raise CapabilityMismatch(
            f"relay does not support KEM id 0x{kem_id:04x}; loaded: {caps.kem_names()}"
        )
    if not caps.supports_sig(sig_id):
        raise CapabilityMismatch(
            f"relay does not support SIG id 0x{sig_id:04x}; loaded: {caps.sig_names()}"
        )


def negotiate(
    relay_url: str,
    kem_id: int,
    sig_id: int,
    timeout: float = 10.0,
) -> RelayCapabilities:
    """Convenience: fetch + validate in one call."""
    caps = fetch_capabilities(relay_url, timeout=timeout)
    validate(caps, kem_id=kem_id, sig_id=sig_id)
    return caps


__all__ = [
    "SUPPORTED_WIRE_VERSION",
    "AlgorithmEntry",
    "RelayCapabilities",
    "fetch_capabilities",
    "validate",
    "negotiate",
]
