"""
paramant — Python SDK for the PARAMANT post-quantum relay.

v3.0.0 replaces kyber-py (author-declared not-production-safe) and the
silent ECDH fallback with pqcrypto (backbone-hq, Apache-2.0, thin CFFI
over audited PQClean C code). Default algorithms are ML-KEM-768 (FIPS 203)
and ML-DSA-65 (FIPS 204). Blobs follow wire format v1 (PQHB magic).
"""
from .errors import (
    ParamantError,
    UnsupportedAlgorithm,
    InvalidMagic,
    InvalidVersion,
    InvalidFlags,
    MalformedBlob,
    CapabilityMismatch,
)
from . import wire_format
from . import crypto
from . import capabilities

__all__ = [
    "ParamantError",
    "UnsupportedAlgorithm",
    "InvalidMagic",
    "InvalidVersion",
    "InvalidFlags",
    "MalformedBlob",
    "CapabilityMismatch",
    "wire_format",
    "crypto",
    "capabilities",
    "__version__",
]

__version__ = "3.0.0"
