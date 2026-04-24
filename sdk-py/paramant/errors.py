"""Error hierarchy for paramant v3+."""


class ParamantError(Exception):
    """Base class for all SDK-raised errors."""


class UnsupportedAlgorithm(ParamantError):
    def __init__(self, family: str, alg_id: int):
        self.family = family
        self.alg_id = alg_id
        super().__init__(f"unsupported {family} algorithm id 0x{alg_id:04x}")


class InvalidMagic(ParamantError):
    def __init__(self, got: bytes):
        self.got = got
        super().__init__(f"invalid magic bytes: expected PQHB, got {got.hex()}")


class InvalidVersion(ParamantError):
    def __init__(self, got: int, supported):
        self.got = got
        self.supported = supported
        super().__init__(
            f"invalid wire version 0x{got:02x}, supported={[f'0x{v:02x}' for v in supported]}"
        )


class InvalidFlags(ParamantError):
    def __init__(self, flags: int):
        self.flags = flags
        super().__init__(f"invalid flags 0x{flags:02x}, expected 0x00 in v1")


class MalformedBlob(ParamantError):
    """Raised when a v1 blob cannot be parsed (truncated, length mismatch, etc.)."""


class CapabilityMismatch(ParamantError):
    """Raised when the relay cannot handle the requested wire version or algorithm pair."""
