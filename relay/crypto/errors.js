class CryptoError extends Error {
  constructor(message, code) {
    super(message);
    this.name = this.constructor.name;
    this.code = code;
  }
}

class InvalidMagic extends CryptoError {
  constructor(got) {
    super(`Invalid magic bytes: expected PQHB, got ${got}`, "INVALID_MAGIC");
  }
}

class InvalidVersion extends CryptoError {
  constructor(version, supported) {
    super(`Unsupported wire format version ${version}, supported: ${supported.join(", ")}`, "INVALID_VERSION");
    this.version = version;
    this.supported = supported;
  }
}

class UnsupportedAlgorithm extends CryptoError {
  constructor(kind, id) {
    super(`Unsupported ${kind} algorithm ID: 0x${id.toString(16).padStart(4, "0")}`, "UNSUPPORTED_ALGORITHM");
    this.kind = kind;
    this.id = id;
  }
}

class MalformedBlob extends CryptoError {
  constructor(reason) {
    super(`Malformed blob: ${reason}`, "MALFORMED_BLOB");
  }
}

class InvalidFlags extends CryptoError {
  constructor(flags) {
    super(`Invalid flags byte: 0x${flags.toString(16).padStart(2, "0")}, must be 0x00 in v1`, "INVALID_FLAGS");
  }
}

module.exports = {
  CryptoError,
  InvalidMagic,
  InvalidVersion,
  UnsupportedAlgorithm,
  MalformedBlob,
  InvalidFlags
};
