const {
  InvalidMagic,
  InvalidVersion,
  MalformedBlob,
  InvalidFlags,
  UnsupportedAlgorithm
} = require("./errors");
const { hasKEM, hasSig } = require("./registry");

const MAGIC = Buffer.from("PQHB", "ascii");
const VERSION_V1 = 0x01;
const SUPPORTED_VERSIONS = [VERSION_V1];
const HEADER_FIXED_SIZE = 10;
const NONCE_SIZE = 12;

function encode({ kemId, sigId, flags = 0x00, ctKem, senderPub, signature, nonce, ciphertext }) {
  if (!Number.isInteger(kemId) || kemId < 0 || kemId > 0xFFFF) throw new Error("kemId must be uint16");
  if (!Number.isInteger(sigId) || sigId < 0 || sigId > 0xFFFF) throw new Error("sigId must be uint16");
  if (flags !== 0x00) throw new InvalidFlags(flags);
  if (!Buffer.isBuffer(ctKem)) throw new Error("ctKem must be Buffer");
  if (!Buffer.isBuffer(senderPub)) throw new Error("senderPub must be Buffer");
  if (!Buffer.isBuffer(nonce) || nonce.length !== NONCE_SIZE) throw new Error(`nonce must be ${NONCE_SIZE} bytes`);
  if (!Buffer.isBuffer(ciphertext)) throw new Error("ciphertext must be Buffer");

  const hasSignature = sigId !== 0x0000;
  if (hasSignature && !Buffer.isBuffer(signature)) throw new Error("signature required when sigId != 0x0000");
  if (!hasSignature && signature) throw new Error("signature must be absent when sigId = 0x0000");

  const header = Buffer.alloc(HEADER_FIXED_SIZE);
  MAGIC.copy(header, 0);
  header.writeUInt8(VERSION_V1, 4);
  header.writeUInt16BE(kemId, 5);
  header.writeUInt16BE(sigId, 7);
  header.writeUInt8(flags, 9);

  const parts = [header];

  const ctKemLen = Buffer.alloc(4);
  ctKemLen.writeUInt32BE(ctKem.length, 0);
  parts.push(ctKemLen, ctKem);

  const senderPubLen = Buffer.alloc(4);
  senderPubLen.writeUInt32BE(senderPub.length, 0);
  parts.push(senderPubLen, senderPub);

  if (hasSignature) {
    const sigLen = Buffer.alloc(4);
    sigLen.writeUInt32BE(signature.length, 0);
    parts.push(sigLen, signature);
  }

  parts.push(nonce);

  const ctLen = Buffer.alloc(4);
  ctLen.writeUInt32BE(ciphertext.length, 0);
  parts.push(ctLen, ciphertext);

  return Buffer.concat(parts);
}

function decode(blob) {
  if (!Buffer.isBuffer(blob)) throw new MalformedBlob("input must be Buffer");
  if (blob.length < HEADER_FIXED_SIZE) throw new MalformedBlob("too short for header");

  if (blob.compare(MAGIC, 0, 4, 0, 4) !== 0) {
    throw new InvalidMagic(blob.subarray(0, 4).toString("hex"));
  }

  const version = blob.readUInt8(4);
  if (!SUPPORTED_VERSIONS.includes(version)) {
    throw new InvalidVersion(version, SUPPORTED_VERSIONS);
  }

  const kemId = blob.readUInt16BE(5);
  const sigId = blob.readUInt16BE(7);
  const flags = blob.readUInt8(9);

  if (flags !== 0x00) throw new InvalidFlags(flags);
  if (!hasKEM(kemId)) throw new UnsupportedAlgorithm("KEM", kemId);
  if (!hasSig(sigId)) throw new UnsupportedAlgorithm("SIG", sigId);

  let offset = HEADER_FIXED_SIZE;

  if (blob.length < offset + 4) throw new MalformedBlob("truncated at ctKem length");
  const ctKemLen = blob.readUInt32BE(offset);
  offset += 4;
  if (blob.length < offset + ctKemLen) throw new MalformedBlob("truncated at ctKem body");
  const ctKem = blob.subarray(offset, offset + ctKemLen);
  offset += ctKemLen;

  if (blob.length < offset + 4) throw new MalformedBlob("truncated at senderPub length");
  const senderPubLen = blob.readUInt32BE(offset);
  offset += 4;
  if (blob.length < offset + senderPubLen) throw new MalformedBlob("truncated at senderPub body");
  const senderPub = blob.subarray(offset, offset + senderPubLen);
  offset += senderPubLen;

  let signature = null;
  if (sigId !== 0x0000) {
    if (blob.length < offset + 4) throw new MalformedBlob("truncated at sig length");
    const sigLen = blob.readUInt32BE(offset);
    offset += 4;
    if (blob.length < offset + sigLen) throw new MalformedBlob("truncated at sig body");
    signature = blob.subarray(offset, offset + sigLen);
    offset += sigLen;
  }

  if (blob.length < offset + NONCE_SIZE) throw new MalformedBlob("truncated at nonce");
  const nonce = blob.subarray(offset, offset + NONCE_SIZE);
  offset += NONCE_SIZE;

  if (blob.length < offset + 4) throw new MalformedBlob("truncated at ciphertext length");
  const ctLen = blob.readUInt32BE(offset);
  offset += 4;
  if (blob.length < offset + ctLen) throw new MalformedBlob("truncated at ciphertext body");
  const ciphertext = blob.subarray(offset, offset + ctLen);
  offset += ctLen;

  const aad = blob.subarray(0, HEADER_FIXED_SIZE);

  return {
    version,
    kemId,
    sigId,
    flags,
    ctKem: Buffer.from(ctKem),
    senderPub: Buffer.from(senderPub),
    signature: signature ? Buffer.from(signature) : null,
    nonce: Buffer.from(nonce),
    ciphertext: Buffer.from(ciphertext),
    aad: Buffer.from(aad),
    consumedBytes: offset
  };
}

function buildAAD({ kemId, sigId, flags = 0x00, chunkIndex = 0 }) {
  const buf = Buffer.alloc(HEADER_FIXED_SIZE + 4);
  MAGIC.copy(buf, 0);
  buf.writeUInt8(VERSION_V1, 4);
  buf.writeUInt16BE(kemId, 5);
  buf.writeUInt16BE(sigId, 7);
  buf.writeUInt8(flags, 9);
  buf.writeUInt32BE(chunkIndex, HEADER_FIXED_SIZE);
  return buf;
}

function isV1(blob) {
  return Buffer.isBuffer(blob)
    && blob.length >= 4
    && blob.compare(MAGIC, 0, 4, 0, 4) === 0;
}

module.exports = {
  encode,
  decode,
  buildAAD,
  isV1,
  MAGIC,
  VERSION_V1,
  SUPPORTED_VERSIONS,
  HEADER_FIXED_SIZE,
  NONCE_SIZE
};
