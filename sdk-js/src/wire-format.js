// Paramant wire-format v1 encoder / decoder.
// Bit-exact against docs/wire-format-v1.md.

export const MAGIC = new Uint8Array([0x50, 0x51, 0x48, 0x42]); // 'PQHB'
export const VERSION_V1 = 0x01;
export const SUPPORTED_VERSIONS = [VERSION_V1];
export const HEADER_FIXED_SIZE = 10;
export const NONCE_SIZE = 12;

export class InvalidMagicError extends Error {
  constructor(got) { super(`invalid magic: ${got}`); this.name = 'InvalidMagicError'; }
}
export class InvalidVersionError extends Error {
  constructor(got) { super(`invalid version: ${got}`); this.name = 'InvalidVersionError'; }
}
export class MalformedBlobError extends Error {
  constructor(msg) { super(`malformed blob: ${msg}`); this.name = 'MalformedBlobError'; }
}
export class InvalidFlagsError extends Error {
  constructor(got) { super(`invalid flags: ${got}`); this.name = 'InvalidFlagsError'; }
}

function asU8(x, name) {
  if (x instanceof Uint8Array) return x;
  if (x && x.buffer instanceof ArrayBuffer) return new Uint8Array(x.buffer, x.byteOffset, x.byteLength);
  throw new TypeError(`${name} must be a Uint8Array`);
}

export function encode({ kemId, sigId, flags = 0x00, ctKem, senderPub, signature, nonce, ciphertext }) {
  if (!Number.isInteger(kemId) || kemId < 0 || kemId > 0xFFFF) throw new Error('kemId must be uint16');
  if (!Number.isInteger(sigId) || sigId < 0 || sigId > 0xFFFF) throw new Error('sigId must be uint16');
  if (flags !== 0x00) throw new InvalidFlagsError(flags);

  const ctKemU8 = asU8(ctKem, 'ctKem');
  const senderPubU8 = asU8(senderPub, 'senderPub');
  const nonceU8 = asU8(nonce, 'nonce');
  const ciphertextU8 = asU8(ciphertext, 'ciphertext');

  if (nonceU8.length !== NONCE_SIZE) throw new Error(`nonce must be ${NONCE_SIZE} bytes`);

  const hasSignature = sigId !== 0x0000;
  let signatureU8 = null;
  if (hasSignature) {
    if (!signature) throw new Error('signature required when sigId != 0x0000');
    signatureU8 = asU8(signature, 'signature');
  } else if (signature) {
    throw new Error('signature must be absent when sigId = 0x0000');
  }

  const total =
    HEADER_FIXED_SIZE +
    4 + ctKemU8.length +
    4 + senderPubU8.length +
    (hasSignature ? 4 + signatureU8.length : 0) +
    NONCE_SIZE +
    4 + ciphertextU8.length;

  const out = new Uint8Array(total);
  const dv = new DataView(out.buffer, out.byteOffset, out.byteLength);
  let o = 0;

  // Header
  out.set(MAGIC, o); o += 4;
  dv.setUint8(o, VERSION_V1); o += 1;
  dv.setUint16(o, kemId, false); o += 2;
  dv.setUint16(o, sigId, false); o += 2;
  dv.setUint8(o, flags); o += 1;

  // Key encapsulation
  dv.setUint32(o, ctKemU8.length, false); o += 4;
  out.set(ctKemU8, o); o += ctKemU8.length;
  dv.setUint32(o, senderPubU8.length, false); o += 4;
  out.set(senderPubU8, o); o += senderPubU8.length;

  // Signature (if signed)
  if (hasSignature) {
    dv.setUint32(o, signatureU8.length, false); o += 4;
    out.set(signatureU8, o); o += signatureU8.length;
  }

  // Payload
  out.set(nonceU8, o); o += NONCE_SIZE;
  dv.setUint32(o, ciphertextU8.length, false); o += 4;
  out.set(ciphertextU8, o); o += ciphertextU8.length;

  return out;
}

export function decode(blob) {
  const b = asU8(blob, 'blob');
  if (b.length < HEADER_FIXED_SIZE) throw new MalformedBlobError('too short for header');

  for (let i = 0; i < 4; i++) {
    if (b[i] !== MAGIC[i]) {
      const hex = [...b.slice(0, 4)].map(x => x.toString(16).padStart(2, '0')).join('');
      throw new InvalidMagicError(hex);
    }
  }

  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const version = b[4];
  if (!SUPPORTED_VERSIONS.includes(version)) throw new InvalidVersionError(version);

  const kemId = dv.getUint16(5, false);
  const sigId = dv.getUint16(7, false);
  const flags = b[9];
  if (flags !== 0x00) throw new InvalidFlagsError(flags);

  let o = HEADER_FIXED_SIZE;

  if (b.length < o + 4) throw new MalformedBlobError('truncated at ctKem length');
  const ctKemLen = dv.getUint32(o, false); o += 4;
  if (b.length < o + ctKemLen) throw new MalformedBlobError('truncated at ctKem body');
  const ctKem = b.slice(o, o + ctKemLen); o += ctKemLen;

  if (b.length < o + 4) throw new MalformedBlobError('truncated at senderPub length');
  const senderPubLen = dv.getUint32(o, false); o += 4;
  if (b.length < o + senderPubLen) throw new MalformedBlobError('truncated at senderPub body');
  const senderPub = b.slice(o, o + senderPubLen); o += senderPubLen;

  let signature = null;
  if (sigId !== 0x0000) {
    if (b.length < o + 4) throw new MalformedBlobError('truncated at sig length');
    const sigLen = dv.getUint32(o, false); o += 4;
    if (b.length < o + sigLen) throw new MalformedBlobError('truncated at sig body');
    signature = b.slice(o, o + sigLen); o += sigLen;
  }

  if (b.length < o + NONCE_SIZE) throw new MalformedBlobError('truncated at nonce');
  const nonce = b.slice(o, o + NONCE_SIZE); o += NONCE_SIZE;

  if (b.length < o + 4) throw new MalformedBlobError('truncated at ciphertext length');
  const ctLen = dv.getUint32(o, false); o += 4;
  if (b.length < o + ctLen) throw new MalformedBlobError('truncated at ciphertext body');
  const ciphertext = b.slice(o, o + ctLen); o += ctLen;

  return {
    version, kemId, sigId, flags,
    ctKem, senderPub, signature, nonce, ciphertext,
    aad: b.slice(0, HEADER_FIXED_SIZE),
    consumedBytes: o,
  };
}

export function buildAAD({ kemId, sigId, flags = 0x00, chunkIndex = 0 }) {
  const buf = new Uint8Array(HEADER_FIXED_SIZE + 4);
  const dv = new DataView(buf.buffer);
  buf.set(MAGIC, 0);
  dv.setUint8(4, VERSION_V1);
  dv.setUint16(5, kemId, false);
  dv.setUint16(7, sigId, false);
  dv.setUint8(9, flags);
  dv.setUint32(HEADER_FIXED_SIZE, chunkIndex, false);
  return buf;
}

export function isV1(blob) {
  if (!(blob instanceof Uint8Array)) return false;
  if (blob.length < 4) return false;
  for (let i = 0; i < 4; i++) if (blob[i] !== MAGIC[i]) return false;
  return true;
}
