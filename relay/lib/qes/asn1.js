'use strict';
// Minimal DER encoder/decoder, just enough for CMS SignedData and RFC 3161.
//
// Deliberately dependency-free: the relay already ships without an ASN.1
// library and a QES prototype is not a good reason to add one. Everything here
// is definite-length DER, which is all that CMS and PKIX allow anyway.

// ── encoding ────────────────────────────────────────────────────────────────

function encodeLength(n) {
  if (n < 0x80) return Buffer.from([n]);
  const bytes = [];
  let v = n;
  while (v > 0) { bytes.unshift(v & 0xff); v >>>= 8; }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

// One tag-length-value. `tag` is the full identifier octet.
function tlv(tag, content) {
  const body = Buffer.isBuffer(content) ? content : Buffer.concat(content);
  return Buffer.concat([Buffer.from([tag]), encodeLength(body.length), body]);
}

const seq = (...parts) => tlv(0x30, parts.flat());
const set = (...parts) => tlv(0x31, parts.flat());
const octetString = (buf) => tlv(0x04, buf);
const bitString = (buf, unused = 0) => tlv(0x03, Buffer.concat([Buffer.from([unused]), buf]));
const nullValue = () => Buffer.from([0x05, 0x00]);
// Context-specific constructed [n].
const explicit = (n, ...parts) => tlv(0xa0 | n, parts.flat());
// Context-specific constructed [n] IMPLICIT over a SET/SEQUENCE body.
const implicitSet = (n, ...parts) => tlv(0xa0 | n, parts.flat());

function integer(value) {
  let buf;
  if (Buffer.isBuffer(value)) {
    buf = value;
  } else {
    const n = BigInt(value);
    if (n === 0n) buf = Buffer.from([0]);
    else {
      let hex = n.toString(16);
      if (hex.length % 2) hex = '0' + hex;
      buf = Buffer.from(hex, 'hex');
    }
  }
  // Strip redundant leading zeros, then re-add one if the top bit is set.
  let i = 0;
  while (i + 1 < buf.length && buf[i] === 0 && (buf[i + 1] & 0x80) === 0) i++;
  buf = buf.subarray(i);
  if (buf.length && (buf[0] & 0x80)) buf = Buffer.concat([Buffer.from([0]), buf]);
  if (!buf.length) buf = Buffer.from([0]);
  return tlv(0x02, buf);
}

function oid(dotted) {
  const parts = String(dotted).split('.').map((p) => parseInt(p, 10));
  if (parts.length < 2 || parts.some((p) => !Number.isInteger(p) || p < 0)) {
    throw new Error('invalid OID: ' + dotted);
  }
  const out = [40 * parts[0] + parts[1]];
  for (const part of parts.slice(2)) {
    const chunk = [];
    let v = part;
    do { chunk.unshift(v & 0x7f); v = Math.floor(v / 128); } while (v > 0);
    for (let i = 0; i < chunk.length - 1; i++) chunk[i] |= 0x80;
    out.push(...chunk);
  }
  return tlv(0x06, Buffer.from(out));
}

// UTCTime, the CMS default for dates before 2050.
function utcTime(date) {
  const d = new Date(date);
  const p = (n, w = 2) => String(n).padStart(w, '0');
  const s = p(d.getUTCFullYear() % 100) + p(d.getUTCMonth() + 1) + p(d.getUTCDate()) +
    p(d.getUTCHours()) + p(d.getUTCMinutes()) + p(d.getUTCSeconds()) + 'Z';
  return tlv(0x17, Buffer.from(s, 'ascii'));
}

// AlgorithmIdentifier with an absent-or-NULL parameter, the only two shapes we emit.
function algorithmIdentifier(algOid, { withNull = true } = {}) {
  return withNull ? seq(oid(algOid), nullValue()) : seq(oid(algOid));
}

// ── decoding ────────────────────────────────────────────────────────────────

// Read one TLV at `offset`. Returns { tag, headerLength, length, content, end }
// where `content` is a view into `buf` (no copy).
function readTlv(buf, offset = 0) {
  if (offset >= buf.length) throw new Error('DER: read past end');
  const tag = buf[offset];
  if ((tag & 0x1f) === 0x1f) throw new Error('DER: multi-byte tags unsupported');
  let pos = offset + 1;
  if (pos >= buf.length) throw new Error('DER: truncated length');
  let length = buf[pos++];
  if (length === 0x80) throw new Error('DER: indefinite length is not DER');
  if (length & 0x80) {
    const count = length & 0x7f;
    if (count > 4) throw new Error('DER: length too large');
    length = 0;
    for (let i = 0; i < count; i++) {
      if (pos >= buf.length) throw new Error('DER: truncated length');
      length = (length << 8) | buf[pos++];
    }
  }
  const end = pos + length;
  if (end > buf.length) throw new Error('DER: content past end');
  return { tag, headerLength: pos - offset, length, content: buf.subarray(pos, end), start: offset, end };
}

// Every direct child of a constructed TLV's content.
function readChildren(content) {
  const out = [];
  let pos = 0;
  while (pos < content.length) {
    const node = readTlv(content, pos);
    out.push(node);
    pos = node.end;
  }
  return out;
}

function decodeOid(content) {
  if (!content.length) throw new Error('DER: empty OID');
  const first = content[0];
  const parts = [Math.floor(first / 40), first % 40];
  let value = 0;
  for (let i = 1; i < content.length; i++) {
    value = value * 128 + (content[i] & 0x7f);
    if (!(content[i] & 0x80)) { parts.push(value); value = 0; }
  }
  return parts.join('.');
}

// The full encoding of a node, header included. Used where a signature covers
// the bytes as they appear on the wire.
function rawOf(buf, node) {
  return buf.subarray(node.start, node.end);
}

module.exports = {
  encodeLength, tlv, seq, set, octetString, bitString, nullValue,
  explicit, implicitSet, integer, oid, utcTime, algorithmIdentifier,
  readTlv, readChildren, decodeOid, rawOf,
};
