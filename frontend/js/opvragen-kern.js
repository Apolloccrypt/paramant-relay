// Stukken opvragen: what the client's phone and the office's browser must agree
// on, in one file so the two cannot drift.
//
//   pinOf          the hash in the link's #fragment. It covers the request as
//                  the client sees it, both public keys included, so the relay
//                  cannot hand the phone a key of its own without the phone
//                  noticing (relay/lib/opvraag.js explains the rest).
//   packFile       one file plus its name, type and document, as the plaintext
//                  that encrypt_blob locks to the office's key. The name lives
//                  inside the ciphertext, never beside it.
//   trimPacket     encrypt_blob pads every packet to 5 MiB with random bytes.
//                  We keep the packet and cut the padding back to the next
//                  64 KiB: a 1 MB photo costs the client 1 MB of data, and the
//                  relay still learns its size only roughly.
//   zipStore       a plain zip (no compression) for "Downloaden", built in the
//                  office's browser from files it has just decrypted.

export const PIN_LABEL = 'paramant/opvraag/v1\u0000';
export const SK_LABEL = 'paramant/opvraag/sk/v1\u0000';
export const BUCKET = 65536;

const te = new TextEncoder();
const td = new TextDecoder();

export function b64u(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
export function fromB64u(s) {
  let b = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
  while (b.length % 4) b += '=';
  const raw = atob(b);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}
export function rand(n) { return crypto.getRandomValues(new Uint8Array(n)); }

// The fields, in this order, are the contract. JSON.stringify of strings,
// integers and an array of strings is the same in every engine.
export function canonical(d) {
  return JSON.stringify([d.v, d.id, d.office, d.greet, d.items, d.expires_at, d.kem_pub, d.ecdh_pub]);
}
export async function pinOf(d) {
  const label = te.encode(PIN_LABEL);
  const body = te.encode(canonical(d));
  const buf = new Uint8Array(label.length + body.length);
  buf.set(label, 0); buf.set(body, label.length);
  return b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', buf)));
}

// Shape checks the phone makes before it trusts anything: right key sizes,
// the id the link names, and a hash that matches the fragment.
export async function checkDescriptor(d, id, pin) {
  if (!d || d.v !== 1 || d.id !== id) return false;
  if (!Array.isArray(d.items) || !d.items.length || d.items.some((x) => typeof x !== 'string')) return false;
  if (typeof d.office !== 'string' || typeof d.greet !== 'string' || !Number.isSafeInteger(d.expires_at)) return false;
  // The relay refuses these on the way in; a page that shows them refuses too.
  if ([d.office, d.greet, ...d.items].some((x) => new RegExp(INVISIBLE_RE.source).test(x))) return false;
  let kem, ecdh;
  try { kem = fromB64u(d.kem_pub); ecdh = fromB64u(d.ecdh_pub); } catch { return false; }
  if (kem.length !== 1184 || ecdh.length !== 65 || ecdh[0] !== 4) return false;
  if (!/^[A-Za-z0-9_-]{43}$/.test(pin || '')) return false;
  return (await pinOf(d)) === pin;
}

export function packFile(bytes, meta) {
  const m = te.encode(JSON.stringify({ v: 1, item: meta.item, label: meta.label, name: meta.name,
                                       type: meta.type || '', size: bytes.length }));
  const out = new Uint8Array(4 + m.length + bytes.length);
  new DataView(out.buffer).setUint32(0, m.length, true);
  out.set(m, 4); out.set(bytes, 4 + m.length);
  return out;
}
export function unpackFile(plain) {
  const n = new DataView(plain.buffer, plain.byteOffset, plain.byteLength).getUint32(0, true);
  if (n > 4096 || 4 + n > plain.length) throw new Error('bad file header');
  const meta = JSON.parse(td.decode(plain.subarray(4, 4 + n)));
  const bytes = plain.subarray(4 + n, 4 + n + Number(meta.size));
  if (bytes.length !== Number(meta.size)) throw new Error('file shorter than its header says');
  return { meta, bytes };
}
// What a file of this size costs inside the packet: header, meta, tag.
export const PACKET_OVERHEAD = 1 + 4 + 1088 + 4 + 65 + 12 + 4 + 16 + 4 + 1024;

// The wire packet of encrypt_blob:
//   0x03 | u32be ctKemLen | ctKem | u32be senderLen | sender | nonce(12) | u32be ctLen | ct
export function packetLength(blob) {
  const dv = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  let off = 1;
  off += 4 + dv.getUint32(off);
  off += 4 + dv.getUint32(off);
  off += 12;
  return off + 4 + dv.getUint32(off);
}
export function trimPacket(blob) {
  const len = packetLength(blob);
  return blob.slice(0, Math.min(blob.length, Math.ceil(len / BUCKET) * BUCKET));
}

// The office's private keys for one request, locked under its vault key. The
// request id is the associated data, so a box cannot be moved to another request.
export async function sealSk(vaultKey, id, obj) {
  const iv = rand(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode(SK_LABEL + id) },
    vaultKey, te.encode(JSON.stringify(obj))));
  const out = new Uint8Array(12 + ct.length); out.set(iv, 0); out.set(ct, 12);
  return b64u(out);
}
export async function openSk(vaultKey, id, wrapped) {
  const raw = fromB64u(wrapped);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.subarray(0, 12), additionalData: te.encode(SK_LABEL + id) },
    vaultKey, raw.subarray(12));
  return JSON.parse(td.decode(new Uint8Array(plain)));
}

// ── a zip without compression ────────────────────────────────────────────────
let _crcTable = null;
function crc32(u8) {
  if (!_crcTable) {
    _crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1; _crcTable[n] = c >>> 0; }
  }
  let c = 0xFFFFFFFF;
  for (let i = 0; i < u8.length; i++) c = _crcTable[(c ^ u8[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}
export function zipStore(files) {
  const parts = []; const central = []; let offset = 0;
  const d = new Date();
  const dosTime = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
  const dosDate = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  for (const f of files) {
    const name = te.encode(f.name);
    const crc = crc32(f.bytes);
    const lh = new DataView(new ArrayBuffer(30));
    lh.setUint32(0, 0x04034b50, true); lh.setUint16(4, 20, true); lh.setUint16(6, 0x0800, true);
    lh.setUint16(8, 0, true); lh.setUint16(10, dosTime, true); lh.setUint16(12, dosDate, true);
    lh.setUint32(14, crc, true); lh.setUint32(18, f.bytes.length, true); lh.setUint32(22, f.bytes.length, true);
    lh.setUint16(26, name.length, true); lh.setUint16(28, 0, true);
    parts.push(new Uint8Array(lh.buffer), name, f.bytes);
    const ch = new DataView(new ArrayBuffer(46));
    ch.setUint32(0, 0x02014b50, true); ch.setUint16(4, 20, true); ch.setUint16(6, 20, true); ch.setUint16(8, 0x0800, true);
    ch.setUint16(10, 0, true); ch.setUint16(12, dosTime, true); ch.setUint16(14, dosDate, true);
    ch.setUint32(16, crc, true); ch.setUint32(20, f.bytes.length, true); ch.setUint32(24, f.bytes.length, true);
    ch.setUint16(28, name.length, true); ch.setUint32(42, offset, true);
    central.push(new Uint8Array(ch.buffer), name);
    offset += 30 + name.length + f.bytes.length;
  }
  const cdSize = central.reduce((s, p) => s + p.length, 0);
  const end = new DataView(new ArrayBuffer(22));
  end.setUint32(0, 0x06054b50, true); end.setUint16(8, files.length, true); end.setUint16(10, files.length, true);
  end.setUint32(12, cdSize, true); end.setUint32(16, offset, true);
  return new Blob([...parts, ...central, new Uint8Array(end.buffer)], { type: 'application/zip' });
}

// A file name that is safe in a zip and on every disk.
export const INVISIBLE_RE = /[\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g;
export function safeName(s) {
  return String(s || '').normalize('NFC').replace(INVISIBLE_RE, '').replace(/[\\/:*?"<>|\u0000-\u001f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 120) || 'bestand';
}

export function formatSize(n, lang) {
  const nf = (v, d) => v.toLocaleString(lang === 'en' ? 'en-GB' : 'nl-NL', { maximumFractionDigits: d });
  if (n >= 1048576) return nf(n / 1048576, 1) + ' MB';
  return nf(Math.max(1, Math.round(n / 1024)), 0) + ' kB';
}

export function initials(name) {
  const w = String(name || '').trim().split(/\s+/).filter(Boolean);
  if (!w.length) return '?';
  const pick = w.length === 1 ? w[0].slice(0, 2) : w[0][0] + w[w.length - 1][0];
  return pick.toUpperCase();
}
