// ParaSign document delivery capsule.
//
// The sender encrypts the document in the browser with AES-256-GCM. The relay
// stores only the opaque capsule. The 256-bit key is carried in the URL fragment,
// which browsers do not send in HTTP requests. Envelope id and document hash are
// authenticated as AAD, so a capsule cannot be moved to another signing request.

const MAGIC = new Uint8Array([0x50, 0x53, 0x44, 0x43]); // PSDC
const VERSION = 1;
const KEY_BYTES = 32;
const IV_BYTES = 12;
const MAX_META_BYTES = 4096;
const DOMAIN = 'paramant/parasign/document/v1';

function concat(parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) { out.set(p, off); off += p.length; }
  return out;
}

function b64url(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function fromB64url(value) {
  const s = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  let bin;
  try { bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4)); }
  catch { throw new Error('The document key is malformed.'); }
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function aad(envelopeId, docHash) {
  return new TextEncoder().encode(DOMAIN + '\x00' + String(envelopeId) + '\x00' + String(docHash));
}

function u32be(n) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

function hex(bytes) {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

export function documentKeyFragment(keyBytes) {
  if (!(keyBytes instanceof Uint8Array) || keyBytes.length !== KEY_BYTES) throw new Error('Document key must be 32 bytes.');
  return '#doc=v1.' + b64url(keyBytes);
}

export function parseDocumentKeyFragment(fragment) {
  const raw = String(fragment || '').replace(/^#/, '');
  const params = new URLSearchParams(raw);
  const value = params.get('doc') || '';
  if (!value.startsWith('v1.')) return null;
  const key = fromB64url(value.slice(3));
  if (key.length !== KEY_BYTES) throw new Error('The document key has the wrong length.');
  return key;
}

export async function encryptDocumentCapsule({ bytes, filename, mime, envelopeId, docHash }) {
  if (!(bytes instanceof Uint8Array) || bytes.length === 0) throw new Error('Document bytes are required.');
  if (!/^[0-9a-f]{64}$/.test(String(docHash || ''))) throw new Error('Document hash is invalid.');
  const keyBytes = crypto.getRandomValues(new Uint8Array(KEY_BYTES));
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const metaBytes = new TextEncoder().encode(JSON.stringify({
    version: VERSION,
    filename: String(filename || 'document').slice(0, 200),
    mime: String(mime || 'application/octet-stream').slice(0, 100),
    size: bytes.length,
    doc_hash: docHash,
  }));
  if (metaBytes.length > MAX_META_BYTES) throw new Error('Document metadata is too large.');
  const plain = concat([u32be(metaBytes.length), metaBytes, bytes]);
  let encrypted;
  try {
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt']);
    encrypted = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(envelopeId, docHash) }, key, plain));
  } finally {
    plain.fill(0);
  }
  const capsule = concat([MAGIC, new Uint8Array([VERSION]), iv, encrypted]);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', capsule));
  const fragment = documentKeyFragment(keyBytes);
  keyBytes.fill(0);
  return { capsule, capsuleSha256: hex(digest), fragment };
}

export async function decryptDocumentCapsule({ capsule, fragment, envelopeId, docHash }) {
  if (!(capsule instanceof Uint8Array) || capsule.length < MAGIC.length + 1 + IV_BYTES + 16) throw new Error('The encrypted document capsule is truncated.');
  for (let i = 0; i < MAGIC.length; i++) if (capsule[i] !== MAGIC[i]) throw new Error('The encrypted document capsule has an unknown format.');
  if (capsule[MAGIC.length] !== VERSION) throw new Error('This encrypted document capsule version is not supported.');
  const keyBytes = parseDocumentKeyFragment(fragment);
  if (!keyBytes) throw new Error('This signing link has no document decryption key.');
  const ivOff = MAGIC.length + 1;
  const iv = capsule.slice(ivOff, ivOff + IV_BYTES);
  const ciphertext = capsule.slice(ivOff + IV_BYTES);
  let plain;
  try {
    const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
    plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad(envelopeId, docHash) }, key, ciphertext));
  } catch {
    throw new Error('The encrypted document could not be decrypted. The link may be incomplete or altered.');
  } finally {
    keyBytes.fill(0);
  }
  try {
    if (plain.length < 4) throw new Error('The decrypted document header is truncated.');
    const metaLen = new DataView(plain.buffer, plain.byteOffset, plain.byteLength).getUint32(0, false);
    if (metaLen < 2 || metaLen > MAX_META_BYTES || plain.length < 4 + metaLen) throw new Error('The decrypted document metadata is invalid.');
    let meta;
    try { meta = JSON.parse(new TextDecoder().decode(plain.slice(4, 4 + metaLen))); }
    catch { throw new Error('The decrypted document metadata is invalid.'); }
    const documentBytes = plain.slice(4 + metaLen);
    if (meta.version !== VERSION || meta.doc_hash !== docHash || meta.size !== documentBytes.length) throw new Error('The encrypted document metadata does not match this signing request.');
    return {
      bytes: documentBytes,
      filename: String(meta.filename || 'document').slice(0, 200),
      mime: String(meta.mime || 'application/octet-stream').slice(0, 100),
    };
  } finally {
    plain.fill(0);
  }
}
