// The visible handwriting of a co-signature, encrypted for the other parties.
//
// A signer draws their signature or types their name. The PDF that every party
// downloads at the end has to show it, and the PDF is built in each party's own
// browser, so the handwriting has to travel. It travels encrypted: the key is
// derived from the document key, which only the parties hold (it never reaches
// the relay, see js/parasign-document-capsule.js). The relay stores ciphertext
// it cannot read.
//
// It is presentation, not evidence. The signed manifest says where a mark sits
// (relay/envelope.js normaliseAppearance) and that is all a signature binds; a
// lost or unreadable ink costs the look of the PDF, never what was signed.
//
// Also the key-share arithmetic for the invitation link: A xor B = K.

import { cleanInk } from './cosign-layout.js?v=1';

const DOMAIN = 'paramant/parasign/ink/v1';
const enc = new TextEncoder();

function b64url(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function fromB64url(value) {
  const s = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
export { b64url };

function aad(envelopeId, partyIndex) {
  return enc.encode(DOMAIN + '\x00' + String(envelopeId) + '\x00' + String(partyIndex));
}

async function inkKey(documentKey, usage) {
  if (!(documentKey instanceof Uint8Array) || documentKey.length !== 32) throw new Error('document key required');
  const material = new Uint8Array(enc.encode(DOMAIN + '\x00').length + 32);
  material.set(enc.encode(DOMAIN + '\x00'), 0);
  material.set(documentKey, material.length - 32);
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', material));
  material.fill(0);
  try {
    return await crypto.subtle.importKey('raw', digest, { name: 'AES-GCM' }, false, [usage]);
  } finally {
    digest.fill(0);
  }
}

// ink: { kind:'type', text } | { kind:'draw', path, w, h }. Returns base64url
// of iv || ciphertext, or '' when there is nothing to send.
export async function sealInk({ ink, documentKey, envelopeId, partyIndex }) {
  const clean = cleanInk(ink);
  if (!clean || !documentKey) return '';
  const key = await inkKey(documentKey, 'encrypt');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad(envelopeId, partyIndex) }, key, enc.encode(JSON.stringify(clean))));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0); out.set(ct, iv.length);
  return b64url(out);
}

// The other way round. Any failure (wrong key, tampered bytes, junk) is null:
// the caller then draws the party's name instead.
export async function openInk({ sealed, documentKey, envelopeId, partyIndex }) {
  try {
    if (!sealed || !documentKey) return null;
    const raw = fromB64url(sealed);
    if (raw.length < 12 + 16) return null;
    const key = await inkKey(documentKey, 'decrypt');
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12), additionalData: aad(envelopeId, partyIndex) }, key, raw.slice(12));
    return cleanInk(JSON.parse(new TextDecoder().decode(plain)));
  } catch {
    return null;
  }
}

// ── Split document key ───────────────────────────────────────────────────────
// The invitation mail carries share A, the relay keeps share B, and only the
// signed-in invitee gets both. Either share alone is 32 uniformly random bytes.
export function splitKey(key) {
  if (!(key instanceof Uint8Array) || key.length !== 32) throw new Error('document key must be 32 bytes');
  const a = crypto.getRandomValues(new Uint8Array(32));
  const b = new Uint8Array(32);
  for (let i = 0; i < 32; i++) b[i] = key[i] ^ a[i];
  return { a, b };
}

export function joinKey(a, b) {
  if (!(a instanceof Uint8Array) || !(b instanceof Uint8Array) || a.length !== 32 || b.length !== 32) throw new Error('key shares must be 32 bytes');
  const k = new Uint8Array(32);
  for (let i = 0; i < 32; i++) k[i] = a[i] ^ b[i];
  return k;
}

// '#ks=v1.<43>' -> the 32-byte share, or null when the fragment carries none.
export function parseKeyShareFragment(fragment) {
  const raw = String(fragment || '').replace(/^#/, '');
  const value = new URLSearchParams(raw).get('ks') || '';
  if (!/^v1\.[A-Za-z0-9_-]{43}$/.test(value)) return null;
  const share = fromB64url(value.slice(3));
  return share.length === 32 ? share : null;
}

export function keyShareFragment(share) {
  return '#ks=v1.' + b64url(share);
}
