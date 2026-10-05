// paramant-core.js — shared encrypt + upload core for the Paramant mail integrations.
//
// One module, two consumers:
//   • Chromium extension service worker (Gmail)  — calls sealAndUploadChunk() per chunk
//   • Outlook Office.js add-in (taskpane)         — calls encryptAndUpload() on the whole file
//
// The output is byte-compatible with the recipient page at paramant.app/get
// (Thunderbird FileLink download mode), so links produced here are decrypted by the
// existing, shipping receiver without any server-side change.
//
// Threat model: the relay stores only opaque, AES-256-GCM ciphertext padded to a fixed
// 5 MB block. The symmetric key never reaches the relay — it travels in the URL fragment
// (#k=), which browsers never send to servers. The relay also never receives the
// plaintext filename (it lives only inside the encrypted blob and in the link the sender
// pastes). Burn-on-read: each blob is single-view and TTL-expired server-side.
//
// No external dependencies — Web Crypto (crypto.subtle), fetch, btoa only. These exist in
// both MV3 service workers and Office.js task panes.

'use strict';

// ── Constants ─────────────────────────────────────────────────────────────────

// Plaintext bytes per chunk. Must be small enough that the encrypted, framed packet
// (PRSH header + AES-GCM tag + meta JSON) still fits inside PADDED_BLOCK. 4.9 MB leaves
// ~100 KB of headroom, matching the Thunderbird FileLink integration.
export const CHUNK_PLAIN  = Math.floor(4.9 * 1024 * 1024); // 5_138_022
// Every upload is padded to exactly this size so blob length leaks nothing (DPI resistance)
// and so the relay's per-blob ceiling is a hard, predictable number.
export const PADDED_BLOCK = 5 * 1024 * 1024;               // 5_242_880

export const PACKET_VERSION = 0x02;
const PRSH_MAGIC = Object.freeze([0x50, 0x52, 0x53, 0x48]); // 'PRSH'

// Where a receiver opens the link. /get is public: the receiver of a mail has
// no Paramant account. This used to be /parashare, which is the sender's page
// and sits behind the login, so a receiver was sent to /auth/login and never
// reached the file. nginx forwards links already sent to /parashare?t= to /get.
export const RECEIVE_BASE = 'https://paramant.app/get';
/** @deprecated the old name; it now points at the public receiving page. */
export const PARASHARE_BASE = RECEIVE_BASE;
export const DEFAULT_RELAY  = 'https://relay.paramant.app';

// Where a user upgrades when a monthly quota is hit. Surfaced verbatim in the
// 402 melding so both the Outlook taskpane and the Gmail/Outlook content-script
// banner can link the same place the webapp does.
export const UPGRADE_URL = 'https://paramant.app/pricing';

// Sectored relays. An API key is valid on exactly one of these; discoverRelay() finds it.
export const SECTOR_RELAYS = Object.freeze([
  'https://relay.paramant.app',
  'https://health.paramant.app',
  'https://legal.paramant.app',
  'https://finance.paramant.app',
  'https://iot.paramant.app',
]);

// The receiver opens every link on paramant.app/get, and that page fetches only
// from the relays above. A link to any other relay cannot be opened there
// (fase 1, EXT-09-A), so the integrations upload to these relays only.
export function isReceivableRelay(url) {
  return SECTOR_RELAYS.includes(String(url || '').replace(/\/+$/, ''));
}
export const SELF_HOST_UNSUPPORTED = 'A self-hosted relay is not supported here yet: the receiver opens the link on paramant.app, which only fetches from Paramant relays. Clear the relay setting in the options.';

const UPLOAD_TIMEOUT_MS = 120_000;
const MAX_UPLOAD_RETRIES = 4;     // for 503 (capacity) / 429 (rate)
const MAX_HASH_RETRIES   = 3;     // for the (astronomically rare) 409 hash collision

// ── Byte helpers ────────────────────────────────────────────────────────────────

export function concat(...arrays) {
  let total = 0;
  for (const a of arrays) total += a.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

// Correct, streaming base64. Builds the binary string in 32 KB windows (safe for
// Function.apply) then encodes once, so there is exactly one trailing '=' run and no
// invalid mid-string padding. (The naive "btoa per window" approach corrupts any blob
// whose window size is not a multiple of 3 — see core tests.)
export function toBase64(u8) {
  let binary = '';
  const WINDOW = 0x8000; // 32_768
  for (let i = 0; i < u8.length; i += WINDOW) {
    binary += String.fromCharCode.apply(null, u8.subarray(i, i + WINDOW));
  }
  return btoa(binary);
}

export function fromBase64(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// ── Chunks across the extension message boundary ────────────────────────────────
//
// chrome.runtime.sendMessage serialises its message as JSON. An ArrayBuffer or a
// Uint8Array does not survive that: it arrives as {} and new Uint8Array({}) is
// zero bytes long. Until 2026-10-04 every attachment sent through Gmail or
// Outlook web was sealed and uploaded as an empty file while the sender saw
// "Encrypted link inserted" (fase 1, EXT-13-A). So a chunk crosses the boundary
// as a base64 string, and the receiving side checks the decoded length against
// the length that chunk must have. A chunk of the wrong size is refused, never
// sealed: an upload that fails loudly beats a link to an empty file.

export function expectedChunkLength(fileSize, index) {
  const start = index * CHUNK_PLAIN;
  return Math.max(0, Math.min(CHUNK_PLAIN, fileSize - start));
}

export function encodeChunkMessage(bytes) {
  const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return toBase64(u8);
}

export function decodeChunkMessage(b64, fileSize, index) {
  if (typeof b64 !== 'string') {
    throw new ParamantError('chunk_unreadable', 'The file could not be read. Please try again.');
  }
  const u8 = fromBase64(b64);
  if (u8.length !== expectedChunkLength(fileSize, index)) {
    throw new ParamantError('chunk_size_mismatch', 'The file could not be read whole. Nothing was sent. Please try again.');
  }
  return u8;
}

// URL-safe base64 (RFC 4648 §5), no padding — used for the key fragment.
export function urlSafeKey(rawU8) {
  return toBase64(rawU8).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export async function sha256hex(bufferSource) {
  const digest = await crypto.subtle.digest('SHA-256', bufferSource);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function randomFileId() {
  return Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, '0')).join('');
}

export function chunkCount(fileSize) {
  return Math.max(1, Math.ceil(fileSize / CHUNK_PLAIN));
}

// ── Encrypt one chunk → padded 5 MB blob ─────────────────────────────────────────
//
// Layout (matches the parashare receiver exactly):
//   plaintext : 'PRSH'(4) | metaLen(4 BE) | metaJSON | chunkData
//   packet    : 0x02(1)  | nonce(12)      | ctLen(4 BE) | ciphertext(=AES-GCM(plaintext)+tag)
//   blob      : packet ++ random padding, total length === PADDED_BLOCK
// The raw key is returned separately; it is NEVER part of the blob.

export async function encryptChunk(chunkU8, fileMeta) {
  const magic    = new Uint8Array(PRSH_MAGIC);
  const metaBytes = new TextEncoder().encode(JSON.stringify(fileMeta));
  const metaLen   = new Uint8Array(4);
  new DataView(metaLen.buffer).setUint32(0, metaBytes.length, false);
  const plain = concat(magic, metaLen, metaBytes, chunkU8);

  const symKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  const rawKey = new Uint8Array(await crypto.subtle.exportKey('raw', symKey));
  const nonce  = crypto.getRandomValues(new Uint8Array(12));
  const ct     = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, symKey, plain));

  const ctLen = new Uint8Array(4);
  new DataView(ctLen.buffer).setUint32(0, ct.length, false);
  const packet = concat(new Uint8Array([PACKET_VERSION]), nonce, ctLen, ct);

  // Defensive: a chunk that does not fit the padded block would be silently truncated
  // and become undecryptable. CHUNK_PLAIN is sized to prevent this; fail loudly if not.
  if (packet.length > PADDED_BLOCK) {
    throw new ParamantError('chunk_too_large',
      `Encrypted packet ${packet.length}B exceeds ${PADDED_BLOCK}B block. Lower CHUNK_PLAIN.`);
  }

  const padded = new Uint8Array(PADDED_BLOCK);
  padded.set(packet);
  for (let p = packet.length; p < PADDED_BLOCK; p += 65536) {
    crypto.getRandomValues(padded.subarray(p, Math.min(p + 65536, PADDED_BLOCK)));
  }
  return { padded, rawKey };
}

// ── Errors ────────────────────────────────────────────────────────────────────

export class ParamantError extends Error {
  constructor(code, message, { status = null, retryable = false } = {}) {
    super(message);
    this.name = 'ParamantError';
    this.code = code;
    this.status = status;
    this.retryable = retryable;
  }
}

// Human, UI-ready sentence for a 402 monthly-transfer-quota rejection. The relay
// returns { error, dimension, plan, limit }; both consumers show this string
// verbatim (taskpane progress text / injected banner), so the translation lives
// once in the shared core instead of leaking a bare "upload_failed" per surface.
export function quotaReachedMessage(plan, limit) {
  const planPart = plan ? ` on the ${plan} plan` : '';
  const countPart = Number.isFinite(limit)
    ? ` You have used all ${limit} monthly transfer${limit === 1 ? '' : 's'}${planPart}.`
    : (plan ? ` You have used this month's transfer allowance${planPart}.` : '');
  return `Monthly transfer limit reached.${countPart} Upgrade at ${UPGRADE_URL} to send more.`;
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(new ParamantError('aborted', 'Upload cancelled'));
    const t = setTimeout(resolve, ms);
    signal?.addEventListener('abort', () => { clearTimeout(t); reject(new ParamantError('aborted', 'Upload cancelled')); }, { once: true });
  });
}

// ── Auth / discovery ──────────────────────────────────────────────────────────

export async function checkKey(relay, apiKey, signal) {
  const res = await fetch(`${relay}/v2/check-key`, {
    method: 'POST',
    headers: { 'X-Api-Key': apiKey, 'Content-Type': 'application/json' },
    signal: signal ?? AbortSignal.timeout(8000),
  });
  // A 429 says nothing about the key. Reporting it as valid:false told a
  // customer with a good key "Invalid API key" (fase 1, EXT-19-A, SEND-03-A).
  if (res.status === 429) return { valid: false, plan: null, rateLimited: true };
  if (!res.ok) return { valid: false, plan: null };
  return res.json();
}

export const RATE_LIMITED_MESSAGE = 'Too many sign-in attempts from this network. Wait a minute and try again.';

// Race check-key across the sectored relays and return the one that accepts the key.
// Callers should cache the result per key to avoid repeating the fan-out every transfer.
export async function discoverRelay(apiKey, preferred) {
  if (preferred) return preferred.replace(/\/+$/, '');
  const results = await Promise.allSettled(
    SECTOR_RELAYS.map(async url => {
      const r = await fetch(`${url}/v2/check-key`, {
        method: 'POST',
        headers: { 'X-Api-Key': apiKey },
        signal: AbortSignal.timeout(5000),
      });
      if (r.status === 429) throw new Error('rate_limited');
      const d = await r.json();
      if (!d.valid) throw new Error('invalid');
      return url;
    })
  );
  const found = results.find(r => r.status === 'fulfilled');
  if (found) return found.value;
  // No sector said yes. If one of them only said "slow down", the key may well
  // be good: say that, instead of falling through to a verdict on the key.
  if (results.some(r => r.status === 'rejected' && r.reason?.message === 'rate_limited')) {
    throw new ParamantError('rate_limited', RATE_LIMITED_MESSAGE, { status: 429, retryable: true });
  }
  return DEFAULT_RELAY;
}

// ── Upload one padded blob ──────────────────────────────────────────────────────
// Retries on 503 (relay at capacity) and 429 (rate/trial), honouring Retry-After.
// Returns { token, effectiveTtlMs }.

// Exactly one credential: an API key (X-Api-Key) or a ParaSend session token
// (Authorization: Bearer pst_...), which is what a signed-in account without a
// key on this device uses.
function authHeaders(apiKey, bearer) {
  return bearer ? { Authorization: `Bearer ${bearer}` } : { 'X-Api-Key': apiKey };
}

async function uploadPadded({ relay, apiKey, bearer, padded, meta, ttlMs, signal }) {
  const hash = await sha256hex(padded);
  const body = JSON.stringify({ hash, payload: toBase64(padded), ttl_ms: ttlMs, meta });

  for (let attempt = 0; ; attempt++) {
    let res;
    try {
      res = await fetch(`${relay}/v2/inbound`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', ...authHeaders(apiKey, bearer) },
        body,
        signal: signal ?? AbortSignal.timeout(UPLOAD_TIMEOUT_MS),
      });
    } catch (e) {
      if (e.name === 'AbortError' || e.code === 'aborted') throw new ParamantError('aborted', 'Upload cancelled');
      if (attempt < MAX_UPLOAD_RETRIES) { await sleep(800 * (attempt + 1), signal); continue; }
      throw new ParamantError('network', 'Network error reaching the relay. Check your connection.');
    }

    if (res.ok) {
      const data = await res.json();
      if (!data.download_token) throw new ParamantError('no_token', 'Relay did not return a download token.');
      return { token: data.download_token, effectiveTtlMs: data.ttl_ms ?? ttlMs };
    }

    if (res.status === 409) {
      // Hash already in use — random padding makes this essentially impossible, but if it
      // happens the caller must re-encrypt (new padding ⇒ new hash). Signal that.
      throw new ParamantError('hash_collision', 'Hash collision', { status: 409, retryable: true });
    }

    if ((res.status === 503 || res.status === 429) && attempt < MAX_UPLOAD_RETRIES) {
      const retryAfter = parseInt(res.headers.get('Retry-After') || '', 10);
      const waitMs = Number.isFinite(retryAfter) ? retryAfter * 1000 : 1000 * (attempt + 1);
      await sleep(waitMs, signal);
      continue;
    }

    if (res.status === 402) {
      // Monthly transfer quota reached (Phase 4 gate on /v2/inbound). NOT retryable:
      // retrying only re-hits the cap. Surface a structured, human upgrade melding so
      // the UI shows a real next step instead of a bare "upload_failed".
      const q = await res.json().catch(() => ({}));
      if (q.error === 'monthly_transfer_quota_reached') {
        const e = new ParamantError('quota_reached', quotaReachedMessage(q.plan, q.limit), { status: 402 });
        e.dimension  = q.dimension || 'transfers_month';
        e.plan       = q.plan ?? null;
        e.limit      = (q.limit ?? null);
        e.upgradeUrl = UPGRADE_URL;
        throw e;
      }
      throw new ParamantError('upload_failed', q.error || 'Upload failed (HTTP 402).', { status: 402 });
    }

    const err = await res.json().catch(() => ({}));
    throw new ParamantError('upload_failed', err.error || `Upload failed (HTTP ${res.status}).`, { status: res.status });
  }
}

// Encrypt + upload a single chunk, transparently re-encrypting on the rare 409.
// Returns { token, key, effectiveTtlMs }. Used by both consumers.
export async function sealAndUploadChunk({ relay, apiKey, bearer, chunkU8, fileMeta, relayMeta, ttlMs, signal }) {
  for (let hashAttempt = 0; ; hashAttempt++) {
    const { padded, rawKey } = await encryptChunk(chunkU8, fileMeta);
    try {
      const { token, effectiveTtlMs } = await uploadPadded({ relay, apiKey, bearer, padded, meta: relayMeta, ttlMs, signal });
      return { token, key: urlSafeKey(rawKey), effectiveTtlMs };
    } catch (e) {
      if (e.code === 'hash_collision' && hashAttempt < MAX_HASH_RETRIES) continue;
      throw e;
    }
  }
}

// ── Share URL ───────────────────────────────────────────────────────────────────
// Format (read by frontend/js/get.page.js, the FileLink branch):
//   {RECEIVE_BASE}?t=T1,T2&c=N&r=RELAY#k=K1,K2
//
// No file name in the URL (hertest T4-9). The query of a link is sent to the
// server on every open and ends up in mail logs, proxies and scanners; the
// promise is "only an address and a link". The name travels inside the seal
// (fileMeta.file_name) and the receiver reads it from there. `name` is still
// accepted so existing callers keep working; it is not used.
export function buildShareUrl({ tokens, name, chunks, relay, keys }) {
  const t = tokens.map(encodeURIComponent).join(',');
  const r = encodeURIComponent(relay);
  return `${RECEIVE_BASE}?t=${t}&c=${chunks}&r=${r}#k=${keys.join(',')}`;
}

// ── High-level orchestration (whole file already in memory) ──────────────────────
// Used by the Outlook add-in. The Chromium service worker streams chunk-by-chunk from the
// content script instead (see service-worker.js) but uses the same sealAndUploadChunk().
//
// onProgress({ phase, chunkIndex, totalChunks, fraction }) is called as work advances.

export async function encryptAndUpload({
  bytes, fileName, fileSize, apiKey, relay, ttlMs, deviceId = 'paramant-mail', onProgress, signal,
}) {
  const total  = chunkCount(fileSize);
  const fileId = randomFileId();
  const tokens = [];
  const keys   = [];
  let effectiveTtlMs = ttlMs;

  for (let i = 0; i < total; i++) {
    if (signal?.aborted) throw new ParamantError('aborted', 'Upload cancelled');
    const start = i * CHUNK_PLAIN;
    const chunkU8 = bytes.subarray(start, Math.min(start + CHUNK_PLAIN, bytes.length));

    onProgress?.({ phase: 'upload', chunkIndex: i, totalChunks: total, fraction: i / total });

    const res = await sealAndUploadChunk({
      relay, apiKey, chunkU8, ttlMs, signal,
      // Encrypted metadata (inside the blob, for the receiver). Never seen by the relay.
      fileMeta: { file_id: fileId, file_name: fileName, file_size: fileSize, chunk_index: i, total_chunks: total, chunk_size: chunkU8.length },
      // Cleartext metadata sent to the relay: only what it needs (dedup + routing). No filename, no size.
      relayMeta: { device_id: deviceId, file_id: fileId, chunk_index: i, total_chunks: total },
    });
    tokens.push(res.token);
    keys.push(res.key);
    effectiveTtlMs = Math.min(effectiveTtlMs, res.effectiveTtlMs);
  }

  onProgress?.({ phase: 'done', chunkIndex: total, totalChunks: total, fraction: 1 });

  return {
    shareUrl: buildShareUrl({ tokens, name: fileName, chunks: total, relay, keys }),
    tokens, keys, relay, totalChunks: total,
    expiresAt: new Date(Date.now() + effectiveTtlMs).toISOString(),
    effectiveTtlMs,
  };
}
