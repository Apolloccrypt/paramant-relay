// paramant-core.js — shared encrypt + upload core for the Paramant mail integrations.
//
// One module, two consumers:
//   • Chromium extension service worker (Gmail)  — calls sealAndUploadChunk() per chunk
//   • Outlook Office.js add-in (taskpane)         — calls encryptAndUpload() on the whole file
//
// The output is byte-compatible with the recipient page at paramant.app/parashare
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

export const PARASHARE_BASE = 'https://paramant.app/parashare';
export const DEFAULT_RELAY  = 'https://relay.paramant.app';

// Sectored relays. An API key is valid on exactly one of these; discoverRelay() finds it.
export const SECTOR_RELAYS = Object.freeze([
  'https://relay.paramant.app',
  'https://health.paramant.app',
  'https://legal.paramant.app',
  'https://finance.paramant.app',
  'https://iot.paramant.app',
]);

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
  if (!res.ok) return { valid: false, plan: null };
  return res.json();
}

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
      const d = await r.json();
      if (!d.valid) throw new Error('invalid');
      return url;
    })
  );
  const found = results.find(r => r.status === 'fulfilled');
  return found ? found.value : DEFAULT_RELAY;
}

// ── Upload one padded blob ──────────────────────────────────────────────────────
// Retries on 503 (relay at capacity) and 429 (rate/trial), honouring Retry-After.
// Returns { token, effectiveTtlMs }.

async function uploadPadded({ relay, apiKey, padded, meta, ttlMs, signal }) {
  const hash = await sha256hex(padded);
  const body = JSON.stringify({ hash, payload: toBase64(padded), ttl_ms: ttlMs, meta });

  for (let attempt = 0; ; attempt++) {
    let res;
    try {
      res = await fetch(`${relay}/v2/inbound`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Api-Key': apiKey },
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

    const err = await res.json().catch(() => ({}));
    throw new ParamantError('upload_failed', err.error || `Upload failed (HTTP ${res.status}).`, { status: res.status });
  }
}

// Encrypt + upload a single chunk, transparently re-encrypting on the rare 409.
// Returns { token, key, effectiveTtlMs }. Used by both consumers.
export async function sealAndUploadChunk({ relay, apiKey, chunkU8, fileMeta, relayMeta, ttlMs, signal }) {
  for (let hashAttempt = 0; ; hashAttempt++) {
    const { padded, rawKey } = await encryptChunk(chunkU8, fileMeta);
    try {
      const { token, effectiveTtlMs } = await uploadPadded({ relay, apiKey, padded, meta: relayMeta, ttlMs, signal });
      return { token, key: urlSafeKey(rawKey), effectiveTtlMs };
    } catch (e) {
      if (e.code === 'hash_collision' && hashAttempt < MAX_HASH_RETRIES) continue;
      throw e;
    }
  }
}

// ── Share URL ───────────────────────────────────────────────────────────────────
// Format (verified against parashare.html receiver):
//   {PARASHARE_BASE}?t=T1,T2&n=NAME&c=N&r=RELAY#k=K1,K2

export function buildShareUrl({ tokens, name, chunks, relay, keys }) {
  // Encoded exactly like the shipping sender so the parashare receiver
  // (which does decodeURIComponent(sp.get('n'))) reads every field back intact.
  const t = tokens.map(encodeURIComponent).join(',');
  const r = encodeURIComponent(relay);
  const n = encodeURIComponent(name);
  return `${PARASHARE_BASE}?t=${t}&n=${n}&c=${chunks}&r=${r}#k=${keys.join(',')}`;
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
