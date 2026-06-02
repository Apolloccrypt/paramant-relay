// core.test.js — proves the shared crypto+upload core is byte-compatible with the
// shipping paramant.app/parashare receiver, and that the relay stores exactly what we send.
//
// The decrypt path below is an INDEPENDENT re-implementation of what parashare.html does
// (lines ~1103-1167): read the 0x02 packet out of the padded blob, AES-GCM-decrypt with
// the key from the URL fragment, strip the PRSH frame. If our encrypt feeds that decrypt,
// real recipients can open our links.

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  CHUNK_PLAIN, PADDED_BLOCK, PACKET_VERSION,
  concat, toBase64, urlSafeKey, sha256hex, randomFileId, chunkCount,
  encryptChunk, sealAndUploadChunk, buildShareUrl, encryptAndUpload,
} from '../../shared/paramant-core.js';

// ── Receiver re-implementation (mirrors parashare.html) ──────────────────────────

function readU32BE(u8, off) {
  return ((u8[off] << 24) | (u8[off + 1] << 16) | (u8[off + 2] << 8) | u8[off + 3]) >>> 0;
}

async function parashareDecrypt(paddedBlob, urlSafeKeyStr) {
  const buf = paddedBlob instanceof Uint8Array ? paddedBlob : new Uint8Array(paddedBlob);
  const version = buf[0];
  if (version !== 0x02) throw new Error('Unsupported packet version ' + version);
  const nonce = buf.subarray(1, 13);
  const ctLen = readU32BE(buf, 13);
  const ct = buf.subarray(17, 17 + ctLen);

  const b64 = urlSafeKeyStr.replace(/-/g, '+').replace(/_/g, '/');
  const rawKey = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const symKey = await crypto.subtle.importKey('raw', rawKey, 'AES-GCM', false, ['decrypt']);
  const plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce }, symKey, ct));

  if (plain[0] !== 0x50 || plain[1] !== 0x52 || plain[2] !== 0x53 || plain[3] !== 0x48) {
    throw new Error('Invalid decrypted payload — wrong key?');
  }
  const metaLen = readU32BE(plain, 4);
  const meta = JSON.parse(new TextDecoder().decode(plain.subarray(8, 8 + metaLen)));
  const data = plain.slice(8 + metaLen);
  return { meta, data };
}

function randomBytes(n) {
  const u8 = new Uint8Array(n);
  // crypto.getRandomValues caps at 65536 bytes per call
  for (let i = 0; i < n; i += 65536) crypto.getRandomValues(u8.subarray(i, Math.min(i + 65536, n)));
  return u8;
}

// ── Byte helpers ─────────────────────────────────────────────────────────────────

describe('byte helpers', () => {
  it('concat joins typed arrays in order', () => {
    expect([...concat(new Uint8Array([1, 2]), new Uint8Array([3]))]).toEqual([1, 2, 3]);
  });

  it('toBase64 round-trips through atob at every size and edge', () => {
    for (const size of [0, 1, 2, 3, 8192, 8193, 65536, 1_000_003]) {
      const u8 = randomBytes(size);
      const decoded = Uint8Array.from(atob(toBase64(u8)), c => c.charCodeAt(0));
      expect(decoded).toEqual(u8);
    }
  });

  it('toBase64 output is what the relay (Buffer.from base64) decodes to — no mid-string padding', () => {
    const u8 = randomBytes(PADDED_BLOCK); // exactly the upload size
    const b64 = toBase64(u8);
    // exactly one trailing pad run, never interior '='
    expect(b64.indexOf('=')).toBe(b64.length % 4 === 0 ? b64.replace(/=+$/, '').length : b64.indexOf('='));
    const relayDecoded = Buffer.from(b64, 'base64'); // what relay.js does
    expect(relayDecoded.length).toBe(PADDED_BLOCK);
    expect(Buffer.compare(relayDecoded, Buffer.from(u8))).toBe(0);
  });

  it('urlSafeKey is base64url with no padding or unsafe chars', () => {
    const k = urlSafeKey(randomBytes(32));
    expect(k).not.toMatch(/[+/=]/);
  });

  it('chunkCount matches ceil(size / CHUNK_PLAIN), min 1', () => {
    expect(chunkCount(0)).toBe(1);
    expect(chunkCount(1)).toBe(1);
    expect(chunkCount(CHUNK_PLAIN)).toBe(1);
    expect(chunkCount(CHUNK_PLAIN + 1)).toBe(2);
    expect(chunkCount(CHUNK_PLAIN * 3)).toBe(3);
  });
});

// ── Encryption compatibility ─────────────────────────────────────────────────────

describe('encryptChunk → parashare receiver', () => {
  it('produces a 5 MB blob the receiver decrypts back to the exact plaintext', async () => {
    const plaintext = randomBytes(200_000);
    const fileMeta = { file_id: randomFileId(), file_name: 'rapport €.pdf', file_size: 200_000, chunk_index: 0, total_chunks: 1, chunk_size: 200_000 };
    const { padded, rawKey } = await encryptChunk(plaintext, fileMeta);

    expect(padded.length).toBe(PADDED_BLOCK);
    expect(padded[0]).toBe(PACKET_VERSION);

    const { meta, data } = await parashareDecrypt(padded, urlSafeKey(rawKey));
    expect(data).toEqual(plaintext);
    expect(meta).toEqual(fileMeta);
  });

  it('a full-size chunk (4.9 MB) still fits the padded block and decrypts', async () => {
    const plaintext = randomBytes(CHUNK_PLAIN);
    const { padded, rawKey } = await encryptChunk(plaintext, { file_name: 'big.bin' });
    const { data } = await parashareDecrypt(padded, urlSafeKey(rawKey));
    expect(data.length).toBe(CHUNK_PLAIN);
    expect(data).toEqual(plaintext);
  });

  it('a wrong key fails the AES-GCM auth tag (burn-proof)', async () => {
    const { padded } = await encryptChunk(randomBytes(1000), {});
    await expect(parashareDecrypt(padded, urlSafeKey(randomBytes(32)))).rejects.toThrow();
  });

  it('every blob is unique even for identical input (random nonce + padding)', async () => {
    const pt = randomBytes(1000);
    const a = await encryptChunk(pt, {});
    const b = await encryptChunk(pt, {});
    expect(await sha256hex(a.padded)).not.toBe(await sha256hex(b.padded));
  });
});

// ── Share URL ────────────────────────────────────────────────────────────────────

describe('buildShareUrl', () => {
  it('matches the ?t&n&c&r#k= shape and parses back', () => {
    const url = buildShareUrl({ tokens: ['t1', 't2'], name: 'a b €.pdf', chunks: 2, relay: 'https://legal.paramant.app', keys: ['k1', 'k2'] });
    expect(url.startsWith('https://paramant.app/parashare?')).toBe(true);
    const [base, frag] = url.split('#');
    expect(frag).toBe('k=k1,k2');
    const sp = new URLSearchParams(base.split('?')[1]);
    expect(sp.get('t')).toBe('t1,t2');
    expect(sp.get('c')).toBe('2');
    expect(sp.get('r')).toBe('https://legal.paramant.app');
    expect(decodeURIComponent(sp.get('n'))).toBe('a b €.pdf');
  });
});

// ── Upload (mocked relay) ────────────────────────────────────────────────────────

describe('sealAndUploadChunk', () => {
  beforeEach(() => { vi.restoreAllMocks(); });

  function mockRelay(handler) {
    globalThis.fetch = vi.fn(async (url, opts) => handler(url, opts));
  }

  it('uploads a hash + base64 payload and returns token + key', async () => {
    let seen;
    mockRelay(async (_url, opts) => {
      seen = JSON.parse(opts.body);
      return new Response(JSON.stringify({ ok: true, download_token: 'TOK', ttl_ms: 3600000 }), { status: 200 });
    });
    const res = await sealAndUploadChunk({
      relay: 'https://relay.paramant.app', apiKey: 'pgp_x', chunkU8: randomBytes(500),
      fileMeta: { file_name: 'x' }, relayMeta: { device_id: 'paramant-gmail', file_id: 'fid' }, ttlMs: 3600000,
    });
    expect(res.token).toBe('TOK');
    expect(res.key).not.toMatch(/[+/=]/);
    expect(seen.hash).toMatch(/^[a-f0-9]{64}$/);
    expect(Buffer.from(seen.payload, 'base64').length).toBe(PADDED_BLOCK);
    expect(seen.meta).toEqual({ device_id: 'paramant-gmail', file_id: 'fid' });
    expect(seen.meta.file_name).toBeUndefined(); // relay never sees the filename
  });

  it('retries on 503 (capacity) honouring Retry-After, then succeeds', async () => {
    let calls = 0;
    mockRelay(async () => {
      calls++;
      if (calls === 1) return new Response(JSON.stringify({ error: 'at capacity' }), { status: 503, headers: { 'Retry-After': '0' } });
      return new Response(JSON.stringify({ download_token: 'TOK2', ttl_ms: 1000 }), { status: 200 });
    });
    const res = await sealAndUploadChunk({ relay: 'r', apiKey: 'k', chunkU8: randomBytes(10), fileMeta: {}, relayMeta: {}, ttlMs: 1000 });
    expect(calls).toBe(2);
    expect(res.token).toBe('TOK2');
  });

  it('re-encrypts on a 409 hash collision', async () => {
    let calls = 0;
    mockRelay(async () => {
      calls++;
      if (calls === 1) return new Response(JSON.stringify({ error: 'Hash already in use' }), { status: 409 });
      return new Response(JSON.stringify({ download_token: 'TOK3', ttl_ms: 1000 }), { status: 200 });
    });
    const res = await sealAndUploadChunk({ relay: 'r', apiKey: 'k', chunkU8: randomBytes(10), fileMeta: {}, relayMeta: {}, ttlMs: 1000 });
    expect(calls).toBe(2);
    expect(res.token).toBe('TOK3');
  });

  it('surfaces a clear error on a hard failure', async () => {
    mockRelay(async () => new Response(JSON.stringify({ error: 'Max 5MB on trial' }), { status: 413 }));
    await expect(sealAndUploadChunk({ relay: 'r', apiKey: 'k', chunkU8: randomBytes(10), fileMeta: {}, relayMeta: {}, ttlMs: 1000 }))
      .rejects.toThrow(/Max 5MB/);
  });
});

// ── Full multi-chunk round trip (mocked relay storage) ───────────────────────────

describe('encryptAndUpload → relay store → parashare download', () => {
  it('encrypts, chunks, uploads, and the receiver reassembles the original file', async () => {
    // Simulate the relay: store padded blobs by token, like /v2/inbound + /v2/dl/:token/get.
    const store = new Map();
    let n = 0;
    globalThis.fetch = vi.fn(async (_url, opts) => {
      const body = JSON.parse(opts.body);
      const token = 'tok' + (n++);
      store.set(token, Buffer.from(body.payload, 'base64')); // exactly what the relay keeps
      return new Response(JSON.stringify({ ok: true, download_token: token, ttl_ms: body.ttl_ms }), { status: 200 });
    });

    const original = randomBytes(CHUNK_PLAIN * 2 + 12345); // 3 chunks
    const result = await encryptAndUpload({
      bytes: original, fileName: 'video.mp4', fileSize: original.length,
      apiKey: 'pgp_x', relay: 'https://relay.paramant.app', ttlMs: 86_400_000, deviceId: 'paramant-gmail',
    });

    expect(result.totalChunks).toBe(3);
    const sp = new URLSearchParams(result.shareUrl.split('?')[1].split('#')[0]);
    const tokens = sp.get('t').split(',');
    const keys = result.shareUrl.split('#k=')[1].split(',');
    expect(tokens.length).toBe(3);
    expect(keys.length).toBe(3);

    // Receiver: download each token's stored blob, decrypt with its key, reassemble.
    const parts = [];
    for (let i = 0; i < tokens.length; i++) {
      const blob = store.get(tokens[i]);
      const { data } = await parashareDecrypt(new Uint8Array(blob), keys[i]);
      parts.push(data);
    }
    const reassembled = concat(...parts);
    expect(reassembled.length).toBe(original.length);
    expect(reassembled).toEqual(original);
  });

  it('reports progress and a plausible expiry', async () => {
    globalThis.fetch = vi.fn(async (_url, opts) => {
      const body = JSON.parse(opts.body);
      return new Response(JSON.stringify({ download_token: 't', ttl_ms: body.ttl_ms }), { status: 200 });
    });
    const seen = [];
    const res = await encryptAndUpload({
      bytes: randomBytes(100), fileName: 'a.txt', fileSize: 100,
      apiKey: 'k', relay: 'r', ttlMs: 3_600_000, onProgress: p => seen.push(p.phase),
    });
    expect(seen).toContain('done');
    expect(new Date(res.expiresAt).getTime()).toBeGreaterThan(Date.now());
  });
});
