"use strict";

const DEFAULT_RELAY    = "https://relay.paramant.app";
const PARASHARE_BASE   = "https://paramant.app/parashare";
const CHUNK_PLAIN      = 4.9 * 1024 * 1024; // plaintext bytes per chunk, matching parashare
const PADDED_BLOCK     = 5   * 1024 * 1024; // every upload is padded to exactly this size
const META_MAGIC       = new Uint8Array([0x50, 0x52, 0x53, 0x48]); // 'PRSH'

// ── Helpers ───────────────────────────────────────────────────────────────────

async function sha256hex(buffer) {
  const buf = await crypto.subtle.digest("SHA-256", buffer);
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

function concat(...arrays) {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function toBase64(u8) {
  let s = "";
  // Process in 8 KB slices to avoid call-stack limits on large buffers
  for (let i = 0; i < u8.length; i += 8192) {
    s += btoa(String.fromCharCode(...u8.subarray(i, i + 8192)));
  }
  return s;
}

// ── Encrypt one chunk → padded 5 MB blob (0x01 packet, PRSH header) ──────────

async function encryptChunk(chunkData, fileMeta) {
  // Build PRSH packet: magic(4) | metaLen(4) | meta JSON | chunkData
  const metaBytes = new TextEncoder().encode(JSON.stringify(fileMeta));
  const metaLen   = new Uint8Array(4);
  new DataView(metaLen.buffer).setUint32(0, metaBytes.length, false);
  const plain = concat(META_MAGIC, metaLen, metaBytes, chunkData);

  // AES-256-GCM
  const symKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt"]);
  const rawKey = new Uint8Array(await crypto.subtle.exportKey("raw", symKey));
  const nonce  = crypto.getRandomValues(new Uint8Array(12));
  const ct     = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce }, symKey, plain));

  // 0x01 packet: version(1) | nonce(12) | rawKey(32) | ctLen(4) | ct
  const ctLen = new Uint8Array(4);
  new DataView(ctLen.buffer).setUint32(0, ct.length, false);
  const packet = concat(new Uint8Array([0x01]), nonce, rawKey, ctLen, ct);

  // Pad to exactly PADDED_BLOCK with random bytes (DPI resistance)
  const padded = new Uint8Array(PADDED_BLOCK);
  padded.set(packet.subarray(0, Math.min(packet.length, PADDED_BLOCK)));
  for (let p = packet.length; p < PADDED_BLOCK; p += 65536) {
    crypto.getRandomValues(padded.subarray(p, Math.min(p + 65536, PADDED_BLOCK)));
  }
  return padded;
}

// ── Upload one padded blob ────────────────────────────────────────────────────

async function uploadChunk(relay, apiKey, padded, meta) {
  const hash = await sha256hex(padded);
  const body = JSON.stringify({
    hash,
    payload: toBase64(padded),
    ttl_ms: meta.ttl_ms,
    meta: {
      device_id:    "thunderbird-filelink",
      file_name:    meta.file_name,
      file_size:    meta.file_size,
      file_id:      meta.file_id,
      chunk_index:  meta.chunk_index,
      total_chunks: meta.total_chunks,
    },
  });

  const res = await fetch(`${relay}/v2/inbound`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Api-Key":    apiKey,
    },
    body,
    signal: AbortSignal.timeout(120_000),
  });

  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    if (res.status === 503) throw new Error("Relay at capacity — try again in 10 seconds.");
    throw new Error(err.error || `Upload failed: HTTP ${res.status}`);
  }

  const { download_token } = await res.json();
  if (!download_token) throw new Error("Relay did not return a download token.");
  return download_token;
}

// ── FileLink handler ──────────────────────────────────────────────────────────

browser.cloudFile.onFileUpload.addListener(async (account, { id, name, data }) => {
  const { apiKey, relayUrl } = await browser.storage.local.get(["apiKey", "relayUrl"]);
  if (!apiKey) throw new Error("No PARAMANT API key configured — open the extension settings.");

  const relay       = (relayUrl || DEFAULT_RELAY).replace(/\/$/, "");
  const fileBytes   = new Uint8Array(data);
  const totalChunks = Math.max(1, Math.ceil(fileBytes.length / CHUNK_PLAIN));
  const fileId      = Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, "0")).join("");
  const ttl_ms      = totalChunks > 1 ? 900_000 : 3_600_000;

  const tokens = [];
  for (let i = 0; i < totalChunks; i++) {
    const start     = Math.round(i * CHUNK_PLAIN);
    const chunkData = fileBytes.slice(start, Math.min(start + CHUNK_PLAIN, fileBytes.length));

    const padded = await encryptChunk(chunkData, {
      file_id: fileId, file_name: name, file_size: fileBytes.length,
      chunk_index: i, total_chunks: totalChunks, chunk_size: chunkData.length,
    });

    const token = await uploadChunk(relay, apiKey, padded, {
      file_name: name, file_size: fileBytes.length,
      file_id: fileId, chunk_index: i, total_chunks: totalChunks, ttl_ms,
    });
    tokens.push(token);
  }

  // Use the parashare page so multi-chunk reassembly and decryption work for the recipient
  const url = `${PARASHARE_BASE}?t=${encodeURIComponent(tokens.join(","))}&n=${encodeURIComponent(name)}&c=${totalChunks}`;
  return { url };
});

// Burn-on-read: TTL handles cleanup automatically
browser.cloudFile.onFileDeleted.addListener((_account, _fileId) => {});

// Restore configured state after Thunderbird restarts
browser.cloudFile.onAccountAdded.addListener(async (account) => {
  const { apiKey } = await browser.storage.local.get("apiKey");
  if (apiKey) {
    await browser.cloudFile.updateAccount(account.id, { configured: true });
  }
});
