// service-worker.js — message router + chunked transfer orchestration.
//
// Why the upload lives here and not in the content script: MV3 content scripts inherit the
// page's origin for CORS, so a script on mail.google.com cannot POST to relay.paramant.app.
// The service worker can (host_permissions grant it a CORS exemption), and keeping the API
// key here means the page's world never sees it. The content script reads the file in
// plaintext chunks and streams them in; the worker encrypts each chunk and uploads it.

import {
  getCapabilities, loginWithApiKey, loginWithTotp, verifySession, logout, getUploadCredentials,
} from './auth-client.js';
import { sealAndUploadChunk, buildShareUrl, chunkCount, randomFileId } from '../../../shared/paramant-core.js';
import { getSettings, addHistory } from '../shared/settings.js';

// ── Message router ────────────────────────────────────────────────────────────────

const handlers = {
  GET_CAPABILITIES: () => getCapabilities(),
  CHECK_SESSION:    () => verifySession(),
  LOGIN_APIKEY:     msg => loginWithApiKey(msg.apikey),
  LOGIN_TOTP:       msg => loginWithTotp(msg.email, msg.totp),
  LOGOUT:           () => logout(),
  OPEN_POPUP:       () => openPopup(),
  TRANSFER_BEGIN:   msg => transferBegin(msg),
  TRANSFER_CHUNK:   msg => transferChunk(msg),
  TRANSFER_FINISH:  msg => transferFinish(msg),
  TRANSFER_ABORT:   msg => transferAbort(msg),
};

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  const handler = handlers[msg?.type];
  if (!handler) return false;
  Promise.resolve(handler(msg))
    .then(sendResponse)
    .catch(err => sendResponse({ ok: false, success: false, error: String(err?.message || err) }));
  return true; // async response
});

// ── Open the popup when an unauthenticated user clicks the compose button ───────────

async function openPopup() {
  try {
    await chrome.action.openPopup(); // Chrome 127+, best effort
    return { ok: true };
  } catch {
    // Older Chrome / no user gesture: nudge the toolbar icon instead.
    try {
      await chrome.action.setBadgeText({ text: '!' });
      await chrome.action.setBadgeBackgroundColor({ color: '#1D4ED8' });
      setTimeout(() => chrome.action.setBadgeText({ text: '' }), 8000);
    } catch {}
    return { ok: false, fallback: 'toolbar' };
  }
}

// ── Transfers ───────────────────────────────────────────────────────────────────────
// One entry per in-flight file. Held in memory; if the worker is evicted mid-transfer the
// content script's next chunk gets `unknown_transfer` and surfaces a retry to the user.

const transfers = new Map();

async function transferBegin(msg) {
  const creds = await getUploadCredentials();
  if (!creds) return { ok: false, error: 'not_authenticated' };

  const { ttl_ms } = await getSettings();
  const size  = msg.file?.size ?? 0;
  const total = chunkCount(size);
  const id = randomFileId();

  transfers.set(id, {
    tokens: [], keys: [], fileId: randomFileId(),
    name: msg.file?.name || 'attachment', size, total,
    relay: creds.relay, apikey: creds.apikey,
    ttlMs: ttl_ms, effTtlMs: ttl_ms,
  });
  return { ok: true, transferId: id, totalChunks: total };
}

async function transferChunk(msg) {
  const st = transfers.get(msg.transferId);
  if (!st) return { ok: false, error: 'unknown_transfer' };
  try {
    const chunkU8 = new Uint8Array(msg.bytes);
    const res = await sealAndUploadChunk({
      relay: st.relay, apiKey: st.apikey, chunkU8, ttlMs: st.ttlMs,
      fileMeta:  { file_id: st.fileId, file_name: st.name, file_size: st.size, chunk_index: msg.index, total_chunks: st.total, chunk_size: chunkU8.length },
      relayMeta: { device_id: 'paramant-gmail', file_id: st.fileId, chunk_index: msg.index, total_chunks: st.total },
    });
    st.tokens[msg.index] = res.token;
    st.keys[msg.index]   = res.key;
    st.effTtlMs = Math.min(st.effTtlMs, res.effectiveTtlMs);
    return { ok: true, index: msg.index };
  } catch (err) {
    transfers.delete(msg.transferId);
    return { ok: false, error: String(err?.message || err) };
  }
}

async function transferFinish(msg) {
  const st = transfers.get(msg.transferId);
  if (!st) return { ok: false, error: 'unknown_transfer' };
  transfers.delete(msg.transferId);

  if (st.tokens.length !== st.total || st.tokens.some(t => !t)) {
    return { ok: false, error: 'incomplete_transfer' };
  }

  const shareUrl  = buildShareUrl({ tokens: st.tokens, name: st.name, chunks: st.total, relay: st.relay, keys: st.keys });
  const expiresAt = new Date(Date.now() + st.effTtlMs).toISOString();

  // History stores no key material — only what the sender needs to recognise the transfer.
  await addHistory({ name: st.name, size: st.size, chunks: st.total, expires_at: expiresAt });

  return { ok: true, shareUrl, expiresAt, totalChunks: st.total };
}

function transferAbort(msg) {
  transfers.delete(msg.transferId);
  return { ok: true };
}
