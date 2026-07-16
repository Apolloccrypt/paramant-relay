'use strict';
// ParaSign Open Developer-API (/v1) — thin public layer over the internal /v2
// envelope machinery. See docs/parasign-open-api-spec.md (Model A: hosted
// signing ceremony).
//
// Design contract with the rest of the relay:
//   * This module owns NO crypto and NO redis of its own. Every relay internal
//     it needs (envelope store, notary key, safeHttpsRequest, ...) is injected
//     via the `deps` object at call time, so the module stays unit-testable
//     with fakes and never reaches into relay.js closures.
//   * The only NEW capability introduced here is the document blobstore — the
//     one deliberate break of the "relay never sees the PDF" invariant, and it
//     is scoped to open-API envelopes only. It is IN-MEMORY + TTL and clearly
//     labelled as the Model-A concession; a production deploy must move it to
//     encrypted-at-rest storage (Redis/S3) with the same TTL semantics.
//
// Status of the surface (honest labelling):
//   FUNCTIONAL: auth (Bearer psk_ + parasign scope), POST /v1/envelopes
//     (create + hash + blob store + envelope.sent webhook), GET /v1/envelopes/:id
//     (status + external status mapping), POST /v1/envelopes/:id/void
//     (+ envelope.voided webhook), GET /document (serves the stored blob).
//   STUB / INTERIM: /receipt returns a notary-signed *interim manifest*, not the
//     full multi-signer .psign (needs a store method exposing raw per-party
//     signatures). PDF stamp-worker absent -> /document serves the UNSTAMPED
//     original (X-ParaSign-Stamped: false). signer.completed / envelope.completed
//     / envelope.declined webhooks are NOT auto-fired (the transition originates
//     in /v2/envelopes/:id/sign, which this build does not modify); emitEvent()
//     is exported so that path can drive them later. Sandbox auto-signer for
//     psk_test_ is a labelled TODO.

const crypto = require('crypto');

const SHA3 = (buf) => crypto.createHash('sha3-256').update(buf).digest('hex');
const MAX_PDF_BYTES = parseInt(process.env.PARASIGN_MAX_PDF_BYTES || String(20 * 1024 * 1024), 10);

// ── Model-A document blobstore (EPHEMERAL, in-memory, TTL) ────────────────────
// id -> { pdf: Buffer, filename, ts, ttlMs }. THE Model-A concession. Not
// durable across restarts by design in this build; production must relocate.
const blobs = new Map();
// id -> side-record the envelope store cannot hold (plaintext emails/names,
// webhook target + per-envelope secret, metadata, test-flag). Also ephemeral.
const meta = new Map();

function _sweep() {
  const now = Date.now();
  for (const [id, b] of blobs) if (b.ttlMs && now - b.ts > b.ttlMs) blobs.delete(id);
  for (const [id, m] of meta)  if (m.ttlMs && now - m.ts > m.ttlMs) meta.delete(id);
}
const _sweepTimer = setInterval(_sweep, 300_000);
if (_sweepTimer.unref) _sweepTimer.unref();

// ── Entitlement (scope) ───────────────────────────────────────────────────────
// A psk_ key grants the parasign scope when its key-table record says so. Three
// accepted representations so this survives the reserved-single-scope enum in
// lib/keys-table.js without forcing a schema migration:
//   rec.scope === 'parasign'  |  rec.parasign === true  |  rec.scopes[] has it.
function hasParaSignScope(rec) {
  if (!rec) return false;
  if (rec.scope === 'parasign') return true;
  if (rec.parasign === true) return true;
  if (Array.isArray(rec.scopes) && rec.scopes.includes('parasign')) return true;
  return false;
}

// ── Entitlement hooks (STUBS — wire to billing + admin) ───────────────────────
// Grant point: call from the billing-success handler once a plan that includes
// ParaSign is paid. Toggle point: call from an admin route to enable/disable per
// key. Both mutate the live apiKeys record; persistence to users.json is the
// caller's job (mirror the setup-mint _mutateUsersJson pattern). TODO: persist.
function grantParaSignScope(apiKeys, key, plan) {
  const rec = apiKeys.get(key);
  if (!rec) return false;
  rec.parasign = true;
  if (plan) rec.plan = plan;
  // TODO(entitlement): persist rec to users.json + emit an audit entry.
  return true;
}
function setParaSignEnabled(apiKeys, key, enabled) {
  const rec = apiKeys.get(key);
  if (!rec) return false;
  rec.parasign = !!enabled;
  // TODO(entitlement): persist + audit.
  return true;
}

// ── external status mapping ───────────────────────────────────────────────────
// internal envelope.js states: 'sent' -> 'complete' (+ new 'void').
function externalStatus(env) {
  const s = env.status;
  if (s === 'complete') return 'completed';
  if (s === 'void') return 'void';
  if (s === 'declined') return 'declined';           // not yet produced internally
  if (s === 'sent') return (env.signed_count > 0) ? 'in_progress' : 'sent';
  return s || 'unknown';
}

function jsonRes(res, code, obj, J, extraHeaders) {
  res.writeHead(code, Object.assign({ 'Content-Type': 'application/json' }, extraHeaders || {}));
  res.end(J(obj));
}
const errRes = (res, code, error, message, J) => jsonRes(res, code, { error, message }, J);

// ── per-envelope webhook (reuses safeHttpsRequest + the HMAC-SHA256 recipe) ────
// Mirrors relay.pushWebhooks headers so a client verifies identically:
//   X-Paramant-Sig = hex HMAC_SHA256(webhook_secret, raw_body). Adds a unique
//   X-Paramant-Delivery so clients can dedupe replays.
async function emitEvent(deps, id, event, extra) {
  const m = meta.get(id);
  if (!m || !m.webhook_url) return { skipped: 'no_webhook' };
  const payload = deps.J({
    event, id, ts: new Date().toISOString(),
    data: extra || {}, metadata: m.metadata || {},
  });
  const sig = m.webhook_secret
    ? crypto.createHmac('sha256', m.webhook_secret).update(payload).digest('hex') : '';
  const delivery = crypto.randomBytes(12).toString('hex');
  try {
    await deps.safeHttpsRequest(m.webhook_url, {
      method: 'POST', timeout: 5000,
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'X-Paramant-Event': event,
        'X-Paramant-Sig': sig,
        'X-Paramant-Delivery': delivery,
        'User-Agent': 'paramant-relay/parasign-v1',
      },
      body: payload,
    });
    return { ok: true, delivery };
  } catch (e) {
    deps.log && deps.log('warn', 'parasign_v1_webhook_fail', { id, event, err: e.message, code: e.code });
    return { ok: false, err: e.message };
  }
}

// ── main router ───────────────────────────────────────────────────────────────
// deps: { req, res, method, path, query, clientIp, authHeader, publicOrigin,
//         apiKeys, envStore, envCreateRateOk, safeHttpsRequest, canonicalJSON,
//         sigEngine, relayIdentity, readBody, J, log }
async function route(deps) {
  const { res, method, path, query, apiKeys, envStore, J } = deps;

  // 1) AUTH — Bearer psk_live_/psk_test_ + parasign scope.
  const m = /^Bearer\s+(.+)$/i.exec((deps.authHeader || '').trim());
  const token = m ? m[1].trim() : '';
  const isPsk = /^psk_(live|test)_/.test(token);
  if (!token || !isPsk) {
    return errRes(res, 401,
      'unauthorized',
      'Missing or malformed API key. Send Authorization: Bearer psk_live_... / Geen of ongeldige API-sleutel; stuur Authorization: Bearer psk_live_...',
      J);
  }
  const mode = token.startsWith('psk_test_') ? 'test' : 'live';
  const rec = apiKeys.get(token);
  if (!rec || rec.active === false) {
    return errRes(res, 401, 'unauthorized',
      'API key not recognised or revoked. / API-sleutel onbekend of ingetrokken.', J);
  }
  if (!hasParaSignScope(rec)) {
    return errRes(res, 403, 'forbidden_scope',
      'This key lacks the "parasign" scope. Enable ParaSign for this key/account. / Deze sleutel mist de scope "parasign". Activeer ParaSign voor deze sleutel/dit account.', J);
  }

  // Sub-path after /v1/envelopes ...
  // /v1/envelopes            (POST create)
  // /v1/envelopes/:id        (GET status)
  // /v1/envelopes/:id/document | /receipt   (GET)
  // /v1/envelopes/:id/void   (POST)
  if (!envStore) {
    return errRes(res, 503, 'store_unavailable', 'Envelope store unavailable (redis/crypto not ready).', J);
  }

  if (path === '/v1/envelopes' && method === 'POST') {
    return createEnvelope(deps, token, mode, rec);
  }

  const tail = path.startsWith('/v1/envelopes/') ? path.slice('/v1/envelopes/'.length) : null;
  if (tail !== null) {
    const [id, sub] = tail.split('/');
    if (!/^[A-Za-z0-9_-]{20,64}$/.test(id)) return errRes(res, 404, 'not_found', 'Unknown envelope.', J);
    if (!sub && method === 'GET')             return getEnvelope(deps, id);
    if (sub === 'document' && method === 'GET') return getDocument(deps, id);
    if (sub === 'receipt'  && method === 'GET') return getReceipt(deps, id);
    if (sub === 'void'     && method === 'POST') return voidEnvelope(deps, id, token);
  }

  return errRes(res, 404, 'not_found', 'No such /v1 route.', J);
}

// ── POST /v1/envelopes ────────────────────────────────────────────────────────
async function createEnvelope(deps, apiKey, mode, rec) {
  const { res, apiKeys, envStore, envCreateRateOk, readBody, J, publicOrigin } = deps;
  if (!envCreateRateOk(apiKey)) {
    return jsonRes(res, 429, { error: 'rate_limited', message: 'Envelope create quota exceeded (50/hour/key).' }, J, { 'Retry-After': '3600' });
  }

  let d;
  try { d = JSON.parse((await readBody(deps.req, MAX_PDF_BYTES + 1_000_000)).toString()); }
  catch (e) { return errRes(res, 400, 'bad_json', 'Body is not valid JSON.', J); }

  // 1) obtain PDF bytes (base64 or HTTPS url via the SSRF-guarded fetcher).
  let pdf = null;
  const doc = d.document || {};
  try {
    if (doc.content_base64) {
      pdf = Buffer.from(String(doc.content_base64), 'base64');
    } else if (doc.url) {
      const r = await deps.safeHttpsRequest(String(doc.url), { method: 'GET', timeout: 8000 });
      if (r.status !== 200) return errRes(res, 422, 'document_unfetchable', 'document.url did not return 200.', J);
      pdf = r.body;
    } else {
      return errRes(res, 400, 'missing_document', 'Provide document.content_base64 or document.url.', J);
    }
  } catch (e) {
    if (e.code === 'SSRF_URL' || e.code === 'SSRF_DNS') return errRes(res, 422, 'document_unfetchable', 'document.url rejected by SSRF guard.', J);
    return errRes(res, 422, 'document_unfetchable', 'Could not read the document.', J);
  }
  if (!pdf || pdf.length === 0) return errRes(res, 400, 'empty_document', 'Empty document.', J);
  if (pdf.length > MAX_PDF_BYTES) return jsonRes(res, 413, { error: 'document_too_large', message: `Max ${MAX_PDF_BYTES} bytes.` }, J);
  if (pdf.slice(0, 5).toString('latin1') !== '%PDF-') return errRes(res, 422, 'not_a_pdf', 'Document does not look like a PDF (%PDF- header missing).', J);

  // 2) validate signers.
  const signers = Array.isArray(d.signers) ? d.signers : [];
  if (signers.length === 0) return errRes(res, 400, 'missing_signers', 'At least one signer is required.', J);
  const parties = signers.map(s => ({ label: (s && s.name) || '', email: (s && s.email) || '' }));

  // 3) hash + create internal envelope. Default binding_mode 'email' (Model A
  //    hosted ceremony: each slot bound to its invited mailbox).
  const docHash = SHA3(pdf);
  const bindingMode = (d.binding_mode === 'open') ? 'open' : 'email';
  const ttlDays = Number.isFinite(d.ttl_days) ? d.ttl_days : undefined;
  let out;
  try {
    out = await envStore.create({
      creatorApiKeyHash: SHA3(Buffer.from(apiKey)),
      docHash, parties,
      originalFilename: (d.original_filename || '').toString(),
      expiresInDays: ttlDays,
      bindingMode,
    });
  } catch (e) {
    return errRes(res, 400, 'create_failed', e.message, J);
  }

  // 4) side-records: blob (Model-A) + meta (webhook/metadata/plaintext).
  const webhookUrl = (typeof d.webhook_url === 'string' && d.webhook_url) ? d.webhook_url : null;
  const webhookSecret = webhookUrl ? crypto.randomBytes(32).toString('hex') : null;
  const ttlMs = (out.expires_at ? (new Date(out.expires_at).getTime() - Date.now()) : 30 * 86400_000);
  blobs.set(out.id, { pdf, filename: (d.original_filename || 'document.pdf').toString(), ts: Date.now(), ttlMs });
  meta.set(out.id, {
    apiKey, accountId: (rec && rec.account_id) || apiKey, mode,
    webhook_url: webhookUrl, webhook_secret: webhookSecret,
    metadata: (d.metadata && typeof d.metadata === 'object') ? d.metadata : {},
    signers: signers.map((s, i) => ({ index: i, name: (s.name || ''), email: (s.email || ''), order: s.order || (i + 1) })),
    original_filename: (d.original_filename || '').toString(),
    ts: Date.now(), ttlMs,
  });

  const origin = publicOrigin || '';
  const signerOut = out.party_links.map((pl, i) => ({
    index: pl.party_index,
    name: signers[i] ? (signers[i].name || null) : null,
    email: signers[i] ? (signers[i].email || null) : null,
    order: signers[i] ? (signers[i].order || (i + 1)) : (i + 1),
    status: 'pending',
    sign_url: origin + pl.sign_path,
  }));

  // 5) envelope.sent webhook (functional).
  emitEvent(deps, out.id, 'envelope.sent', { status: 'sent', signer_count: signerOut.length });

  // TODO(sandbox): psk_test_ envelopes should be auto-signed by a throwaway
  // ML-DSA sandbox signer so integrators can test end-to-end without a human.
  const sandboxNote = (mode === 'test')
    ? 'sandbox auto-signer not yet wired (TODO); this test envelope behaves like a live one'
    : undefined;

  return jsonRes(res, 201, {
    id: out.id,
    status: 'sent',
    mode,
    doc_hash: docHash,
    binding_mode: out.binding_mode,
    created_at: out.created_at,
    expires_at: out.expires_at,
    signers: signerOut,
    webhook_secret: webhookSecret,     // returned ONCE, for HMAC verification
    metadata: meta.get(out.id).metadata,
    _sandbox_note: sandboxNote,
  }, J);
}

// ── GET /v1/envelopes/:id ─────────────────────────────────────────────────────
async function getEnvelope(deps, id) {
  const { res, envStore, J } = deps;
  let env;
  try { env = await envStore.getRedacted(id); } catch (e) { return errRes(res, 503, 'store_unavailable', e.message, J); }
  if (!env) return errRes(res, 404, 'not_found', 'Unknown envelope.', J);
  const m = meta.get(id) || {};
  const ext = externalStatus(env);
  const nameFor = (i) => (m.signers && m.signers[i]) ? m.signers[i].name : (env.parties[i] && env.parties[i].label) || null;
  const body = {
    id: env.id,
    status: ext,
    signers: env.parties.map(p => ({
      index: p.index,
      name: nameFor(p.index),
      status: p.status,
      signed_at: p.signed_at || undefined,
    })),
    signed_count: env.signed_count,
    signer_count: env.party_count,
    created_at: env.created_at,
    expires_at: env.expires_at,
    documents: null,
    metadata: m.metadata || {},
  };
  if (ext === 'completed') {
    body.documents = {
      signed_pdf: `/v1/envelopes/${env.id}/document`,
      receipt: `/v1/envelopes/${env.id}/receipt`,
    };
  }
  return jsonRes(res, 200, body, J);
}

// ── GET /v1/envelopes/:id/document ────────────────────────────────────────────
async function getDocument(deps, id) {
  const { res, envStore, J } = deps;
  let env;
  try { env = await envStore.getRedacted(id); } catch (e) { return errRes(res, 503, 'store_unavailable', e.message, J); }
  if (!env) return errRes(res, 404, 'not_found', 'Unknown envelope.', J);
  if (env.status !== 'complete') return errRes(res, 409, 'not_ready', 'Envelope is not completed yet.', J);
  const b = blobs.get(id);
  if (!b) return errRes(res, 404, 'document_gone', 'Document blob expired or unavailable (ephemeral Model-A store).', J);
  // STUB: no stamp-worker in this build -> the ORIGINAL (unstamped) PDF is
  // returned. X-ParaSign-Stamped: false makes that explicit to the caller.
  const fname = (b.filename || 'document.pdf').replace(/"/g, '');
  res.writeHead(200, {
    'Content-Type': 'application/pdf',
    'Content-Length': b.pdf.length,
    'Content-Disposition': `attachment; filename="${fname}"`,
    'X-ParaSign-Stamped': 'false',
  });
  return res.end(b.pdf);
}

// ── GET /v1/envelopes/:id/receipt ─────────────────────────────────────────────
// INTERIM: returns a notary-signed manifest over the envelope metadata, not the
// full per-signer .psign. Building the true .psign needs a store method that
// exposes raw per-party (signature, pubkey); getRedacted deliberately hides
// those. Labelled version '1-interim'. Verifiable with the relay notary pubkey.
async function getReceipt(deps, id) {
  const { res, envStore, canonicalJSON, sigEngine, relayIdentity, J } = deps;
  let env;
  try { env = await envStore.getRedacted(id); } catch (e) { return errRes(res, 503, 'store_unavailable', e.message, J); }
  if (!env) return errRes(res, 404, 'not_found', 'Unknown envelope.', J);
  if (env.status !== 'complete') return errRes(res, 409, 'not_ready', 'Envelope is not completed yet.', J);
  if (!sigEngine || !relayIdentity) return errRes(res, 503, 'notary_unavailable', 'Notary key not available.', J);

  const manifest = {
    type: 'parasign-envelope-receipt',
    version: '1-interim',
    algorithm: 'ML-DSA-65',
    envelope_id: env.id,
    document_hash: env.doc_hash,
    document_hash_algo: 'sha3-256',
    status: 'completed',
    created_at: env.created_at,
    completed_at: env.completed_at,
    parties: env.parties.map(p => ({ index: p.index, label: p.label, signer_pk_hash: p.signer_pk_hash, signed_at: p.signed_at })),
    notary: { relay_pk_hash: relayIdentity.pk_hash },
  };
  let notarySig;
  try { notarySig = Buffer.from(sigEngine.sign(Buffer.from(canonicalJSON(manifest), 'utf8'), relayIdentity.sk)).toString('base64'); }
  catch (e) { return errRes(res, 500, 'notary_sign_failed', e.message, J); }
  manifest.notary_signature = notarySig;

  const m = meta.get(id) || {};
  const base = (m.original_filename || 'document').replace(/\.pdf$/i, '').replace(/"/g, '');
  res.writeHead(200, {
    'Content-Type': 'application/json',
    'Content-Disposition': `attachment; filename="${base}.psign"`,
    'X-ParaSign-Receipt-Kind': 'interim-manifest',
  });
  return res.end(J(manifest));
}

// ── POST /v1/envelopes/:id/void ───────────────────────────────────────────────
async function voidEnvelope(deps, id, apiKey) {
  const { res, envStore, readBody, J } = deps;
  let reason = '';
  try { const d = JSON.parse((await readBody(deps.req, 4096)).toString() || '{}'); reason = (d.reason || '').toString(); } catch (_) {}
  let out;
  try { out = await envStore.voidEnvelope(id, reason); }
  catch (e) { return errRes(res, 503, 'store_unavailable', e.message, J); }
  if (!out.ok && out.code === 'not_found') return errRes(res, 404, 'not_found', 'Unknown envelope.', J);
  if (!out.ok && out.code === 'already_complete') return errRes(res, 409, 'already_complete', 'A completed envelope cannot be voided.', J);
  if (!out.ok) return errRes(res, 409, out.code || 'conflict', 'Void rejected.', J);
  emitEvent(deps, id, 'envelope.voided', { status: 'void', reason });
  return jsonRes(res, 200, { id, status: 'void', voided_at: out.voided_at }, J);
}

module.exports = {
  route, emitEvent, hasParaSignScope, externalStatus,
  grantParaSignScope, setParaSignEnabled,
  _blobs: blobs, _meta: meta,   // exposed for tests / diagnostics
};
