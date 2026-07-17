'use strict';
// ParaSign Open Developer-API (/v1) - thin public layer over the internal /v2
// envelope machinery. See docs/parasign-open-api-spec.md (Model A: hosted
// signing ceremony).
//
// Design contract with the rest of the relay:
//   * This module owns NO crypto and NO redis of its own. Every relay internal
//     it needs (envelope store, notary key, safeHttpsRequest, ...) is injected
//     via the `deps` object at call time, so the module stays unit-testable
//     with fakes and never reaches into relay.js closures.
//   * The only NEW capability introduced here is the document blobstore - the
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

// Constant-time compare of two equal-length hex strings (SHA3-256 fingerprints).
// false for empty / mismatched-length / non-string inputs.
function hexEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length === 0 || a.length !== b.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8')); }
  catch { return false; }
}

// ── Receipt authorization ─────────────────────────────────────────────────────
// The scope gate (psk_ + parasign) only proves the caller may use ParaSign at
// all -- NOT that they may pull THIS envelope's full .psign with the raw signer
// signatures. This is the per-envelope owner/participant check. Authorized iff:
//   (a) OWNER by durable fingerprint -- create() stored SHA3(api_key) as
//       creator_api_hash; recompute from the presented key and constant-time
//       compare. Survives restarts (Redis-backed), independent of the ephemeral
//       meta map. This is the authoritative owner check.
//   (b) OWNER by account -- a DIFFERENT key on the SAME account that created it.
//       The durable record only fingerprints the creating key, so this leans on
//       the ephemeral meta side-record (accountId captured at create); best-
//       effort convenience layered on top of (a).
//   (c) PARTICIPANT by invite token -- a signer proves membership with the per-
//       party invite token from their signing link, via header
//       X-ParaSign-Invite-Token or ?invite_token=/?t=. Verified constant-time
//       against every party slot by the store.
// Anything else -> not authorized (the caller then gets a generic 404, so it
// cannot tell "not yours" from "does not exist").
// OWNER-only check -- the (a)+(b) half of authorizeReceipt, split out so the
// destructive/private owner-only routes (void, document) and the owner-OR-
// participant receipt route share ONE definition of "who owns this envelope".
// Synchronous: both owner paths are local (fingerprint + ephemeral meta).
function isEnvelopeOwner(deps, id, token, rec, env) {
  // (a) durable owner fingerprint -- create() stored SHA3(api_key); recompute
  //     from the presented key and constant-time compare.
  if (env && env.creator_api_hash && hexEqual(SHA3(Buffer.from(token)), env.creator_api_hash)) return true;
  // (b) same-account owner (ephemeral meta) -- a different key on the same acct.
  const m = meta.get(id);
  const acct = rec && rec.account_id;
  if (m && acct && m.accountId && m.accountId === acct) return true;
  return false;
}

async function authorizeReceipt(deps, id, token, rec, env) {
  // (a)+(b) OWNER (durable fingerprint or same-account).
  if (isEnvelopeOwner(deps, id, token, rec, env)) return true;
  // (c) participant invite token (header preferred; query fallback).
  const hdr = (deps.req && deps.req.headers && deps.req.headers['x-parasign-invite-token']) || '';
  const q = (deps.query && (deps.query.invite_token || deps.query.t)) || '';
  const inviteTok = (hdr || q || '').toString();
  if (inviteTok) {
    try { if ((await deps.envStore.isParticipantToken(id, inviteTok)) >= 0) return true; }
    catch { /* store hiccup -> deny */ }
  }
  return false;
}

// ── Entitlement hooks (STUBS - wire to billing + admin) ───────────────────────
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

  // 1) AUTH - Bearer psk_live_/psk_test_ + parasign scope.
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
    if (!sub && method === 'GET')             return getEnvelope(deps, id, token, rec);
    if (sub === 'document' && method === 'GET') return getDocument(deps, id, token, rec);
    if (sub === 'receipt'  && method === 'GET') return getReceipt(deps, id, token, rec);
    if (sub === 'void'     && method === 'POST') return voidEnvelope(deps, id, token, rec);
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

  // 2b) Entitlement metering. Count this create against the account's monthly
  //     ParaSign signing quota for its plan (tiers.js signs_month). This is what
  //     ties a psk_ key to the paid entitlement layer: over the plan cap -> 402
  //     monthly_sign_quota_reached, no envelope created, nothing else counted.
  //     Injected (deps.signQuotaGate) so this module owns no redis; it fails OPEN
  //     on missing plan/redis so a paying user is never blocked by infra.
  if (typeof deps.signQuotaGate === 'function') {
    const meteredAccount = (rec && rec.account_id) || apiKey;
    let g;
    // Pass the whole key record so the gate can read plan_parasign (ParaSign
    // tier), not just the product-blind legacy plan. Fallback stays legacy-plan.
    try { g = await deps.signQuotaGate(meteredAccount, rec || {}); }
    catch (_e) { g = { allowed: true }; }
    if (g && g.allowed === false && g.over_limit) {
      return jsonRes(res, 402, {
        error: 'monthly_sign_quota_reached',
        message: 'Monthly ParaSign signing quota reached for this plan. Upgrade to continue. / Maandelijkse ParaSign-ondertekenlimiet voor dit plan bereikt; upgrade om door te gaan.',
      }, J, { 'Retry-After': '86400' });
    }
  }

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
// This is deliberately the ONE /v1 read that stays reachable to a scoped key
// that is neither owner nor participant: a lightweight progress oracle (per-
// party pending/signed, counts, timestamps). But it must NOT hand identifying
// or commercial data to a stranger, so it is authorization-AWARE:
//   * OWNER or PARTICIPANT (authorizeReceipt, same gate as /document) -> RICH
//     view: signer NAMES + the creator METADATA (quote_id & friends).
//   * anyone else -> REDACTED public view: names and metadata omitted entirely.
// Loads via getForReceipt for the durable creator_api_hash the owner check
// needs (getRedacted omits it). getRedacted itself is left untouched.
async function getEnvelope(deps, id, token, rec) {
  const { res, envStore, J } = deps;
  let env;
  try { env = await envStore.getForReceipt(id); } catch (e) { return errRes(res, 503, 'store_unavailable', e.message, J); }
  if (!env) return errRes(res, 404, 'not_found', 'Unknown envelope.', J);
  let authorized = false;
  try { authorized = await authorizeReceipt(deps, id, token, rec, env); }
  catch (_) { authorized = false; }
  const m = meta.get(id) || {};
  const ext = externalStatus(env);
  const nameFor = (i) => (m.signers && m.signers[i]) ? m.signers[i].name : (env.parties[i] && env.parties[i].label) || null;
  const body = {
    id: env.id,
    status: ext,
    signers: env.parties.map(p => ({
      index: p.index,
      // Names are identifying -> only for the owner/participant view.
      ...(authorized ? { name: nameFor(p.index) } : {}),
      status: p.status,
      signed_at: p.signed_at || undefined,
    })),
    signed_count: env.signed_count,
    signer_count: env.party_count,
    created_at: env.created_at,
    expires_at: env.expires_at,
    documents: null,
    // Creator metadata (quote_id & any free-form fields) is commercial -> only
    // exposed to the owner/participant. Absent from the public redacted view.
    ...(authorized ? { metadata: m.metadata || {} } : {}),
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
// SECURITY: this serves the actual signed PDF bytes, so it is gated exactly like
// the receipt -- the caller must be the envelope OWNER or a PARTICIPANT (valid
// invite token). An authenticated-but-unrelated key gets a generic 404 (no
// existence/state leak). Loads via getForReceipt because the ownership check
// needs the durable creator_api_hash (getRedacted intentionally omits it).
async function getDocument(deps, id, token, rec) {
  const { res, envStore, J } = deps;
  let env;
  try { env = await envStore.getForReceipt(id); } catch (e) { return errRes(res, 503, 'store_unavailable', e.message, J); }
  if (!env) return errRes(res, 404, 'not_found', 'Unknown envelope.', J);
  // Authorization runs BEFORE any state-dependent (409 not_ready) branch so a
  // valid stranger key cannot tell "not yours" from "does not exist" from "not
  // completed yet" -- all collapse to the same 404.
  let authorized = false;
  try { authorized = await authorizeReceipt(deps, id, token, rec, env); }
  catch (_) { authorized = false; }
  if (!authorized) return errRes(res, 404, 'not_found', 'Unknown envelope.', J);
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
// Returns the FULL multi-signer .psign for an authorized caller: the complete
// record MET the raw per-party ML-DSA-65 signatures (public_key + signature per
// party), notary-counter-signed exactly like the single-signer .psign that
// parasign.buildEnvelope produces (algorithm/document_hash/notary block +
// notary signature over the canonical JSON minus that signature field). A
// verifier can therefore (1) recompute each party's sign-message via
// envelope.signMessageBytes under `sign_recipe` and check every signer
// signature, and (2) check the notary counter-signature against the relay
// pubkey -- the same verify logic the direct sign-flow / /v2/verify use.
//
// SECURITY: gated on authorizeReceipt() -- the caller must be the envelope OWNER
// (durable creator_api_hash / same account) or a PARTICIPANT (valid invite
// token). An authenticated-but-unrelated key gets a generic 404 (no existence
// leak). getForReceipt exposes the raw signatures; getRedacted is untouched.
async function getReceipt(deps, id, token, rec) {
  const { res, envStore, canonicalJSON, sigEngine, relayIdentity, J } = deps;
  let env;
  try { env = await envStore.getForReceipt(id); } catch (e) { return errRes(res, 503, 'store_unavailable', e.message, J); }
  // Generic 404 for BOTH "unknown" and "not authorized" so a valid key from
  // another account/envelope cannot distinguish the two. Authorization runs
  // BEFORE any state-dependent (409 not_ready) branch so state does not leak.
  if (!env) return errRes(res, 404, 'not_found', 'Unknown envelope.', J);
  let authorized = false;
  try { authorized = await authorizeReceipt(deps, id, token, rec, env); }
  catch (_) { authorized = false; }
  if (!authorized) return errRes(res, 404, 'not_found', 'Unknown envelope.', J);

  if (env.status !== 'complete') return errRes(res, 409, 'not_ready', 'Envelope is not completed yet.', J);
  if (!sigEngine || !relayIdentity) return errRes(res, 503, 'notary_unavailable', 'Notary key not available.', J);

  const psign = {
    type: 'parasign-envelope-receipt',
    version: '2',
    algorithm: 'ML-DSA-65',
    envelope_id: env.id,
    document_hash: env.doc_hash,
    document_hash_algo: 'sha3-256',
    binding_mode: env.binding_mode,
    recipe_version: env.recipe_version,
    // The recipe each party signature was verified under (open -> v4). A verifier
    // recomputes each party message with envelope.signMessageBytes(...) at this
    // recipe. Included so the .psign is self-contained.
    sign_recipe: env.effective_recipe,
    status: 'completed',
    created_at: env.created_at,
    completed_at: env.completed_at,
    expires_at: env.expires_at,
    parties: env.parties.map(p => ({
      index: p.index,
      label: p.label,
      email_hash: p.email_hash || null,
      status: p.status,
      signed_at: p.signed_at,
      public_key: p.pk_b64 || null,   // raw ML-DSA-65 signer public key (base64)
      signature: p.sig_b64 || null,   // raw ML-DSA-65 per-party signature (base64)
      signer_pk_hash: p.signer_pk_hash,
    })),
    notary: {
      relay_pk_hash: relayIdentity.pk_hash,
      relay_pubkey_url: (deps.publicOrigin || 'https://paramant.app') + '/v2/pubkey',
    },
  };
  let notarySig;
  try { notarySig = Buffer.from(sigEngine.sign(Buffer.from(canonicalJSON(psign), 'utf8'), relayIdentity.sk)).toString('base64'); }
  catch (e) { return errRes(res, 500, 'notary_sign_failed', e.message, J); }
  psign.notary_signature = notarySig;

  const m = meta.get(id) || {};
  const base = (m.original_filename || env.original_filename || 'document').replace(/\.pdf$/i, '').replace(/"/g, '');
  res.writeHead(200, {
    'Content-Type': 'application/json',
    'Content-Disposition': `attachment; filename="${base}.psign"`,
    'X-ParaSign-Receipt-Kind': 'full-psign',
  });
  return res.end(J(psign));
}

// ── POST /v1/envelopes/:id/void ───────────────────────────────────────────────
// SECURITY: voiding tears down the WHOLE envelope, so it is OWNER-ONLY -- a
// participant proving membership with an invite token must NOT be able to
// retract everyone's envelope. Hence isEnvelopeOwner (paths a+b) and NOT the
// owner-OR-participant authorizeReceipt. An unrelated key -- or a mere
// participant -- gets a generic 404. Authorization runs BEFORE the store's
// state-dependent branches (e.g. the already_complete 409) so a stranger cannot
// probe an envelope's state. Loads via getForReceipt for the durable
// creator_api_hash (getRedacted omits it).
async function voidEnvelope(deps, id, token, rec) {
  const { res, envStore, readBody, J } = deps;
  let env;
  try { env = await envStore.getForReceipt(id); } catch (e) { return errRes(res, 503, 'store_unavailable', e.message, J); }
  if (!env) return errRes(res, 404, 'not_found', 'Unknown envelope.', J);
  if (!isEnvelopeOwner(deps, id, token, rec, env)) return errRes(res, 404, 'not_found', 'Unknown envelope.', J);
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
  authorizeReceipt, hexEqual,   // exposed for tests
  _blobs: blobs, _meta: meta,   // exposed for tests / diagnostics
};
