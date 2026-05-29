// Multi-party envelope state machine (R-?) for ParaSign Model 2.
//
// The relay never sees the document. The creator's client computes
// SHA3-256 over the original PDF and POSTs the hash + party list. Each
// party gets a co-sign URL, fetches the envelope, signs (ML-DSA-65) over
// (sha3_256(doc_hash || envelope.id || party_index)), and POSTs the
// signature back. The relay verifies, stores it atomically, and emits a
// CT-log entry. When the last party signs, status flips to 'complete'.
//
// Storage: Redis hash per envelope. All mutations are atomic via either
// HSETNX (idempotency) or a Lua script (sign + completion check).
//
// Zero-knowledge invariants enforced here:
//   * the relay only stores hex doc_hash, never document bytes
//   * recipient signatures are verified server-side, but the relay never
//     learns the private key (only the signature + public key)
//   * unknown envelope IDs return a generic 404 (no leak distinguishing
//     'does not exist' from 'exists but you are not a party')

'use strict';

const crypto = require('crypto');

const ID_BYTES = 24;             // 24 random bytes -> 32-char base64url
const MAX_PARTIES = 20;          // sanity cap; CT-log/Redis can handle more
const MAX_LABEL_LEN = 80;
const DEFAULT_TTL_DAYS = 30;
const MAX_TTL_DAYS = 365;
// Domain-separation label for ParaSign document signatures (recipe v3, R018 /
// pentest H3). MUST stay byte-identical across relay + SDK + core.
const SIGN_DOMAIN_DOC = 'paramant/parasign/doc/v1';

function newEnvelopeId() {
  return crypto.randomBytes(ID_BYTES).toString('base64url');
}

// Canonical party-email hash. Namespaced + case-normalized so the value is
// computed identically at envelope creation (here), at the admin-side binding
// check, and at the client when it recomputes the v2 sign-message. Being
// unsalted over a low-entropy email space is an accepted/documented privacy
// property -- see ADR R018.
function partyEmailHash(email) {
  const norm = (email || '').toString().trim().toLowerCase();
  if (!norm) return '';
  return crypto.createHash('sha3-256')
    .update('paramant/party-email/v1\x00', 'utf8')
    .update(norm, 'utf8')
    .digest('hex');
}

// Constant-time compare of two equal-length hex strings (e.g. email hashes).
// Returns false for empty / mismatched-length / non-string inputs.
function safeHexEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  if (a.length === 0 || a.length !== b.length) return false;
  try { return crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex')); }
  catch { return false; }
}

// Constant-time compare for an invite token against its stored value.
function safeTokenEqual(stored, provided) {
  if (!stored || typeof provided !== 'string' || provided.length === 0) return false;
  const a = Buffer.from(stored);
  const b = Buffer.from(provided);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// Sign-message construction. Public so the recipient client can recompute
// the same bytes locally before calling ml_dsa65.sign().
//
//   recipeVersion 1 (default; legacy / open envelopes):
//     sha3_256(id || doc_hash || party_index)
//   recipeVersion 2 (email-bound envelopes):
//     sha3_256(id || doc_hash || party_index || party_email_hash_bytes)
//
// v2 makes the signature itself commit to "party i, whose invited email hashes
// to H". v1 stays valid for already-deployed and open envelopes; the relay
// picks the recipe from the envelope's stored recipe_version. This only defines
// the MESSAGE -- it is orthogonal to how the message is signed, so the
// activation<->key-use seam (R018) is unaffected.
//   recipeVersion 3 (per-document PRF activation, R018): a domain-separation
//     label is PREPENDED so a ParaSign document signature can never be replayed
//     as any other signed message (pentest H3). The label is byte-identical
//     across relay + SDK + core; the NUL terminator delimits it from the id.
//       sha3_256("paramant/parasign/doc/v1" || 0x00 || id || doc || pi || email_hash)
function signMessageBytes(envelopeId, docHashHex, partyIndex, partyEmailHashHex, recipeVersion) {
  const v = Number(recipeVersion) || 1;
  const h = crypto.createHash('sha3-256');
  if (v >= 3) {
    h.update(Buffer.from(SIGN_DOMAIN_DOC, 'utf8')).update(Buffer.from([0]));
  }
  h.update(Buffer.from(envelopeId, 'utf8'))
   .update(Buffer.from(docHashHex, 'hex'))
   .update(Buffer.from(String(partyIndex), 'utf8'));
  if (v >= 2) {
    // Decoded email-hash bytes: 32 bytes when present, 0 bytes when the party
    // has no email -- deterministic either way.
    h.update(Buffer.from(partyEmailHashHex || '', 'hex'));
  }
  return h.digest();
}

// Lua script: idempotent party-sign + completion transition.
// KEYS[1] = redis hash key (env:<id>)
// ARGV[1] = party index (string)
// ARGV[2] = signature b64 + ':' + pubkey b64 (composite to keep field count low)
// ARGV[3] = ISO timestamp
// Returns: { newOrIdem ('new'|'idem'|'conflict'), signedCount, partyCount, status }
const SIGN_LUA = `
local key = KEYS[1]
local pi = ARGV[1]
local sigComposite = ARGV[2]
local at = ARGV[3]
local sigField = 'p' .. pi .. '_sig'
local atField  = 'p' .. pi .. '_signed_at'
local existing = redis.call('HGET', key, sigField)
local partyCount = tonumber(redis.call('HGET', key, 'party_count')) or 0
local signedCount = tonumber(redis.call('HGET', key, 'signed_count')) or 0
local status = redis.call('HGET', key, 'status') or ''
if existing then
  if existing == sigComposite then
    return {'idem', tostring(signedCount), tostring(partyCount), status}
  end
  return {'conflict', tostring(signedCount), tostring(partyCount), status}
end
redis.call('HSET', key, sigField, sigComposite)
redis.call('HSET', key, atField,  at)
signedCount = redis.call('HINCRBY', key, 'signed_count', 1)
if signedCount >= partyCount then
  redis.call('HSET', key, 'status', 'complete')
  redis.call('HSET', key, 'completed_at', at)
  status = 'complete'
end
return {'new', tostring(signedCount), tostring(partyCount), status}
`;

class EnvelopeStore {
  constructor(redisClient, { ctAppend, sigVerify } = {}) {
    this.redis = redisClient;
    this.ctAppend = ctAppend || (() => null);    // (kind, envelope_id, payload) -> ct entry
    this.sigVerify = sigVerify || (() => false); // (sig, msg, pub) -> bool
    this._signScriptSha = null;
  }

  available() {
    return !!(this.redis && this.redis.isReady);
  }

  async _loadScript() {
    if (this._signScriptSha) return this._signScriptSha;
    if (!this.available()) throw new Error('redis unavailable');
    this._signScriptSha = await this.redis.scriptLoad(SIGN_LUA);
    return this._signScriptSha;
  }

  async create({ creatorPkHash, creatorApiKeyHash, docHash, parties, originalFilename, expiresInDays, bindingMode, recipeVersion: recipeVersionArg }) {
    if (!this.available()) throw new Error('redis unavailable');
    if (!/^[0-9a-f]{64}$/.test(docHash)) throw new Error('doc_hash must be 64-char sha3-256 hex');
    if (!Array.isArray(parties) || parties.length === 0) throw new Error('parties required');
    if (parties.length > MAX_PARTIES) throw new Error('too many parties (max ' + MAX_PARTIES + ')');
    const ttlDays = Math.max(1, Math.min(MAX_TTL_DAYS,
      Number.isFinite(expiresInDays) ? expiresInDays : DEFAULT_TTL_DAYS));
    const now = new Date();
    const expires = new Date(now.getTime() + ttlDays * 86400_000);

    // Generate a unique id, retrying once on the astronomically unlikely
    // collision with an existing envelope.
    let id, key, ok = false;
    for (let attempt = 0; attempt < 3 && !ok; attempt++) {
      id = newEnvelopeId();
      key = 'env:' + id;
      const created = await this.redis.hSetNX(key, 'doc_hash', docHash);
      if (created) ok = true;
    }
    if (!ok) throw new Error('could not allocate envelope id');

    // 'email' = each party slot is bound to its invited email and may only be
    // signed via the trusted admin proxy (verified_email_hash + X-Internal-Auth);
    // 'open' = the legacy public flow (any holder of env_id+party_index signs).
    const mode = bindingMode === 'email' ? 'email' : 'open';
    // Explicit recipeVersion (1-3) wins; else default by binding mode. The
    // per-document PRF activation flow (R018) creates v3 (domain-prefixed)
    // envelopes; open=1, email=2 stay the defaults for existing flows.
    const recipeVersion = (Number.isInteger(recipeVersionArg) && recipeVersionArg >= 1 && recipeVersionArg <= 3)
      ? recipeVersionArg
      : (mode === 'email' ? 2 : 1);

    const hash = {
      id,
      status: 'sent',
      doc_hash: docHash,
      binding_mode: mode,
      recipe_version: String(recipeVersion),
      creator_pk_hash: creatorPkHash || '',
      creator_api_hash: creatorApiKeyHash || '',
      original_filename: (originalFilename || '').toString().slice(0, 200),
      party_count: String(parties.length),
      signed_count: '0',
      created_at: now.toISOString(),
      expires_at: expires.toISOString(),
    };
    // Per-party capability token: the secret embedded in the invite link.
    // Stored server-side, returned to the creator ONCE below so it can build
    // the invite emails, and NEVER exposed via getRedacted/getForParty output.
    const inviteTokens = [];
    for (let i = 0; i < parties.length; i++) {
      const p = parties[i] || {};
      hash['p' + i + '_label'] = (p.label || '').toString().slice(0, MAX_LABEL_LEN);
      // We store the canonical party-email hash only, never the email itself -
      // the creator (or admin) keeps the address and emails the invite link.
      hash['p' + i + '_email_hash'] = partyEmailHash(p.email);
      hash['p' + i + '_status'] = 'pending';
      const token = crypto.randomBytes(32).toString('base64url');
      hash['p' + i + '_invite_token'] = token;
      inviteTokens.push(token);
    }
    await this.redis.hSet(key, hash);
    await this.redis.expire(key, ttlDays * 86400);

    try { this.ctAppend('envelope_create', id, { doc_hash: docHash, party_count: parties.length, binding_mode: mode }); } catch {}

    return {
      id,
      created_at: hash.created_at,
      expires_at: hash.expires_at,
      binding_mode: mode,
      recipe_version: recipeVersion,
      party_count: parties.length,
      // For 'email' envelopes the invite token is part of the link and is also
      // returned raw so the caller can email it. For 'open' envelopes the link
      // is the legacy token-free path (byte-identical to before).
      party_links: parties.map((_, i) => ({
        party_index: i,
        sign_path: '/co-sign?env=' + id + '&p=' + i + (mode === 'email' ? '&t=' + inviteTokens[i] : ''),
        invite_token: mode === 'email' ? inviteTokens[i] : null,
      })),
    };
  }

  // Public view. Redacted: party labels are shown but email hashes are
  // omitted, and signatures are returned only as length / pk-hash.
  async getRedacted(id) {
    if (!this.available()) throw new Error('redis unavailable');
    const key = 'env:' + id;
    const h = await this.redis.hGetAll(key);
    if (!h || !h.doc_hash) return null;
    const partyCount = parseInt(h.party_count, 10) || 0;
    const parties = [];
    for (let i = 0; i < partyCount; i++) {
      const sig = h['p' + i + '_sig'] || '';
      parties.push({
        index: i,
        label: h['p' + i + '_label'] || null,
        status: sig ? 'signed' : (h['p' + i + '_status'] || 'pending'),
        signed_at: h['p' + i + '_signed_at'] || null,
        signer_pk_hash: sig ? crypto.createHash('sha3-256').update(Buffer.from(sig.split(':')[1] || '', 'base64')).digest('hex') : null,
      });
    }
    return {
      id: h.id,
      status: h.status,
      doc_hash: h.doc_hash,
      binding_mode: h.binding_mode || 'open',
      recipe_version: parseInt(h.recipe_version, 10) || 1,
      original_filename: h.original_filename || null,
      created_at: h.created_at,
      expires_at: h.expires_at,
      completed_at: h.completed_at || null,
      party_count: partyCount,
      signed_count: parseInt(h.signed_count, 10) || 0,
      parties,
    };
  }

  // Constant-time check of a per-party invite token against the stored value.
  async checkInviteToken(id, partyIndex, token) {
    if (!this.available()) throw new Error('redis unavailable');
    const stored = await this.redis.hGet('env:' + id, 'p' + parseInt(partyIndex, 10) + '_invite_token');
    return safeTokenEqual(stored, token);
  }

  // Party-scoped view for the co-signer: exactly what the client needs to
  // recompute the sign-message (doc_hash, recipe_version, this party's
  // email_hash) plus presentation fields. For email-bound envelopes the
  // per-party invite token MUST match, else this returns null (a generic miss,
  // so a wrong/absent token is indistinguishable from a non-existent envelope).
  // For open envelopes the token is not required -- the slot is public by design.
  async getForParty(id, partyIndex, token) {
    if (!this.available()) throw new Error('redis unavailable');
    const h = await this.redis.hGetAll('env:' + id);
    if (!h || !h.doc_hash) return null;
    const partyCount = parseInt(h.party_count, 10) || 0;
    const pi = parseInt(partyIndex, 10);
    if (!Number.isInteger(pi) || pi < 0 || pi >= partyCount) return null;
    const mode = h.binding_mode || 'open';
    if (mode === 'email' && !safeTokenEqual(h['p' + pi + '_invite_token'], token)) return null;
    const sig = h['p' + pi + '_sig'] || '';
    return {
      id: h.id,
      doc_hash: h.doc_hash,
      original_filename: h.original_filename || null,
      status: h.status,
      binding_mode: mode,
      recipe_version: parseInt(h.recipe_version, 10) || 1,
      expires_at: h.expires_at,
      party: {
        index: pi,
        label: h['p' + pi + '_label'] || null,
        email_hash: h['p' + pi + '_email_hash'] || '',
        status: sig ? 'signed' : (h['p' + pi + '_status'] || 'pending'),
        signed_at: h['p' + pi + '_signed_at'] || null,
      },
    };
  }

  async markViewed(id, partyIndex) {
    if (!this.available()) throw new Error('redis unavailable');
    const key = 'env:' + id;
    // HSETNX-equivalent for the viewed_at field: only update if not signed yet.
    const status = await this.redis.hGet(key, 'p' + partyIndex + '_status');
    if (status === undefined || status === null) return false;     // out-of-range
    const sig = await this.redis.hGet(key, 'p' + partyIndex + '_sig');
    if (sig) return true;        // already signed, treat view as no-op
    // Idempotent: HSETNX viewed_at; if already viewed, do nothing.
    const firstView = await this.redis.hSetNX(key, 'p' + partyIndex + '_viewed_at', new Date().toISOString());
    if (firstView) {
      await this.redis.hSet(key, 'p' + partyIndex + '_status', 'viewed');
      try { this.ctAppend('envelope_view', id, { party_index: partyIndex }); } catch {}
    }
    return true;
  }

  // Sign a party slot. Idempotent: re-submitting the same (sig, pubkey)
  // returns 'idem'. Submitting a different one with the slot already
  // signed returns 'conflict' and is rejected.
  async sign(id, partyIndex, signerPubB64, signatureB64, opts = {}) {
    if (!this.available()) throw new Error('redis unavailable');
    const key = 'env:' + id;
    const h = await this.redis.hGetAll(key);
    if (!h || !h.doc_hash) return { ok: false, code: 'not_found' };
    const partyCount = parseInt(h.party_count, 10) || 0;
    const pi = parseInt(partyIndex, 10);
    if (!Number.isInteger(pi) || pi < 0 || pi >= partyCount) return { ok: false, code: 'not_found' };
    if (h.status === 'complete') return { ok: false, code: 'closed' };

    const mode = h.binding_mode || 'open';
    const emailHash = h['p' + pi + '_email_hash'] || '';
    // Email-bound envelopes (R018): accept the signature ONLY when a trusted
    // internal caller (the admin proxy, which already checked the signer's
    // authenticated session email) asserts a verified_email_hash equal to this
    // party's bound hash. Anonymous/public callers cannot set internalTrusted,
    // so they can never fill an email-bound slot. Fail-closed: a party with no
    // bound email (empty hash) cannot be signed in email mode.
    if (mode === 'email') {
      if (!opts.internalTrusted) return { ok: false, code: 'email_binding_required' };
      if (!safeHexEqual(opts.verifiedEmailHash, emailHash)) return { ok: false, code: 'email_mismatch' };
    }

    // Verify the signature server-side. The relay only sees doc_hash, id,
    // party_index (and, for v2, the party's email hash) - so the recipient
    // signs over their hash, not the document. This binds the signature to
    // this envelope slot. The recipe is chosen by the stored recipe_version.
    const recipeVersion = parseInt(h.recipe_version, 10) || 1;
    const msg = signMessageBytes(id, h.doc_hash, pi, emailHash, recipeVersion);
    let verified = false;
    try {
      verified = !!this.sigVerify(Buffer.from(signatureB64, 'base64'), msg, Buffer.from(signerPubB64, 'base64'));
    } catch { verified = false; }
    if (!verified) return { ok: false, code: 'bad_signature' };

    const composite = signatureB64 + ':' + signerPubB64;
    const at = new Date().toISOString();
    await this._loadScript();
    const result = await this.redis.evalSha(this._signScriptSha, {
      keys: [key],
      arguments: [String(pi), composite, at],
    });
    const [outcome, signedCountStr, partyCountStr, status] = result;
    if (outcome === 'conflict') return { ok: false, code: 'conflict' };
    const out = {
      ok: true,
      code: outcome,             // 'new' | 'idem'
      signed_count: parseInt(signedCountStr, 10),
      party_count: parseInt(partyCountStr, 10),
      status,
    };
    if (outcome === 'new') {
      try {
        this.ctAppend('envelope_sign', id, {
          party_index: pi,
          signer_pk_hash: crypto.createHash('sha3-256').update(Buffer.from(signerPubB64, 'base64')).digest('hex'),
        });
        if (status === 'complete') this.ctAppend('envelope_complete', id, { signed_count: out.signed_count });
      } catch {}
    }
    return out;
  }
}

module.exports = { EnvelopeStore, signMessageBytes, partyEmailHash, safeHexEqual, newEnvelopeId, SIGN_DOMAIN_DOC, MAX_PARTIES, DEFAULT_TTL_DAYS, MAX_TTL_DAYS };
