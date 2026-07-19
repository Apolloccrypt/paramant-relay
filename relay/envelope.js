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
// Signing-invite window for EMAIL-bound envelopes (R018): how long an invite
// link can actually be USED to sign, deliberately shorter than and independent
// of the 30-day envelope record retention (DEFAULT_TTL_DAYS). Measured from the
// envelope's created_at (= when the sender created it and sent the invites).
// The record is still kept 30d for verification; only the signable window is 7d.
const SIGN_INVITE_TTL_DAYS = 7;
// Domain-separation label for ParaSign document signatures (recipe v3, R018 /
// pentest H3). MUST stay byte-identical across relay + SDK + core.
const SIGN_DOMAIN_DOC = 'paramant/parasign/doc/v1';

// True when an email-bound invite's signing window (created_at + 7d) has closed.
// Open/legacy envelopes have no invite window (only the 30d hash TTL), so callers
// apply this in email mode only. Missing/unparseable created_at -> not closed
// (real envelopes always store it; the 30d hash TTL remains the backstop).
function signInviteClosed(createdAtIso, nowMs) {
  const t = Date.parse(createdAtIso || '');
  if (!Number.isFinite(t)) return false;
  return (nowMs - t) > SIGN_INVITE_TTL_DAYS * 86400_000;
}
// ISO timestamp when an email-bound invite stops being signable, or null.
function signInviteExpiresAt(createdAtIso) {
  const t = Date.parse(createdAtIso || '');
  if (!Number.isFinite(t)) return null;
  return new Date(t + SIGN_INVITE_TTL_DAYS * 86400_000).toISOString();
}

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
//   recipeVersion 4 (open-mode signer binding): like v3 but the SIGNER's public
//     key is APPENDED, so the signature commits to "key K signed slot i of doc D".
//     Open envelopes have no email/invite-token gate, so without this any caller
//     who knew the envelope id could fill any party slot with a substituted key.
//     Binding the pubkey turns each open-slot signature into a genuine, non-
//     forgeable commitment to the exact key that produced it.
//       sha3_256("paramant/parasign/doc/v1" || 0x00 || id || doc || pi || email_hash || signer_pub)
function signMessageBytes(envelopeId, docHashHex, partyIndex, partyEmailHashHex, recipeVersion, signerPubB64) {
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
  if (v >= 4) {
    // Signer public-key bytes bind the signature to the exact key. base64 in,
    // raw bytes mixed in (deterministic; empty -> 0 bytes, but sign() rejects
    // an empty signer key before reaching here).
    h.update(Buffer.from(signerPubB64 || '', 'base64'));
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
local partyCount = tonumber(redis.call('HGET', key, 'party_count')) or 0
local signedCount = tonumber(redis.call('HGET', key, 'signed_count')) or 0
local status = redis.call('HGET', key, 'status') or ''
-- Atomic terminal-state guard. A completed OR voided envelope is immutable and
-- cannot take a signature. This is the AUTHORITATIVE check: the sign() wrapper's
-- pre-read is only a fast path, so keeping the guard inside the script closes the
-- void<->complete race (a concurrent void can no longer be overwritten by a sign
-- that read the old status, and a signer can no longer complete a voided envelope).
if status == 'complete' then
  return {'closed', tostring(signedCount), tostring(partyCount), status}
end
if status == 'void' then
  return {'voided', tostring(signedCount), tostring(partyCount), status}
end
local existing = redis.call('HGET', key, sigField)
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

// Lua script: atomic void transition. Flips a still-open envelope to 'void'.
// Runs on the same key as SIGN_LUA, so the two can never interleave: a void and
// a completing sign are serialised by redis, preserving the "complete is
// immutable" invariant in BOTH directions.
//   KEYS[1] = redis hash key (env:<id>)
//   ARGV[1] = ISO timestamp   ARGV[2] = void reason (already truncated)
//   Returns: { code ('not_found'|'already_complete'|'idem'|'void'), voided_at }
const VOID_LUA = `
local key = KEYS[1]
local at = ARGV[1]
local reason = ARGV[2]
local dh = redis.call('HGET', key, 'doc_hash')
if not dh then return {'not_found', ''} end
local status = redis.call('HGET', key, 'status') or ''
if status == 'complete' then return {'already_complete', ''} end
if status == 'void' then
  return {'idem', redis.call('HGET', key, 'voided_at') or ''}
end
redis.call('HSET', key, 'status', 'void')
redis.call('HSET', key, 'voided_at', at)
redis.call('HSET', key, 'void_reason', reason)
return {'void', at}
`;

class EnvelopeStore {
  constructor(redisClient, { ctAppend, sigVerify } = {}) {
    this.redis = redisClient;
    this.ctAppend = ctAppend || (() => null);    // (kind, envelope_id, payload) -> ct entry
    this.sigVerify = sigVerify || (() => false); // (sig, msg, pub) -> bool
    this._signScriptSha = null;
    this._voidScriptSha = null;
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

  async _loadVoidScript() {
    if (this._voidScriptSha) return this._voidScriptSha;
    if (!this.available()) throw new Error('redis unavailable');
    this._voidScriptSha = await this.redis.scriptLoad(VOID_LUA);
    return this._voidScriptSha;
  }

  // Redis key for an account's envelope index (sorted set: member = envelope id,
  // score = created_at ms). One set per account, so a Business account with many
  // api-keys sees every envelope it created. Persistent (no TTL) so it survives
  // restart via AOF and outlives the per-envelope record's own TTL -- the export
  // can then still label an expired envelope instead of silently dropping it.
  _acctIndexKey(accountId) { return 'parasign:acct:' + accountId + ':envelopes'; }

  async create({ creatorPkHash, creatorApiKeyHash, accountId, docHash, parties, originalFilename, expiresInDays, bindingMode, recipeVersion: recipeVersionArg }) {
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
      // The creating account. Written for provenance + so a later re-backfill can
      // resolve the account directly from the record, without a key reverse-map.
      account_id: (accountId || '').toString().slice(0, 200),
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

    // Per-account envelope index. Best-effort: a redis hiccup here must not fail
    // an otherwise-created envelope, and backfillAccountIndex() repairs a miss.
    if (accountId) {
      try { await this.redis.zAdd(this._acctIndexKey(accountId), { score: now.getTime(), value: id }); }
      catch { /* index miss -> recoverable via backfill */ }
    }

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
      voided_at: h.voided_at || null,
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

  // Participant-membership check for the authorized receipt channel: does `token`
  // match ANY party's per-party invite token on this envelope? A signer holds
  // this secret (it is embedded in their signing link), so a valid match proves
  // they are a participant of THIS envelope without needing to know their slot
  // index. Constant-time per comparison and it scans every slot (no early
  // return) so the matching position is not timing-distinguishable. Returns the
  // matching party index, or -1 (open envelopes carry no tokens -> always -1).
  async isParticipantToken(id, token) {
    if (!this.available()) throw new Error('redis unavailable');
    if (typeof token !== 'string' || token.length === 0) return -1;
    const h = await this.redis.hGetAll('env:' + id);
    if (!h || !h.doc_hash) return -1;
    const partyCount = parseInt(h.party_count, 10) || 0;
    let found = -1;
    for (let i = 0; i < partyCount; i++) {
      if (safeTokenEqual(h['p' + i + '_invite_token'], token) && found === -1) found = i;
    }
    return found;
  }

  // Authorized full view for the receipt/.psign channel. UNLIKE getRedacted this
  // deliberately EXPOSES the raw per-party ML-DSA-65 signatures (sig_b64 +
  // pk_b64) needed to assemble the complete, independently-verifiable multi-
  // signer .psign, plus the creator fingerprints (creator_api_hash /
  // creator_pk_hash) the caller uses to authorize the request. This method does
  // NO authorization of its own -- it MUST only be reached after the /v1/receipt
  // handler has confirmed the caller owns (creator_api_hash) or participates in
  // (valid invite token) this envelope. getRedacted stays the public, redacted
  // view and is intentionally left untouched.
  async getForReceipt(id) {
    if (!this.available()) throw new Error('redis unavailable');
    const key = 'env:' + id;
    const h = await this.redis.hGetAll(key);
    if (!h || !h.doc_hash) return null;
    const partyCount = parseInt(h.party_count, 10) || 0;
    const mode = h.binding_mode || 'open';
    const storedRecipe = parseInt(h.recipe_version, 10) || 1;
    // The recipe each slot was actually VERIFIED under in sign(): open slots are
    // upgraded to v4 (signer-pubkey-bound); email/PRF keep their stored recipe.
    // A verifier MUST recompute each party message under this same recipe.
    const effectiveRecipe = (mode === 'open') ? 4 : storedRecipe;
    const parties = [];
    for (let i = 0; i < partyCount; i++) {
      // Stored composite is 'sig_b64:pk_b64' (see the SIGN_LUA field p<i>_sig).
      // Split on the FIRST ':' only -- base64 never contains ':' so this is exact.
      const composite = h['p' + i + '_sig'] || '';
      const ci = composite.indexOf(':');
      const sigB64 = ci >= 0 ? composite.slice(0, ci) : '';
      const pkB64  = ci >= 0 ? composite.slice(ci + 1) : '';
      parties.push({
        index: i,
        label: h['p' + i + '_label'] || null,
        email_hash: h['p' + i + '_email_hash'] || '',
        status: composite ? 'signed' : (h['p' + i + '_status'] || 'pending'),
        signed_at: h['p' + i + '_signed_at'] || null,
        sig_b64: sigB64,
        pk_b64: pkB64,
        signer_pk_hash: pkB64
          ? crypto.createHash('sha3-256').update(Buffer.from(pkB64, 'base64')).digest('hex')
          : null,
      });
    }
    return {
      id: h.id,
      status: h.status,
      doc_hash: h.doc_hash,
      binding_mode: mode,
      recipe_version: storedRecipe,
      effective_recipe: effectiveRecipe,
      original_filename: h.original_filename || null,
      created_at: h.created_at,
      expires_at: h.expires_at,
      completed_at: h.completed_at || null,
      voided_at: h.voided_at || null,
      party_count: partyCount,
      signed_count: parseInt(h.signed_count, 10) || 0,
      // Durable creator fingerprints for the handler's ownership gate.
      creator_pk_hash: h.creator_pk_hash || '',
      creator_api_hash: h.creator_api_hash || '',
      parties,
    };
  }

  // Newest-first list of the envelope ids an account created, read from the
  // per-account index (sorted set, highest score = most recent). `limit` caps the
  // return. Used by the Business+ audit-export to enumerate an account's
  // envelopes across all its keys. An account with no index yet -> [].
  async listAccountEnvelopeIds(accountId, { limit = 1000, prune = true } = {}) {
    if (!this.available()) throw new Error('redis unavailable');
    if (!accountId) return [];
    const n = Math.max(1, Math.min((limit | 0) || 1000, 100000));
    const ids = await this.redis.zRange(this._acctIndexKey(accountId), 0, n - 1, { REV: true });
    if (!Array.isArray(ids) || ids.length === 0) return [];
    if (!prune) return ids;
    // Lazy prune: the index is append-only at create() time, so an entry whose
    // envelope hash has since expired past its TTL would linger in the sorted set
    // forever (unbounded growth). Drop those on read. Fail-open on a redis hiccup:
    // treat an errored EXISTS as present so a transient fault never hides an id.
    const present = await Promise.all(ids.map((id) =>
      this.redis.exists('env:' + id).then((c) => c > 0).catch(() => true)));
    const gone = ids.filter((_, i) => !present[i]);
    if (gone.length) {
      try { await this.redis.zRem(this._acctIndexKey(accountId), gone); } catch { /* best effort */ }
    }
    return ids.filter((_, i) => present[i]);
  }

  // One-shot backfill of the per-account envelope index from existing env:* keys.
  // The index is only written at create() time, so envelopes made BEFORE it
  // existed are absent -- this SCANs every envelope hash and (re)builds the index.
  // Account resolution per envelope: the account_id field written into the record
  // (new envelopes), else the injected resolveAccount(h) reverse-map (typically
  // creator_api_hash -> account_id from users.json). An envelope whose account
  // cannot be resolved is counted (unresolved) and skipped. Idempotent: re-adding
  // an id only refreshes its score. Returns { scanned, indexed, unresolved }.
  async backfillAccountIndex({ resolveAccount, dryRun = false, log } = {}) {
    if (!this.available()) throw new Error('redis unavailable');
    let cursor = '0';                                    // redis v5 wants a string cursor
    let scanned = 0, indexed = 0, unresolved = 0;
    do {
      const reply = await this.redis.scan(cursor, { MATCH: 'env:*', COUNT: 200 });
      cursor = String(reply.cursor);
      for (const key of (reply.keys || [])) {
        const h = await this.redis.hGetAll(key);
        if (!h || !h.doc_hash) continue;                 // not an envelope hash
        scanned++;
        let acct = h.account_id || '';
        if (!acct && typeof resolveAccount === 'function') {
          try { acct = resolveAccount(h) || ''; } catch { acct = ''; }
        }
        if (!acct) { unresolved++; continue; }
        const id = h.id || key.slice('env:'.length);
        const score = Date.parse(h.created_at || '') || 0;
        if (dryRun) { indexed++; continue; }
        try { await this.redis.zAdd(this._acctIndexKey(acct), { score, value: id }); indexed++; }
        catch (e) { if (typeof log === 'function') log('warn', 'backfill_zadd_fail', { id, err: e.message }); }
      }
    } while (String(cursor) !== '0');
    return { scanned, indexed, unresolved };
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
      // When this email-bound invite stops being signable (created_at + 7d);
      // null for open envelopes. Lets the admin gate fail early before the PRF.
      sign_expires_at: mode === 'email' ? signInviteExpiresAt(h.created_at) : null,
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

  // Void an envelope (ParaSign Open-API /v1). Initiator action: flips a still-open
  // envelope to status 'void'. A 'complete' envelope is immutable and cannot be
  // voided. Idempotent: voiding an already-void envelope returns the prior time.
  // (New /v1 transition; the base state machine only had 'sent' -> 'complete'.)
  async voidEnvelope(id, reason) {
    if (!this.available()) throw new Error('redis unavailable');
    const key = 'env:' + id;
    const at = new Date().toISOString();
    const safeReason = (reason || '').toString().slice(0, 200);
    // Atomic read-modify-write via VOID_LUA: the terminal-state check and the
    // status flip happen in one redis-serialised step, so a sign() completing
    // concurrently cannot be silently overwritten to 'void' (and vice-versa).
    // The plaintext reason lands ONLY in the access-controlled, TTL'd envelope
    // record (void_reason is set inside the script). The append-only CT-log is
    // permanent and public-shaped, so it gets a domain-separated HASH of the
    // reason plus its length -- never the words themselves.
    await this._loadVoidScript();
    const [code, voidedAt] = await this.redis.evalSha(this._voidScriptSha, {
      keys: [key],
      arguments: [at, safeReason],
    });
    if (code === 'not_found') return { ok: false, code: 'not_found' };
    if (code === 'already_complete') return { ok: false, code: 'already_complete' };
    if (code === 'idem') return { ok: true, code: 'idem', status: 'void', voided_at: voidedAt || null };
    try {
      this.ctAppend('envelope_void', id, safeReason
        ? {
            reason_hash: crypto.createHash('sha3-256')
              .update('paramant/void-reason/v1\x00', 'utf8').update(safeReason, 'utf8').digest('hex'),
            reason_len: safeReason.length,
          }
        : { reason_len: 0 });
    } catch {}
    return { ok: true, code: 'void', status: 'void', voided_at: voidedAt };
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
    // Fast-path terminal-state rejection (authoritative guard is in SIGN_LUA).
    if (h.status === 'complete') return { ok: false, code: 'closed' };
    if (h.status === 'void') return { ok: false, code: 'voided' };

    const mode = h.binding_mode || 'open';
    const emailHash = h['p' + pi + '_email_hash'] || '';
    // Email-bound envelopes (R018): accept the signature ONLY when a trusted
    // internal caller (the admin proxy, which already checked the signer's
    // authenticated session email) asserts a verified_email_hash equal to this
    // party's bound hash. Anonymous/public callers cannot set internalTrusted,
    // so they can never fill an email-bound slot. Fail-closed: a party with no
    // bound email (empty hash) cannot be signed in email mode.
    if (mode === 'email') {
      // Signing-invite window: an email-bound invite is signable for 7 days from
      // creation, independent of the 30-day record retention. Past that, the
      // slot is closed even though the envelope record still exists.
      if (signInviteClosed(h.created_at, Date.now())) return { ok: false, code: 'invite_expired' };
      if (!opts.internalTrusted) return { ok: false, code: 'email_binding_required' };
      if (!safeHexEqual(opts.verifiedEmailHash, emailHash)) return { ok: false, code: 'email_mismatch' };
    }

    // Verify the signature server-side. The relay only sees doc_hash, id,
    // party_index (and, for v2, the party's email hash) - so the recipient
    // signs over their hash, not the document. This binds the signature to
    // this envelope slot. The recipe is chosen by the stored recipe_version.
    //
    // Open-mode slots have NO email/invite-token gate, so a bare id+party_index
    // message would let any caller who knew the id fill any slot with a
    // substituted key. For open mode we therefore upgrade to recipe v4, which
    // APPENDS the signer's public key: the signature now commits to the exact
    // key that produced it. (email/v2 and PRF/v3 keep their stored recipe — the
    // email_hash / internal-proxy path already binds the signer there.) A v4
    // message mixes the pubkey bytes, so reject an empty signer key up front.
    const storedRecipe = parseInt(h.recipe_version, 10) || 1;
    const effectiveRecipe = (mode === 'open') ? 4 : storedRecipe;
    if (effectiveRecipe >= 4 && !signerPubB64) return { ok: false, code: 'bad_signature' };
    const msg = signMessageBytes(id, h.doc_hash, pi, emailHash, effectiveRecipe, signerPubB64);
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
    // Envelope reached a terminal state between the pre-read and the script.
    if (outcome === 'closed') return { ok: false, code: 'closed' };
    if (outcome === 'voided') return { ok: false, code: 'voided' };
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

module.exports = { EnvelopeStore, signMessageBytes, partyEmailHash, safeHexEqual, newEnvelopeId, SIGN_DOMAIN_DOC, MAX_PARTIES, DEFAULT_TTL_DAYS, MAX_TTL_DAYS, SIGN_INVITE_TTL_DAYS };
