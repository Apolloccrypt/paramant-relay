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

function newEnvelopeId() {
  return crypto.randomBytes(ID_BYTES).toString('base64url');
}

// Sign-message construction. Public so the recipient client can recompute
// the same bytes locally before calling ml_dsa65.sign().
function signMessageBytes(envelopeId, docHashHex, partyIndex) {
  const idBytes = Buffer.from(envelopeId, 'utf8');
  const hashBytes = Buffer.from(docHashHex, 'hex');
  const piBytes = Buffer.from(String(partyIndex), 'utf8');
  // Hash the concatenation so the message has a fixed 32-byte shape.
  return crypto.createHash('sha3-256')
    .update(idBytes).update(hashBytes).update(piBytes).digest();
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

  async create({ creatorPkHash, creatorApiKeyHash, docHash, parties, originalFilename, expiresInDays }) {
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

    const hash = {
      id,
      status: 'sent',
      doc_hash: docHash,
      creator_pk_hash: creatorPkHash || '',
      creator_api_hash: creatorApiKeyHash || '',
      original_filename: (originalFilename || '').toString().slice(0, 200),
      party_count: String(parties.length),
      signed_count: '0',
      created_at: now.toISOString(),
      expires_at: expires.toISOString(),
    };
    for (let i = 0; i < parties.length; i++) {
      const p = parties[i] || {};
      hash['p' + i + '_label'] = (p.label || '').toString().slice(0, MAX_LABEL_LEN);
      // We store sha3_256(email) only, never the email itself - the
      // creator's client keeps the address and emails the co-sign link.
      hash['p' + i + '_email_hash'] = p.email
        ? crypto.createHash('sha3-256').update(p.email.toString()).digest('hex')
        : '';
      hash['p' + i + '_status'] = 'pending';
    }
    await this.redis.hSet(key, hash);
    await this.redis.expire(key, ttlDays * 86400);

    try { this.ctAppend('envelope_create', id, { doc_hash: docHash, party_count: parties.length }); } catch {}

    return {
      id,
      created_at: hash.created_at,
      expires_at: hash.expires_at,
      party_count: parties.length,
      party_links: parties.map((_, i) => ({ party_index: i, sign_path: '/co-sign?env=' + id + '&p=' + i })),
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
      original_filename: h.original_filename || null,
      created_at: h.created_at,
      expires_at: h.expires_at,
      completed_at: h.completed_at || null,
      party_count: partyCount,
      signed_count: parseInt(h.signed_count, 10) || 0,
      parties,
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
  async sign(id, partyIndex, signerPubB64, signatureB64) {
    if (!this.available()) throw new Error('redis unavailable');
    const key = 'env:' + id;
    const h = await this.redis.hGetAll(key);
    if (!h || !h.doc_hash) return { ok: false, code: 'not_found' };
    const partyCount = parseInt(h.party_count, 10) || 0;
    const pi = parseInt(partyIndex, 10);
    if (!Number.isInteger(pi) || pi < 0 || pi >= partyCount) return { ok: false, code: 'not_found' };
    if (h.status === 'complete') return { ok: false, code: 'closed' };

    // Verify the signature server-side. The relay only sees doc_hash, id,
    // and party_index - so the recipient signs over their hash, not the
    // document. This binds the signature to this envelope slot.
    const msg = signMessageBytes(id, h.doc_hash, pi);
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

module.exports = { EnvelopeStore, signMessageBytes, newEnvelopeId, MAX_PARTIES, DEFAULT_TTL_DAYS, MAX_TTL_DAYS };
