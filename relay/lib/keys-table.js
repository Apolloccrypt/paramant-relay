'use strict';
// Account-split schema helpers (stap 1: additive, behaviour-neutral).
//
// Today one string means three things: session.user_id == "pgp_..." ==
// apiKeys.get(key). This module introduces the additive account layer that
// lets account_id, primary_api_key and N per-account keys diverge later,
// WITHOUT changing current behaviour: for an existing key the defaults make
// account_id == the key itself (1:1), so every downstream lookup is identical.
//
// Pure module: no I/O, no globals. Unit-tested in test/keys-table.test.js.
const crypto = require('crypto');
const entitlements = require('./entitlements'); // per-product plan derivation

// The scopes a v2 API key can carry. ENFORCED, by requireScope() and
// scopeActionFor() below, which relay.js calls once per request. Kept as an
// allow-list so the enum stays stable for a non-breaking future migration to
// composite grants.
const VALID_SCOPES = new Set(['full', 'send-only', 'sign-only', 'read-only', 'parasign']);

// -- Scope enforcement (single source of truth) -------------------------------
// A v2 key is minted with a scope (relay.js POST /v2/admin/keys), the scope is
// stored on the record, and it is shown back in every key listing and in the
// dashboard. Until now it did nothing: `requireScope` did not exist and no
// route consulted rec.scope, so a key handed out as read-only had full write
// authority over the whole v2 plane, /v2/admin/* included. That is privilege
// escalation dressed up as a security feature. sec/relay-scope-enforcement
// found it on 16 July 2026; it stayed unlanded for 51 days.
//
// The design is a per-request choke point, not a per-route check, for the same
// reason session-token.js gives: a gate each route has to remember to call is a
// gate the next route forgets.
//
//   action  full  send-only  sign-only  read-only  parasign
//   read     y       y          y          y          y     safe methods, verify, lookup
//   common   y       y          y          .          y     shared infra writes both flows need
//   send     y       y          .          .          .     ParaSend upload / transfer session
//   sign     y       .          y          .          y     ParaSign envelope / signing key
//   admin    y       .          .          .          .     account, key, credential, billing
//   write    y       .          .          .          .     any v2 write not classified below
//
// Two properties this table is held to by test/keys-table-scope.test.js:
//
//   1. `full` is denied nothing. Every key in production today is full (or is a
//      legacy key with no scope, normalised to full at load), so enforcement
//      turns on without changing a single existing flow.
//   2. Every other scope is denied something. A scope that restricts nothing is
//      the bug this whole change exists to fix, and the test fails the moment a
//      new name is added to VALID_SCOPES without a row here.
//
// `write` is the fallback, and it is full-only ON PURPOSE. An unclassified
// mutating v2 route fails closed for narrow keys rather than being waved
// through as a read, so a route added next year cannot silently reopen the
// hole. The cost is bounded by property 1: it can never break a full key.
const SCOPE_ACTIONS = {
  read:   new Set(['full', 'send-only', 'sign-only', 'read-only', 'parasign']),
  common: new Set(['full', 'send-only', 'sign-only', 'parasign']),
  send:   new Set(['full', 'send-only']),
  sign:   new Set(['full', 'sign-only', 'parasign']),
  admin:  new Set(['full']),
  write:  new Set(['full']),
};

// Safe methods never mutate, so they are always 'read'. Asking the method first
// is deliberate: the 2026-07 branch classified by path first, which made
// GET /v2/user/envelopes an 'admin' action and would have locked a read-only
// key out of its own document list.
const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

// Account, key, credential and billing management. Full keys only.
const ADMIN_WRITE_PREFIXES = [
  '/v2/admin/',
  '/v2/user/webauthn/',
  '/v2/billing/',
];
const ADMIN_WRITE_PATHS = new Set([
  '/v2/admin',
  '/v2/user/parasign-keys',      // mints and revokes API keys
  '/v2/user/setup-totp', '/v2/user/verify-totp', '/v2/user/activate-totp',
  '/v2/user/delete-totp', '/v2/user/get-totp-provisional',
  '/v2/user/consume-backup', '/v2/user/regenerate-backup',
  '/v2/claim/reveal',            // hands back a key
  '/v2/reload-users', '/v2/setup/apply',
  '/v2/relays/register', '/v2/team/add-device',
]);

// ParaSend data plane.
const SEND_PATHS = new Set(['/v2/inbound', '/v2/anon-inbound', '/v2/session/create']);

// ParaSign data plane.
const SIGN_PREFIXES = ['/v2/parasign/', '/v2/user/signing-key'];
const SIGN_PATHS = new Set([
  '/v2/envelopes', '/v2/sign', '/v2/sign-dpa', '/v2/qes/sign', '/v2/user/envelopes',
]);

// Writes both flows need, and which are not by themselves send or sign.
const COMMON_PATHS = new Set([
  '/v2/pubkey', '/v2/did/register', '/v2/attest', '/v2/ack', '/v2/webhook',
  '/v2/ws-ticket', '/v2/session/join', '/v2/session-token', '/v2/sth/ingest',
  '/v2/user/usage-purpose', '/v2/billing/webhook',
]);

// POST routes that only read: verification and diagnostics. A read-only key
// must be able to reach these, or "read-only" does not describe the product.
const READ_POSTS = new Set([
  '/v2/verify', '/v2/verify-receipt', '/v2/pubkey/verify',
  '/v2/setup/check', '/v2/setup/dns-check',
]);

const INBOUND_ABORT_RE = /^\/v2\/inbound\/[a-f0-9]{64}$/;

// Map an HTTP (method, path) onto the scope action it needs. Pure; the whole
// route table lives here so relay.js carries no policy of its own.
function scopeActionFor(method, path) {
  const m = String(method || '').toUpperCase();
  const p = String(path || '');
  // /v1 has its own psk_ Bearer gate (lib/parasign-open-api.js) and returns
  // before this one, and /health, /metrics and the static frontend are not the
  // v2 data plane. Nothing outside /v2 is classified here.
  if (!p.startsWith('/v2')) return 'read';
  if (SAFE_METHODS.has(m)) return 'read';
  if (READ_POSTS.has(p)) return 'read';

  // The Stripe webhook lives under /v2/billing/ but carries no key at all.
  if (p !== '/v2/billing/webhook'
      && (ADMIN_WRITE_PATHS.has(p) || ADMIN_WRITE_PREFIXES.some((x) => p.startsWith(x)))) {
    return 'admin';
  }
  if (SEND_PATHS.has(p) || INBOUND_ABORT_RE.test(p)) return 'send';
  if (SIGN_PATHS.has(p) || SIGN_PREFIXES.some((x) => p.startsWith(x))) return 'sign';
  if (p.startsWith('/v2/envelopes/')) return 'sign';   // party view / sign / resend
  if (COMMON_PATHS.has(p)) return 'common';
  return 'write';                                      // unclassified: full only
}

// May a key with this record's scope perform `action`? Default-deny on an
// unknown action. A missing scope, or a scope string no longer in the enum, is
// normalised to 'full', which is exactly what parseAccountFields does at load,
// so legacy records behave identically before and after this gate exists.
function requireScope(keyData, action) {
  const allowed = SCOPE_ACTIONS[action];
  if (!allowed) return false;
  let scope = (keyData && keyData.scope) || 'full';
  if (!VALID_SCOPES.has(scope)) scope = 'full';
  return allowed.has(scope);
}

// ParaSign Open-API (/v1) entitlement check. A key grants the parasign scope
// when its record says so in any of three accepted shapes, so this survives the
// single-string scope enum above without a schema migration:
//   rec.scope === 'parasign'  |  rec.parasign === true  |  rec.scopes[] has it.
//
// AND the grant must still be running. The flag is written by
// entitlements.applyProductTier on a purchase and cleared only by an explicit
// write down to the floor tier; expiry is enforced on READ and never writes
// back. So until 2026-09-06 the three shapes above were read raw, and one month
// of ParaSign Pro bought the /v1 API forever: the term lapsed,
// effectiveProductTier reported `free` to everyone who asked it, and this
// function -- the actual gate -- never asked. A grant with no recorded period
// (an admin set-parasign, and every account from before billing existed) has no
// term to run out and stays true, which is exactly what effectiveProductTier
// already means by expired:false.
function parasignGrantLive(rec, now) {
  if (!rec) return false;
  const flagged = rec.scope === 'parasign'
    || rec.parasign === true
    || (Array.isArray(rec.scopes) && rec.scopes.includes('parasign'));
  if (!flagged) return false;
  return !entitlements.effectiveProductTier(rec, 'parasign', now).expired;
}

function hasParaSignScope(rec, now) {
  return parasignGrantLive(rec, now);
}

// Non-secret, stable key identifier for URLs/listings (never the raw pgp_ key).
// 48 bits of SHA3-free SHA-256 prefix: collision-safe well past 10M keys.
function computeKid(key) {
  return 'k_' + crypto.createHash('sha256').update(String(key)).digest('hex').slice(0, 12);
}

// Mask a secret API key for list/observation output so the full pgp_ value is
// never returned in bulk. Keeps a short prefix + last 4 so an operator can tell
// rows apart, without leaking enough to use the key. The full value is only
// returned by the explicit ?reveal=1 list opt-in or the single-key reveal route
// (both ADMIN_TOKEN-gated, for server-to-server callers). Short strings (<=12)
// are returned unchanged — they are not full keys.
function maskApiKey(key) {
  const s = String(key || '');
  if (s.length <= 12) return s;
  return s.slice(0, 8) + '…' + s.slice(-4);
}

// Parse the additive account fields off a raw users.json key record, with
// backward-compatible defaults. A record with no explicit account_id is its own
// account (account_id = key), is its own primary, full scope, and — being a
// seeded primary — stays re-revealable until the user rotates it.
function parseAccountFields(rawKey) {
  const hasAccountId = rawKey.account_id != null && rawKey.account_id !== '';
  const account_id = hasAccountId ? rawKey.account_id : rawKey.key;
  const is_primary = (rawKey.is_primary !== undefined) ? !!rawKey.is_primary : !hasAccountId;
  const scope = VALID_SCOPES.has(rawKey.scope) ? rawKey.scope : 'full';
  const legacy_revealable = (rawKey.legacy_revealable !== undefined)
    ? !!rawKey.legacy_revealable
    : (!hasAccountId && is_primary);
  // ParaSign /v1 API grant. Orthogonal to `scope` (which stays single-valued):
  // this is an additive, behaviour-neutral boolean entitlement - the relay does
  // not gate on it yet - that an admin toggles on/off as the override alongside
  // the automatic grant on payment. Default off. /*MARK:parasign_parse*/
  const parasign = rawKey.parasign === true;
  // Per-product plans (ParaSend vs ParaSign). Prefer an explicit stored value
  // (post-migration); otherwise derive from the legacy `plan` (+ parasign flag)
  // WITHOUT downgrading, so an un-migrated key still gets correct entitlements.
  const plan_parasend = rawKey.plan_parasend || entitlements.derivePlanParasend(rawKey.plan);
  const plan_parasign = rawKey.plan_parasign || entitlements.derivePlanParasign(rawKey.plan, parasign);
  // Usage-purpose survey answer (growth): rehydrated so it survives a
  // users.json reload. null (not undefined) keeps the admin JSON shape stable.
  const usage_purpose = typeof rawKey.usage_purpose === 'string' ? rawKey.usage_purpose : null;
  const usage_purpose_at = rawKey.usage_purpose_at || null;
  // The paid period belongs to the tier above and must be rehydrated with it.
  // Without this the in-memory record carried a paid tier and no end date, and
  // an end date that is not loaded is an entitlement that never expires: the
  // relay wrote paid_until to users.json correctly and then dropped it on the
  // way back in. Only set when present, so "no period on file" stays absent
  // (never expired) rather than becoming an explicit null.
  const out = { account_id, is_primary, scope, legacy_revealable, parasign, plan_parasend, plan_parasign, usage_purpose, usage_purpose_at };
  for (const product of entitlements.PRODUCTS) {
    const f = entitlements.PRODUCT_PAID_UNTIL_FIELD[product];
    if (rawKey[f] != null) out[f] = rawKey[f];
  }
  return out;
}

// Pick a kid not already present in `taken` (anything with a .has(kid) method:
// the live kidIndex Map, or a Set in tests). On the astronomically-unlikely
// 48-bit prefix collision at LOAD time we cannot regenerate an existing key, so
// we suffix the kid and warn. (At CREATE time the caller regenerates the key
// instead — see assignKid usage notes; not wired in stap 1.)
function assignKid(taken, key, log) {
  const base = computeKid(key);
  if (!taken.has(base)) return base;
  let n = 1, alt = `${base}_${n}`;
  while (taken.has(alt) && n < 1000) { n += 1; alt = `${base}_${n}`; }
  if (log) log('warn', 'kid_collision', { kid: base, resolved: alt, key_prefix: String(key).slice(0, 8) });
  return alt;
}

// Full rebuild of the account/index Maps from the live apiKeys Map. Idempotent:
// clears and re-derives on every call (used after load, trial-load and the
// reload atomic swap). Each apiKeys value must already carry account_id/
// is_primary/scope (set via parseAccountFields at load). Assigns each value a
// stable `kid`. First-writer fills the account record; an explicit primary key
// always wins primary_api_key.
function rebuildKeyIndexes(apiKeys, accounts, accountKeys, kidIndex, log) {
  accounts.clear();
  accountKeys.clear();
  kidIndex.clear();
  for (const [key, v] of apiKeys) {
    const account_id = v.account_id || key;
    if (!accounts.has(account_id)) {
      accounts.set(account_id, { account_id, plan: v.plan, email: v.email || '', primary_api_key: null, label: v.label || '' });
    }
    const acct = accounts.get(account_id);
    // Carry the PER-PRODUCT plans into the summary as well, taking the highest
    // tier any key of the account holds. Without this the summary only ever had
    // the legacy `plan`, so a paid ParaSign grant was invisible to anything
    // reading accounts -- the bug that put a paying customer back behind the
    // free 2-signature wall. It also means the mirror setProductPlan writes
    // survives a restart and POST /v2/admin/keys/reload instead of being
    // silently dropped on the next rebuild.
    // Tier AND paid period together: a summary that took the highest tier but
    // left the date behind handed every account-level read an unbounded grant,
    // which is the same drop mergeAccountRecord used to make one layer up.
    entitlements.mergeProductGrantInto(acct, v, 'parasign');
    entitlements.mergeProductGrantInto(acct, v, 'parasend');
    if (v.parasign) acct.parasign = true;
    if (v.is_primary || !acct.primary_api_key) acct.primary_api_key = v.is_primary ? key : (acct.primary_api_key || key);
    if (!accountKeys.has(account_id)) accountKeys.set(account_id, new Set());
    accountKeys.get(account_id).add(key);
    const kid = assignKid(kidIndex, key, log);
    v.kid = kid;
    kidIndex.set(kid, key);
  }
  return { accounts, accountKeys, kidIndex };
}

// users.json v1 -> v2 migration. Pure: returns a NEW object, never mutates the
// input. Idempotent: a v2 input (schema_version >= 2) is returned unchanged, so
// running it twice is a no-op. Seeds account_id = key for every existing key.
function migrateUsersV2(data) {
  if (!data || !Array.isArray(data.api_keys)) throw new Error('invalid users.json: missing api_keys array');
  if ((data.schema_version | 0) >= 2) return data;
  const accounts = {};
  const api_keys = data.api_keys.map((k) => {
    const fields = parseAccountFields(k);
    const a = accounts[fields.account_id]
      || (accounts[fields.account_id] = { account_id: fields.account_id, plan: k.plan, email: k.email || '', primary_api_key: null, label: k.label || '' });
    if (fields.is_primary || !a.primary_api_key) a.primary_api_key = fields.is_primary ? k.key : (a.primary_api_key || k.key);
    return { ...k, ...fields };
  });
  return { ...data, schema_version: 2, accounts, api_keys };
}

// Decide which keys are over a limit. Returns a Set<key> of over-limit keys
// (keys NOT in the set are within limits). Two orthogonal dimensions, OR'd
// (decision F):
//   per-account  — within each account, active keys are sorted primary-first
//                  then created-asc (missing created = oldest), insertion-order
//                  tiebreak; those at index >= the account's plan cap are over.
//   relay-total  — self-host community only (edition !== 'licensed'): active
//                  keys beyond licenseMaxKeys in insertion order are over.
// Pure: reads the Maps, mutates nothing. `capForPlan(plan)` returns the numeric
// per-account cap (Infinity for uncapped plans).
function computeOverLimit(apiKeys, accounts, accountKeys, opts) {
  const { capForPlan, licenseMaxKeys = Infinity, edition = 'community' } = opts || {};
  const over = new Set();

  const order = new Map();
  let i = 0;
  for (const key of apiKeys.keys()) order.set(key, i++);

  for (const [accountId, keySet] of accountKeys) {
    const acct = accounts.get(accountId);
    const cap = capForPlan ? capForPlan(acct ? acct.plan : 'community') : Infinity;
    if (!(cap < Infinity)) continue;
    const active = [...keySet].filter((k) => { const v = apiKeys.get(k); return v && v.active !== false; });
    active.sort((a, b) => {
      const va = apiKeys.get(a), vb = apiKeys.get(b);
      const pa = va.is_primary ? 0 : 1, pb = vb.is_primary ? 0 : 1;
      if (pa !== pb) return pa - pb;
      const ca = va.created ? (Date.parse(va.created) || 0) : 0;
      const cb = vb.created ? (Date.parse(vb.created) || 0) : 0;
      if (ca !== cb) return ca - cb;
      return order.get(a) - order.get(b);
    });
    active.forEach((k, idx) => { if (idx >= cap) over.add(k); });
  }

  if (edition !== 'licensed' && licenseMaxKeys !== Infinity) {
    let n = 0;
    for (const [key, v] of apiKeys) {
      if (v.active === false) continue;
      n += 1;
      if (n > licenseMaxKeys) over.add(key);
    }
  }

  return over;
}

// Designate `key` as the primary api-key of account `accountId` (stap 4). Mutates
// the live Maps in place: promotes the chosen key (is_primary=true), demotes every
// other member of the account, and repoints accounts[accountId].primary_api_key.
// Pure w.r.t. I/O — the caller persists to users.json and reads no globals.
// Throws (caller maps to 4xx) when the key is unknown, inactive, or not a member
// of the account, so a mismatched account_id can never silently move a primary.
// Returns { previous, current } (previous may be null on a fresh account).
function designatePrimary(apiKeys, accounts, accountKeys, accountId, key) {
  const v = apiKeys.get(key);
  if (!v) { const e = new Error('key_not_found'); e.code = 'key_not_found'; throw e; }
  if (v.active === false) { const e = new Error('key_inactive'); e.code = 'key_inactive'; throw e; }
  const acctOf = v.account_id || key;
  if (acctOf !== accountId) { const e = new Error('key_account_mismatch'); e.code = 'key_account_mismatch'; throw e; }
  const members = accountKeys.get(accountId) || new Set([key]);
  const previous = (accounts.get(accountId) && accounts.get(accountId).primary_api_key) || null;
  for (const m of members) { const mv = apiKeys.get(m); if (mv) mv.is_primary = (m === key); }
  v.is_primary = true;
  if (!accounts.has(accountId)) {
    accounts.set(accountId, { account_id: accountId, plan: v.plan, email: v.email || '', primary_api_key: key, label: v.label || '' });
  } else {
    accounts.get(accountId).primary_api_key = key;
  }
  return { previous, current: key };
}

// -- ParaSign /v1 key issuance (psk_) -----------------------------------------
// Pure record builder shared by BOTH issuance paths (self-serve + admin-mint) so
// there is exactly ONE psk_ format and ONE stored shape -- no drift. relay.js
// wraps this with a CSPRNG token, the live-Map wiring and users.json persistence
// (see mintParasignKey). The key is bound to `accountId` and carries BOTH the
// scope=='parasign' and the boolean parasign grant, so the /v1 auth accepts it
// under either representation and it survives a users.json reload (parseAccountFields
// keeps scope+parasign). A minted product key is never an account primary.
//   randomHex: caller-supplied cryptographic hex (relay: crypto.randomBytes(32)).
//   test:      psk_test_ (sandbox) vs psk_live_.
function buildParasignKeyRecord({ accountId, plan, email, label, test, randomHex, createdAt, planParasign, planParasend, paidUntilParasign, paidUntilParasend }) {
  if (!accountId) throw new Error('accountId required');
  if (!randomHex || typeof randomHex !== 'string') throw new Error('randomHex required');
  const key = (test ? 'psk_test_' : 'psk_live_') + randomHex;
  const created = createdAt || new Date().toISOString();
  const normPlan = (typeof plan === 'string' && plan) ? plan : 'community';
  // INHERIT the account's per-product tiers. Without these the new key only
  // carried the legacy `plan`, which for a ParaSign customer stays 'community'
  // (setProductPlan deliberately never touches it). parseAccountFields would
  // then derive plan_parasign = free on the next load and the /v1 gate would put
  // a paying account back on 2 signatures: the exact incident, reproduced by
  // nothing more than minting a fresh key. Callers pass the merged account
  // record's tiers; absent, we fall back to deriving from the legacy plan.
  const normParasign = entitlements.normaliseParasignTier(planParasign || entitlements.derivePlanParasign(normPlan, true));
  const normParasend = entitlements.normaliseParasendTier(planParasend || entitlements.derivePlanParasend(normPlan));
  const rec = {
    plan: normPlan,
    plan_parasign: normParasign,
    plan_parasend: normParasend,
    label: (typeof label === 'string' ? label.slice(0, 128) : '') || 'parasign-api',
    email: email || '',
    active: true,
    account_id: accountId,
    is_primary: false,
    scope: 'parasign',
    parasign: true,
    product: 'parasign',
    created,
  };
  // users.json persisted entry (subset the loader re-hydrates via parseAccountFields).
  const usersEntry = {
    key, plan: rec.plan, label: rec.label, email: rec.email, active: true, created,
    plan_parasign: normParasign, plan_parasend: normParasend,
    account_id: accountId, is_primary: false, scope: 'parasign', parasign: true, product: 'parasign',
  };
  // The paid PERIOD travels with the inherited tier, onto BOTH the live record
  // and the users.json entry. Without it a key minted while the subscription was
  // still running carried a paid tier and no end date, and "no recorded period"
  // means "never expires" (entitlements.js:137). So the new key outlived the
  // subscription that paid for it, and outlived a restart too, because that is
  // the shape that reached disk. Both issuance paths run through here
  // (POST /v2/user/parasign-keys, self-serve, and the admin mint), so this is
  // the one place it has to be right.
  // applyProductTier is the shared field rule: undefined leaves the field alone,
  // and landing on a floor tier clears any period, so a lapsed grant is minted
  // as a plain floor key with no stale date on it.
  for (const [product, tier, until] of [
    ['parasign', normParasign, paidUntilParasign],
    ['parasend', normParasend, paidUntilParasend],
  ]) {
    entitlements.applyProductTier(rec, product, tier, until);
    entitlements.applyProductTier(usersEntry, product, tier, until);
  }
  return { key, record: rec, usersEntry };
}

// Which plans carry the ParaSign entitlement without an explicit grant. `business`
// is a first-class paid ParaSign tier (1000 signs, audit_export), so its accounts
// must reach the /v1 API on plan name alone -- not only via the fragile per-key
// parasign flag. `licensed` is listed alongside `enterprise` so an un-normalised
// plan name still matches.
const PARASIGN_ENTITLED_PLANS = new Set(['pro', 'business', 'enterprise', 'licensed']);

// Self-serve gate: may this account mint a ParaSign /v1 key? True when ANY member
// key already carries the parasign grant (admin set-parasign / billing auto-grant),
// OR the account plan itself includes ParaSign (paid). Pure: takes the account's
// member key-records and its plan; no I/O, no globals.
// The period is read here too, and for the sharper reason: this is the gate on
// MINTING. A lapsed account that can still mint gets a fresh key on every call,
// each one floored to `free` by mintParasignKey but each one a working /v1
// credential and a new line in users.json. The self-perpetuating part is what
// makes it worth a gate rather than a shrug: a minted key carries parasign:true
// itself, so it re-satisfies this very check for its own account.
function accountHasParasignEntitlement(memberRecords, plan, now) {
  for (const r of (memberRecords || [])) { if (parasignGrantLive(r, now)) return true; }
  return PARASIGN_ENTITLED_PLANS.has(plan);
}

// ── Erasure: what a deletion request must actually remove ────────────────────
//
// Revoking a key stops it working. It does not remove the person behind it, and
// for a while that was the whole of "delete account": POST /admin/delete-account
// flipped every key to inactive, cleared Redis, and left the email address
// sitting in users.json on all five sectors. Audit finding 5 of 2026-07-21.
// Article 17 GDPR is about erasure, and an inactive record that still names
// someone is not erased.
//
// The fields below are the ones that identify a person. Everything else on a key
// record describes what was bought and used, and that has to survive: a payment
// must stay traceable for the tax years it belongs to. So this erases identity,
// never financial fact, and it marks the record instead of removing it, because
// removing the row would take the billing history with it.
const PERSONAL_DATA_FIELDS = Object.freeze([
  'email', 'label', 'dsa_pub', 'trial_metadata', 'name', 'company', 'phone',
]);

// Erase in place, on the parsed users.json that _mutateUsersJson hands its
// callback. Touches both places an account lives: the accounts summary and every
// api-key record belonging to it (see mergeAccountRecord in entitlements.js for
// why there are two).
//
// Idempotent on purpose. A deletion that runs twice, or that is retried after a
// sector was briefly unreachable, must not fail the second time; it should find
// nothing left to do and say so.
function erasePersonalData(data, accountOrKey) {
  const out = { accounts: 0, keys: 0, fields: 0 };
  if (!data || !accountOrKey) return out;
  const wipe = (rec) => {
    let n = 0;
    for (const f of PERSONAL_DATA_FIELDS) {
      if (rec[f] !== undefined && rec[f] !== null) { delete rec[f]; n++; }
    }
    if (n) { rec.erased_at = rec.erased_at || new Date().toISOString(); }
    return n;
  };
  const matches = (rec) => rec && (rec.key === accountOrKey || rec.account_id === accountOrKey);

  for (const rec of (data.api_keys || [])) {
    if (!matches(rec)) continue;
    const n = wipe(rec);
    if (n) { out.keys++; out.fields += n; }
    // A key whose owner is gone must not keep working, even if the revoke call
    // that normally precedes this never landed.
    rec.active = false;
  }
  for (const rec of (data.accounts || [])) {
    if (!matches(rec)) continue;
    const n = wipe(rec);
    if (n) { out.accounts++; out.fields += n; }
  }
  return out;
}

module.exports = {
  PERSONAL_DATA_FIELDS,
  erasePersonalData, VALID_SCOPES, SCOPE_ACTIONS, requireScope, scopeActionFor, hasParaSignScope, parasignGrantLive, computeKid, maskApiKey, parseAccountFields, assignKid, rebuildKeyIndexes, migrateUsersV2, computeOverLimit, designatePrimary, buildParasignKeyRecord, accountHasParasignEntitlement, PARASIGN_ENTITLED_PLANS };
