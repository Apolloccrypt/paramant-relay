'use strict';
// Minimal Mollie Payments API client. The host is HARD-CODED to api.mollie.com,
// so there is no SSRF surface (the caller never supplies a URL). Keys come only
// from env, never from a request:
//   MOLLIE_API_KEY       (live_...)  used in live mode
//   MOLLIE_TEST_API_KEY  (test_...)  used in test mode
// One deployment runs in ONE mode at a time (test while integrating, live in
// prod). billingMode() decides which, so checkout and the webhook agree.

const https = require('https');

const MOLLIE_HOST = 'api.mollie.com';

// Which mode this deployment bills in. Explicit BILLING_MODE wins; otherwise a
// live key means live, else a test key means test. Defaults to 'live' so a
// misconfigured prod never silently bills against a test account.
function billingMode() {
  const m = (process.env.BILLING_MODE || '').toLowerCase();
  if (m === 'test' || m === 'live') return m;
  if (process.env.MOLLIE_API_KEY) return 'live';
  if (process.env.MOLLIE_TEST_API_KEY) return 'test';
  return 'live';
}

// The prefix Mollie gives each kind of key. A key is only ever used in the mode
// its prefix names: a live_ key in MOLLIE_TEST_API_KEY would have taken real
// money while every log said "test", and a test_ key in MOLLIE_API_KEY would
// have granted paid plans against payments that never happen. Both used to be
// accepted without a word, because only the deploy script looked at a prefix.
const KEY_PREFIX = Object.freeze({ live: 'live_', test: 'test_' });

function rawKeyFor(mode) {
  return (mode === 'test' ? process.env.MOLLIE_TEST_API_KEY : process.env.MOLLIE_API_KEY) || '';
}

// The key for this mode, or '' when there is none or its prefix belongs to the
// other mode. '' is the existing "no key" path: every Mollie call then throws
// mollie_key_missing, a checkout answers 502 and a webhook 503 so Mollie tries
// again, and nothing is billed against the wrong account.
function apiKeyFor(mode) {
  const key = rawKeyFor(mode);
  if (!key) return '';
  return key.startsWith(KEY_PREFIX[mode === 'test' ? 'test' : 'live']) ? key : '';
}

// What is wrong with the billing configuration, for the boot log. Never the key
// itself: at most the five characters of a known prefix. An empty list is the
// normal case, and it is what production (BILLING_MODE empty, a live_ key)
// produces.
function configProblems() {
  const problems = [];
  const raw = process.env.BILLING_MODE || '';
  const m = raw.toLowerCase();
  // A typo such as BILLING_MODE=prod used to vanish: it counted as "not set",
  // and the boot line even said so. It still falls back to the inferred
  // one-off stance, because that is the safe one, but it says so as an error.
  if (raw && m !== 'test' && m !== 'live') {
    // Shown only when it looks like a mode someone mistyped; anything else (a
    // key pasted into the wrong variable, say) stays out of the log.
    problems.push({ code: 'billing_mode_unknown', detail: /^[A-Za-z]{1,12}$/.test(raw) ? raw : '(hidden)' });
  }
  const prefixOf = (k) => (k.startsWith(KEY_PREFIX.live) || k.startsWith(KEY_PREFIX.test) ? k.slice(0, 5) : null);
  const live = process.env.MOLLIE_API_KEY || '';
  const test = process.env.MOLLIE_TEST_API_KEY || '';
  if (live && !live.startsWith(KEY_PREFIX.live)) {
    problems.push({ code: 'live_key_wrong_prefix', detail: prefixOf(live) });
  }
  if (test && !test.startsWith(KEY_PREFIX.test)) {
    problems.push({ code: 'test_key_wrong_prefix', detail: prefixOf(test) });
  }
  return problems;
}

// The stance this deployment bills in: which Mollie account (mode) and whether
// the recurring layer (customer, first payment, subscription) may run at all.
//
// billingMode() infers 'live' from the mere presence of a live key. That
// inference was fine for the code of 2026-08-08, which only ever created
// one-off payments. It is not enough to open mandates and subscriptions
// against a real Mollie account, because nobody decided that: production runs
// with BILLING_MODE empty and a live_ key, and a deploy of the recurring layer
// would have started collecting money on an inference, with code that has
// never seen a real Mollie answer.
//
// So the recurring layer needs BILLING_MODE set by hand. 'live' means real
// money, 'test' means the test account. Empty (or anything else) means exactly
// what it meant on 08-08: one-off payments in the inferred mode, no customer,
// no sequenceType, no subscription. Flipping it is a deploy-time decision, made
// in .env, and the boot log says which stance is active.
function billingStance() {
  const explicit = (process.env.BILLING_MODE || '').toLowerCase();
  const recurring = explicit === 'live' || explicit === 'test';
  const mode = billingMode();
  return {
    mode,
    recurring,
    source: recurring ? 'explicit' : 'inferred',
    key_present: !!apiKeyFor(mode),
  };
}

function _request(method, path, apiKey, bodyObj, extraHeaders) {
  return new Promise((resolve, reject) => {
    const body = bodyObj ? JSON.stringify(bodyObj) : null;
    const req = https.request({
      host: MOLLIE_HOST, port: 443, method, path,
      headers: Object.assign(
        { 'Authorization': `Bearer ${apiKey}`, 'Accept': 'application/json' },
        body ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } : {},
        extraHeaders || {}),
      timeout: 8000,
    }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch { /* non-JSON */ }
        resolve({ status: res.statusCode, body: json });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => req.destroy(new Error('mollie_timeout')));
    if (body) req.write(body);
    req.end();
  });
}

// POST /v2/payments. Returns the created payment object (with _links.checkout).
async function createPayment(mode, payload) {
  const key = apiKeyFor(mode);
  if (!key) throw new Error(`mollie_key_missing:${mode}`);
  const r = await _request('POST', '/v2/payments', key, payload);
  if (r.status !== 201) { const e = new Error('mollie_create_failed'); e.status = r.status; e.body = r.body; throw e; }
  return r.body;
}

// GET /v2/payments/:id. Returns the payment object. This is the ONLY source of
// truth the webhook trusts (never the webhook body).
async function getPayment(mode, id) {
  const key = apiKeyFor(mode);
  if (!key) throw new Error(`mollie_key_missing:${mode}`);
  const r = await _request('GET', `/v2/payments/${encodeURIComponent(id)}`, key, null);
  if (r.status !== 200) { const e = new Error('mollie_get_failed'); e.status = r.status; e.body = r.body; throw e; }
  return r.body;
}

// ── Recurring ────────────────────────────────────────────────────────────────
// A one-off payment collects once and never again. To bill every month or year
// Mollie needs three things in order: a customer to hang the mandate on, a first
// payment marked as such (paying it creates the mandate), and a subscription
// that does the collecting from then on. Missing any one of them means the money
// arrives exactly once, which is what happened here.

// POST /v2/customers. The email is what the buyer sees on the Mollie receipt and
// what support searches on; the account id in metadata is how a webhook without
// payment metadata can still be attributed.
async function createCustomer(mode, payload) {
  const key = apiKeyFor(mode);
  if (!key) throw new Error(`mollie_key_missing:${mode}`);
  const r = await _request('POST', '/v2/customers', key, payload);
  if (r.status !== 201) { const e = new Error('mollie_customer_failed'); e.status = r.status; e.body = r.body; throw e; }
  return r.body;
}

// GET /v2/customers/:id. Used to check a stored customer id still exists before
// reusing it; a deleted or foreign id must not silently break a checkout.
async function getCustomer(mode, id) {
  const key = apiKeyFor(mode);
  if (!key) throw new Error(`mollie_key_missing:${mode}`);
  const r = await _request('GET', `/v2/customers/${encodeURIComponent(id)}`, key, null);
  if (r.status !== 200) { const e = new Error('mollie_customer_get_failed'); e.status = r.status; e.body = r.body; throw e; }
  return r.body;
}

// GET /v2/customers/:id/mandates. Returns only the usable ones. A mandate is
// what authorises collection; without a valid one a subscription cannot be
// created, and 'pending' is not yet good enough to bill against.
async function validMandates(mode, customerId) {
  const key = apiKeyFor(mode);
  if (!key) throw new Error(`mollie_key_missing:${mode}`);
  const r = await _request('GET', `/v2/customers/${encodeURIComponent(customerId)}/mandates?limit=50`, key, null);
  if (r.status !== 200) { const e = new Error('mollie_mandates_failed'); e.status = r.status; e.body = r.body; throw e; }
  const list = (r.body && r.body._embedded && r.body._embedded.mandates) || [];
  return list.filter((m) => m && m.status === 'valid');
}

// Mollie's interval vocabulary. Kept here so the rest of the codebase keeps
// speaking 'monthly'/'yearly' and only this file knows the wire format.
function mollieInterval(interval) {
  if (interval === 'monthly') return '1 month';
  if (interval === 'yearly') return '12 months';
  return null;
}

// POST /v2/customers/:id/subscriptions.
//
// startDate matters more than it looks. The buyer has ALREADY paid for the first
// period through the first payment. Without a startDate Mollie collects again
// immediately and charges twice for the same month. So the subscription starts
// on the day the paid period ends, which is exactly the paid_until the webhook
// just computed.
//
// opts.idempotencyKey is sent as Mollie's Idempotency-Key header, so the same
// request made twice within Mollie's window for it (one hour) returns the
// subscription the first one made instead of a second one that collects again
// every month. That covers a retry of this call; it does not cover a process
// that died before making a second call at all.
async function createSubscription(mode, customerId, payload, opts) {
  const key = apiKeyFor(mode);
  if (!key) throw new Error(`mollie_key_missing:${mode}`);
  const idem = opts && opts.idempotencyKey ? { 'Idempotency-Key': String(opts.idempotencyKey) } : null;
  const r = await _request('POST', `/v2/customers/${encodeURIComponent(customerId)}/subscriptions`, key, payload, idem);
  if (r.status !== 201) { const e = new Error('mollie_subscription_failed'); e.status = r.status; e.body = r.body; throw e; }
  return r.body;
}

// DELETE /v2/customers/:id/subscriptions/:id. Cancelling stops future
// collections; it does NOT refund or shorten the period already paid for, which
// is why the entitlement keeps running until paid_until.
async function cancelSubscription(mode, customerId, subscriptionId) {
  const key = apiKeyFor(mode);
  if (!key) throw new Error(`mollie_key_missing:${mode}`);
  const r = await _request(
    'DELETE',
    `/v2/customers/${encodeURIComponent(customerId)}/subscriptions/${encodeURIComponent(subscriptionId)}`,
    key, null);
  // 200 is the cancel. A 404 is thrown with its status, not taken as success:
  // Mollie answers 404 both for a subscription that is gone and for one asked
  // for under the wrong customer, and only the caller knows which customer it
  // used (billing-recurring.stopSubscription decides).
  if (r.status !== 200) {
    const e = new Error(r.status === 404 ? 'mollie_cancel_not_found' : 'mollie_cancel_failed');
    e.status = r.status; e.body = r.body; throw e;
  }
  return r.body || { status: 'canceled' };
}

module.exports = {
  MOLLIE_HOST, KEY_PREFIX, billingMode, billingStance, apiKeyFor, configProblems, createPayment, getPayment,
  createCustomer, getCustomer, validMandates, mollieInterval,
  createSubscription, cancelSubscription,
};
