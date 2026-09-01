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

function apiKeyFor(mode) {
  return (mode === 'test' ? process.env.MOLLIE_TEST_API_KEY : process.env.MOLLIE_API_KEY) || '';
}

function _request(method, path, apiKey, bodyObj) {
  return new Promise((resolve, reject) => {
    const body = bodyObj ? JSON.stringify(bodyObj) : null;
    const req = https.request({
      host: MOLLIE_HOST, port: 443, method, path,
      headers: Object.assign(
        { 'Authorization': `Bearer ${apiKey}`, 'Accept': 'application/json' },
        body ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) } : {}),
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
async function createSubscription(mode, customerId, payload) {
  const key = apiKeyFor(mode);
  if (!key) throw new Error(`mollie_key_missing:${mode}`);
  const r = await _request('POST', `/v2/customers/${encodeURIComponent(customerId)}/subscriptions`, key, payload);
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
  // 200 is the cancel; 404 means it is already gone, which is the same outcome.
  if (r.status !== 200 && r.status !== 404) {
    const e = new Error('mollie_cancel_failed'); e.status = r.status; e.body = r.body; throw e;
  }
  return r.body || { status: 'canceled' };
}

module.exports = {
  MOLLIE_HOST, billingMode, apiKeyFor, createPayment, getPayment,
  createCustomer, getCustomer, validMandates, mollieInterval,
  createSubscription, cancelSubscription,
};
