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

module.exports = { MOLLIE_HOST, billingMode, apiKeyFor, createPayment, getPayment };
