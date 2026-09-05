'use strict';
// A stand-in for api.mollie.com, for tests that have to walk the whole buyer
// path. It is NOT a mock of our own code: relay/lib/mollie.js, the checkout
// route and the webhook route all run exactly as they do in production. The
// only thing replaced is the far end of the wire.
//
// Two halves:
//   1. the API half (/v2/payments, /v2/customers, ...) that lib/mollie.js
//      talks to. Reached through the https interception in mollie-intercept,
//      because MOLLIE_HOST is hard-coded on purpose (no SSRF surface).
//   2. the CHECKOUT half (/checkout/:id), a page a real browser can open and
//      click, which is what the buyer actually does. Clicking it flips the
//      payment to 'paid', POSTs the webhook the way Mollie does (form-encoded,
//      body carries only the id) and 302s to redirectUrl.
//
// Control endpoints (/_ctl/*) let a test do the things a customer service desk
// would do at Mollie: refund, chargeback, fail a payment, or drive a
// subscription's recurring collection.

const http = require('http');
const crypto = require('crypto');

function rid(prefix) { return prefix + crypto.randomBytes(12).toString('hex'); }

function create(opts = {}) {
  const payments = new Map();
  const customers = new Map();
  const subscriptions = new Map();
  const mandates = new Map(); // customerId -> [mandate]
  const webhookCalls = [];
  let failWebhook = false;

  const json = (res, status, obj) => {
    const b = JSON.stringify(obj);
    res.writeHead(status, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(b) });
    res.end(b);
  };
  const readBody = (req) => new Promise((resolve) => {
    const c = []; req.on('data', (d) => c.push(d)); req.on('end', () => resolve(Buffer.concat(c).toString('utf8')));
  });

  let selfOrigin = '';

  // Mollie calls our webhook. Form-encoded, id only: the receiver has to
  // re-fetch, which is the property the webhook route is built on.
  async function callWebhook(payment) {
    if (!payment.webhookUrl || failWebhook) return { skipped: true };
    const body = new URLSearchParams({ id: payment.id }).toString();
    const r = await fetch(payment.webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    }).catch((e) => ({ ok: false, status: 0, _err: e.message }));
    const rec = { id: payment.id, status: r.status || 0, ok: !!r.ok, at: new Date().toISOString() };
    webhookCalls.push(rec);
    return rec;
  }

  function markPaid(p) {
    p.status = 'paid';
    p.paidAt = new Date().toISOString();
    if (p.customerId && p.sequenceType === 'first') {
      const list = mandates.get(p.customerId) || [];
      list.push({ resource: 'mandate', id: rid('mdt_'), status: 'valid', method: 'creditcard' });
      mandates.set(p.customerId, list);
      p.mandateId = list[list.length - 1].id;
    }
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url, `http://127.0.0.1`);
    const p = url.pathname;
    const m = req.method;

    // ---- API half -----------------------------------------------------------
    if (p === '/v2/payments' && m === 'POST') {
      const payload = JSON.parse((await readBody(req)) || '{}');
      const id = rid('tr_');
      const payment = Object.assign({
        resource: 'payment', id, mode: 'test',
        createdAt: new Date().toISOString(),
        status: 'open',
        amountRefunded: undefined,
      }, payload, {
        _links: { checkout: { href: `${selfOrigin}/checkout/${id}`, type: 'text/html' } },
      });
      payments.set(id, payment);
      return json(res, 201, payment);
    }
    let mm;
    if ((mm = p.match(/^\/v2\/payments\/([^/]+)$/)) && m === 'GET') {
      const payment = payments.get(decodeURIComponent(mm[1]));
      if (!payment) return json(res, 404, { status: 404, title: 'Not Found', detail: 'No payment exists with token ' + mm[1] });
      return json(res, 200, payment);
    }
    if (p === '/v2/customers' && m === 'POST') {
      const payload = JSON.parse((await readBody(req)) || '{}');
      const id = rid('cst_');
      const c = Object.assign({ resource: 'customer', id, createdAt: new Date().toISOString() }, payload);
      customers.set(id, c);
      return json(res, 201, c);
    }
    if ((mm = p.match(/^\/v2\/customers\/([^/]+)$/)) && m === 'GET') {
      const c = customers.get(decodeURIComponent(mm[1]));
      if (!c) return json(res, 404, { status: 404, title: 'Not Found' });
      return json(res, 200, c);
    }
    if ((mm = p.match(/^\/v2\/customers\/([^/]+)\/mandates$/)) && m === 'GET') {
      const list = mandates.get(decodeURIComponent(mm[1])) || [];
      return json(res, 200, { count: list.length, _embedded: { mandates: list } });
    }
    if ((mm = p.match(/^\/v2\/customers\/([^/]+)\/subscriptions$/)) && m === 'POST') {
      const customerId = decodeURIComponent(mm[1]);
      const payload = JSON.parse((await readBody(req)) || '{}');
      const id = rid('sub_');
      const s = Object.assign({ resource: 'subscription', id, customerId, status: 'active', createdAt: new Date().toISOString() }, payload);
      subscriptions.set(id, s);
      return json(res, 201, s);
    }
    if ((mm = p.match(/^\/v2\/customers\/([^/]+)\/subscriptions\/([^/]+)$/)) && m === 'DELETE') {
      const s = subscriptions.get(decodeURIComponent(mm[2]));
      if (!s) return json(res, 404, { status: 404, title: 'Not Found' });
      s.status = 'canceled';
      s.canceledAt = new Date().toISOString();
      return json(res, 200, s);
    }

    // ---- CHECKOUT half (what the buyer's browser opens) ---------------------
    if ((mm = p.match(/^\/checkout\/([^/]+)$/)) && m === 'GET') {
      const payment = payments.get(decodeURIComponent(mm[1]));
      if (!payment) { res.writeHead(404, { 'Content-Type': 'text/html' }); return res.end('<h1>onbekende betaling</h1>'); }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      return res.end(`<!doctype html><meta charset="utf-8"><title>Testkassa</title>
<h1>Testkassa</h1>
<p id="desc">${String(payment.description || '').replace(/[<>&]/g, '')}</p>
<p id="amount">${payment.amount.currency} ${payment.amount.value}</p>
<form method="POST" action="/checkout/${payment.id}">
  <button id="pay" name="outcome" value="paid" type="submit">Betaal</button>
  <button id="cancel" name="outcome" value="canceled" type="submit">Annuleer</button>
</form>`);
    }
    if ((mm = p.match(/^\/checkout\/([^/]+)$/)) && m === 'POST') {
      const payment = payments.get(decodeURIComponent(mm[1]));
      if (!payment) { res.writeHead(404); return res.end(); }
      const form = new URLSearchParams(await readBody(req));
      const outcome = form.get('outcome') || 'paid';
      if (outcome === 'paid') markPaid(payment); else payment.status = outcome;
      await callWebhook(payment);
      res.writeHead(302, { Location: payment.redirectUrl || '/' });
      return res.end();
    }

    // ---- control ------------------------------------------------------------
    if (p.startsWith('/_ctl/')) {
      const body = m === 'POST' ? JSON.parse((await readBody(req)) || '{}') : {};
      if (p === '/_ctl/payments') return json(res, 200, [...payments.values()]);
      if (p === '/_ctl/webhooks') return json(res, 200, webhookCalls);
      if (p === '/_ctl/subscriptions') return json(res, 200, [...subscriptions.values()]);
      if (p === '/_ctl/refund') {
        const payment = payments.get(body.id);
        if (!payment) return json(res, 404, { error: 'no_payment' });
        payment.amountRefunded = { currency: payment.amount.currency, value: body.value || payment.amount.value };
        await callWebhook(payment);
        return json(res, 200, payment);
      }
      if (p === '/_ctl/chargeback') {
        const payment = payments.get(body.id);
        if (!payment) return json(res, 404, { error: 'no_payment' });
        payment.status = 'chargeback';
        await callWebhook(payment);
        return json(res, 200, payment);
      }
      if (p === '/_ctl/recurring') {
        // What a subscription does a month later: a new payment, sequenceType
        // 'recurring', same metadata, straight to paid, then the webhook.
        const sub = subscriptions.get(body.subscriptionId);
        if (!sub) return json(res, 404, { error: 'no_subscription' });
        const id = rid('tr_');
        const payment = {
          resource: 'payment', id, mode: 'test', status: 'open',
          createdAt: new Date().toISOString(),
          amount: sub.amount, description: sub.description,
          metadata: sub.metadata, customerId: sub.customerId,
          sequenceType: 'recurring', subscriptionId: sub.id,
          webhookUrl: sub.webhookUrl || body.webhookUrl,
        };
        payments.set(id, payment);
        markPaid(payment);
        await callWebhook(payment);
        return json(res, 200, payment);
      }
      if (p === '/_ctl/webhook-off') { failWebhook = !!body.off; return json(res, 200, { failWebhook }); }
      return json(res, 404, { error: 'unknown_control' });
    }

    json(res, 404, { status: 404, title: 'Not Found', detail: p });
  });

  return {
    server, payments, customers, subscriptions, webhookCalls,
    async listen() {
      await new Promise((r) => server.listen(0, '127.0.0.1', r));
      selfOrigin = `http://127.0.0.1:${server.address().port}`;
      return selfOrigin;
    },
    origin: () => selfOrigin,
    close() { return new Promise((r) => server.close(r)); },
  };
}

module.exports = { create };
