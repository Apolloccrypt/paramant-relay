'use strict';
// ParaSign /v1 webhook delivery (lib/parasign-open-api.js emitEvent). P10
// API-19-C and API-19-J of the fase-1 matrix: every event used to be ONE
// fire-and-forget POST, so a receiver that blinked lost it for good, and
// signer.completed and envelope.completed raced each other with nothing in the
// body to restore the order. This suite drives emitEvent with a fake
// transport and no waiting (webhookRetryDelaysMs = [0, 0]) and checks:
//   * a network error or a 5xx/429 is retried, three attempts in all, with the
//     SAME body, signature and X-Paramant-Delivery, and X-Paramant-Attempt 1..3;
//   * any other answer (here a 400) ends it after one attempt;
//   * the events of one envelope go out one after another, in order, even when
//     the first needs its retries;
//   * every body carries seq: sent 1, signer.completed 1+signed_count,
//     completed/voided party_count+2.
// Pure JS: no relay, no redis, no engine.

const assert = require('assert');
const crypto = require('crypto');
const openApi = require('../lib/parasign-open-api');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

function deps(answers) {
  const calls = [];
  const secret = crypto.randomBytes(16).toString('hex');
  const d = {
    J: JSON.stringify,
    log: () => {},
    webhookRetryDelaysMs: [0, 0],
    // The lib unrefs its retry timer; a ref'd one here keeps this script alive
    // between attempts (otherwise node exits 0 halfway, without a word).
    webhookSleep: (ms) => new Promise((r) => setTimeout(r, ms)),
    store: { async getMeta() { return { webhook_url: 'https://hooks.example.test/x', webhook_secret: secret, metadata: {} }; } },
    async safeHttpsRequest(url, o) {
      calls.push({ event: o.headers['X-Paramant-Event'], attempt: o.headers['X-Paramant-Attempt'], delivery: o.headers['X-Paramant-Delivery'], sig: o.headers['X-Paramant-Sig'], body: o.body });
      const a = answers.length ? answers.shift() : 200;
      if (a === 'neterr') { const e = new Error('ECONNRESET'); e.code = 'ECONNRESET'; throw e; }
      await new Promise((r) => setTimeout(r, 2));
      return { status: a };
    },
  };
  return { d, calls, secret };
}

async function main() {
  // 1. retry on network error and 5xx, then success; same delivery and body.
  {
    const { d, calls, secret } = deps(['neterr', 503, 200]);
    const r = await openApi.emitEvent(d, 'env_retry_1', 'envelope.sent', { status: 'sent', signer_count: 1 });
    assert.strictEqual(calls.length, 3, 'three attempts: network error, 503, 200');
    assert.deepStrictEqual(calls.map((c) => c.attempt), ['1', '2', '3']);
    assert.strictEqual(new Set(calls.map((c) => c.delivery)).size, 1, 'one X-Paramant-Delivery for every attempt');
    assert.strictEqual(new Set(calls.map((c) => c.body)).size, 1, 'the same body every attempt');
    for (const c of calls) assert.strictEqual(c.sig, crypto.createHmac('sha256', secret).update(c.body).digest('hex'));
    assert.strictEqual(r.ok, true);
    assert.strictEqual(r.attempts, 3);
    ok('a failed delivery is retried with the same body, signature and delivery id');
  }
  // 2. gives up after three; a 4xx ends it at once.
  {
    const { d, calls } = deps([500, 500, 500, 500]);
    const r = await openApi.emitEvent(d, 'env_retry_2', 'envelope.sent', { signer_count: 1 });
    assert.strictEqual(calls.length, 3, 'three attempts in all, no fourth');
    assert.strictEqual(r.ok, false);
    const b = deps([400]);
    await openApi.emitEvent(b.d, 'env_retry_3', 'envelope.sent', { signer_count: 1 });
    assert.strictEqual(b.calls.length, 1, 'a 400 is an answer and is not retried');
    ok('three attempts at most, and a 4xx is not retried');
  }
  // 3. order per envelope, and seq.
  {
    const { d, calls } = deps(['neterr', 200]);   // the first event needs a retry
    const p1 = openApi.emitEvent(d, 'env_order', 'signer.completed', { party_index: 0, signed_count: 1, party_count: 2 });
    const p2 = openApi.emitEvent(d, 'env_order', 'signer.completed', { party_index: 1, signed_count: 2, party_count: 2 });
    const p3 = openApi.emitEvent(d, 'env_order', 'envelope.completed', { status: 'completed', signed_count: 2, party_count: 2 });
    await Promise.all([p1, p2, p3]);
    const seen = calls.map((c) => JSON.parse(c.body)).map((b) => `${b.event}:${b.seq}`);
    assert.deepStrictEqual(seen, ['signer.completed:2', 'signer.completed:2', 'signer.completed:3', 'envelope.completed:4'],
      'the second event waits for the first one\'s retry; seq rises');
    assert.strictEqual(openApi.webhookSeq('envelope.sent', {}), 1);
    assert.strictEqual(openApi.webhookSeq('envelope.voided', { party_count: 3 }), 5);
    ok('events of one envelope go out in order and carry seq');
  }
  console.log(`# parasign-webhook-delivery: ${passed} checks passed`);
}

main().catch((e) => { console.error('\nFAILED:', e && e.stack || e); process.exit(1); });
