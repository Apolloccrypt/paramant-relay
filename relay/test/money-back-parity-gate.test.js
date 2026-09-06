'use strict';
// THE MONEY-BACK PARITY GATE. If the document layer says money went back, the
// entitlement layer may not leave a paid tier standing.
//
// WHY THIS EXISTS. The 2026-09-05 hostile review filed "a refund does not take
// the entitlement back" as a loose end, and read it as a deliberate policy on a
// fall-through branch. Both halves were wrong in an instructive way, and the
// instructive part is the class:
//
//   relay/lib/credit-note.js decided "is this money back?" by reading BOTH
//   cumulative counters (amountRefunded, amountChargedBack) as well as the
//   status string. relay/lib/billing.js decided the same question by matching
//   the status string against exactly two values. Two lists that must agree,
//   drifted.
//
// The consequence was not the missing branch the review described. Mollie
// reports a refund on the SAME tr_ id with the status still 'paid' and
// amountRefunded set (see tests/helpers/fake-mollie.cjs /_ctl/refund), so a
// refund never reached a fall-through at all: it went down the GRANT branch,
// and the only thing between a refunded payment and a fresh month granted on it
// was the idempotency marker.
//
// So this gate does not assert "refunded revokes". That catches the case. It
// drives BOTH layers with the same generated matrix of payment shapes and
// asserts they never disagree about whether money went back. A new Mollie
// status, or a fourth counter, is then a red on arrival instead of a finding
// in the next review.
//
// THE PROPERTY
//   For every payment shape:
//     creditNote.isReversal(p) === true   =>   processPayment(p) must NOT
//                                              return 'granted'
//   and, one step sharper:
//     the reversal is WHOLE                =>  processPayment(p) must return
//                                              'revoked' and floor every product
//                                              in the order.
//
// A part-reversal is allowed to be 'ignored': it is not a cancelled sale. What
// it may never be is 'granted'.
//
// Runs anywhere: no redis, no engine, pure function calls.

const { test } = require('node:test');
const assert = require('assert');

const billing = require('../lib/billing');
const creditNote = require('../lib/credit-note');
const catalog = require('../lib/billing-catalog');

// Every status the webhook can see. The first six are Mollie's payment
// lifecycle, the last three are the money-back shapes. 'authorized' is in here
// on purpose: it is a real Mollie status that the source comment in billing.js
// forgot to list, which is the same drift this gate exists to catch.
const STATUSES = [
  'open', 'pending', 'authorized', 'paid',
  'failed', 'expired', 'canceled',
  'refunded', 'chargeback', 'charged_back',
];

// absent / part / whole, for each of the two cumulative counters.
const COUNTERS = [null, '5.00', '59.29'];

// The catalog price for parasign/pro/monthly. Read from the catalog rather than
// typed, so a price change does not turn this gate into a study of the
// amount_mismatch branch instead of the money-back branch.
const PRICE = catalog.resolveOrder({ product: 'parasign', plan: 'pro', interval: 'monthly' }).amount;

function shape(status, refunded, back) {
  const p = {
    id: 'tr_gate',
    status,
    amount: { currency: 'EUR', value: PRICE },
    metadata: { accountId: 'acct_demo', product: 'parasign', plan: 'pro', interval: 'monthly' },
  };
  if (refunded) p.amountRefunded = { currency: 'EUR', value: refunded };
  if (back) p.amountChargedBack = { currency: 'EUR', value: back };
  return p;
}

function label(p) {
  const r = p.amountRefunded ? p.amountRefunded.value : '-';
  const c = p.amountChargedBack ? p.amountChargedBack.value : '-';
  return `${p.status} refunded=${r} chargedBack=${c}`;
}

// A deps stub that records what the decision actually did, so the assertion can
// look at the effect and not only at the returned word.
function deps() {
  const calls = [];
  return {
    calls,
    setProductPlan: (accountId, product, tier, until) => {
      calls.push({ accountId, product, tier, until: until ? until.toISOString() : null });
      return { ok: true };
    },
    // No marker: idempotency must not be what makes this gate pass. That was
    // the load-bearing accident being fixed.
  };
}

const MATRIX = [];
for (const status of STATUSES) {
  for (const refunded of COUNTERS) {
    for (const back of COUNTERS) MATRIX.push(shape(status, refunded, back));
  }
}

test('the matrix is the size it claims to be', () => {
  assert.strictEqual(MATRIX.length, STATUSES.length * COUNTERS.length * COUNTERS.length);
  assert.strictEqual(MATRIX.length, 90);
});

test('a payment the document layer credits is never granted an entitlement', async () => {
  const offenders = [];
  for (const p of MATRIX) {
    if (!creditNote.isReversal(p)) continue;
    const d = deps();
    const out = await billing.processPayment(p, d);
    if (out.result === 'granted') offenders.push(`${label(p)} -> granted (${out.reason})`);
    // The effect, not only the word: nothing may be moved UP while money is out.
    const raised = d.calls.filter((c) => c.tier !== catalog.floorTier(c.product));
    if (raised.length) offenders.push(`${label(p)} -> raised ${JSON.stringify(raised)}`);
  }
  assert.deepStrictEqual(offenders, [], `credit note issued but entitlement kept or granted:\n${offenders.join('\n')}`);
});

test('a WHOLE reversal floors every product in the order, with no paid time left', async () => {
  const offenders = [];
  for (const p of MATRIX) {
    const rev = billing.reversalOf(p);
    if (!rev || !rev.full) continue;
    const d = deps();
    const out = await billing.processPayment(p, d);
    if (out.result !== 'revoked') { offenders.push(`${label(p)} -> ${out.result} (${out.reason})`); continue; }
    if (!d.calls.length) { offenders.push(`${label(p)} -> revoked but moved nothing`); continue; }
    for (const c of d.calls) {
      if (c.tier !== catalog.floorTier(c.product)) offenders.push(`${label(p)} -> ${c.product} left at ${c.tier}`);
      if (c.until !== null) offenders.push(`${label(p)} -> ${c.product} kept paid time until ${c.until}`);
    }
  }
  assert.deepStrictEqual(offenders, [], `whole reversal did not revoke:\n${offenders.join('\n')}`);
});

test('a chargeback stays whole whatever the counters say', () => {
  // The one direction this gate must NOT weaken. Before 2026-09-06 any
  // 'chargeback' status revoked outright, counters or no counters, and a
  // settlement that arrives with a partial amountChargedBack must not turn that
  // into a shrug.
  for (const back of COUNTERS) {
    for (const status of ['chargeback', 'charged_back']) {
      const rev = billing.reversalOf(shape(status, null, back));
      assert.ok(rev && rev.full, `${status} chargedBack=${back || '-'} read as partial`);
      assert.strictEqual(rev.kind, 'chargeback');
    }
  }
});

test('a part-refund grants nothing and revokes nothing', async () => {
  const d = deps();
  const out = await billing.processPayment(shape('paid', '5.00', null), d);
  assert.strictEqual(out.result, 'ignored');
  assert.match(out.reason, /^partial_refund:500_of_\d+$/);
  assert.deepStrictEqual(d.calls, [], 'a part-refund moved an entitlement');
});

test('an ordinary paid payment still grants, so the gate has not simply closed the door', async () => {
  const d = deps();
  const out = await billing.processPayment(shape('paid', null, null), d);
  assert.strictEqual(out.result, 'granted');
  assert.strictEqual(d.calls.length, 1);
  assert.strictEqual(d.calls[0].tier, 'pro');
});

// The gate must be able to go red. This proves the matrix actually exercises
// the branch, rather than passing because nothing in it is a reversal.
test('self-test: the matrix contains reversals, whole and partial, of both kinds', () => {
  const rev = MATRIX.map((p) => billing.reversalOf(p)).filter(Boolean);
  assert.ok(rev.length >= 60, `only ${rev.length} reversal shapes in the matrix`);
  assert.ok(rev.some((r) => r.full), 'no whole reversal in the matrix');
  assert.ok(rev.some((r) => !r.full), 'no partial reversal in the matrix');
  assert.ok(rev.some((r) => r.kind === 'refund'), 'no refund in the matrix');
  assert.ok(rev.some((r) => r.kind === 'chargeback'), 'no chargeback in the matrix');
  // And the layers agree on the count, which is the whole point.
  const byDoc = MATRIX.filter((p) => creditNote.isReversal(p)).length;
  assert.strictEqual(rev.length, byDoc, 'billing and credit-note disagree about how many shapes are money back');
});
