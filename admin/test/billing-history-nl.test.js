'use strict';
// The billing history on the Dutch /account, and the mail after "Plan opzeggen".
//
// Fase 1 (PLAN-19, PLAN-25) found three things a Dutch customer read wrong:
//
//   1. The cancellation sank to the bottom of the list, under older payments.
//      The audit half of GET /api/user/billing/history carries the number
//      logAuditEvent wrote (Date.now()), the relay half an ISO string, and the
//      sort used Date.parse on both. Date.parse of a number is NaN, so every
//      audit row sorted as if it had no date at all.
//   2. The audit rows had English labels only ("Cancellation scheduled").
//   3. The cancellation mail was English only, also for the Dutch page.
//
// The sort is lifted out of server.js and run, so the test exercises the
// shipped code and not a copy. The mail is the real template.
// Run: node --test admin/test/billing-history-nl.test.js

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const SERVER = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');

function liftHistoryTimeMs() {
  const m = SERVER.match(/function historyTimeMs\(ts\) \{[\s\S]*?\n\}/);
  assert.ok(m, 'admin/server.js must compare history rows on one clock (historyTimeMs)');
  return new Function(`${m[0]}; return historyTimeMs;`)();
}

function historyHandler() {
  const start = SERVER.indexOf('api.get("/user/billing/history"');
  assert.notEqual(start, -1, 'admin/server.js must serve GET /user/billing/history');
  const end = SERVER.indexOf('\napi.', start + 1);
  return SERVER.slice(start, end === -1 ? start + 4000 : end)
    .replace(/\/\*[\s\S]*?\*\//g, '').replace(/^[ \t]*\/\/.*$/gm, '');
}

test('a cancellation logged with a numeric ts sorts above older payments', () => {
  const historyTimeMs = liftHistoryTimeMs();
  const cancelledAt = Date.parse('2026-10-05T10:00:00Z');
  const rows = [
    { ts: '2026-10-05T09:00:00.000Z', type: 'invoice' },
    { ts: cancelledAt, type: 'plan_cancellation_scheduled' },
    { ts: '2026-10-04T09:00:00.000Z', type: 'credit_note' },
    { ts: String(cancelledAt - 86_400_000 * 2), type: 'plan_changed' },
  ];
  const sorted = rows.slice().sort((a, b) => historyTimeMs(b.ts) - historyTimeMs(a.ts)).map((r) => r.type);
  assert.deepStrictEqual(sorted, ['plan_cancellation_scheduled', 'invoice', 'credit_note', 'plan_changed']);
  assert.strictEqual(historyTimeMs('garbage'), 0, 'an unreadable ts sorts last, it does not throw');
});

test('the handler sorts on that clock and sends the audit ts as ISO', () => {
  const body = historyHandler();
  assert.match(body, /\.sort\(\(a, b\) => historyTimeMs\(b\.ts\) - historyTimeMs\(a\.ts\)\)/,
    'the merged list must be sorted on historyTimeMs, not on Date.parse');
  assert.doesNotMatch(body, /Date\.parse\(b\.ts\)/, 'Date.parse of a numeric audit ts is NaN');
  assert.match(body, /ts: ms \? new Date\(ms\)\.toISOString\(\) : e\.ts/,
    'an audit row goes out with an ISO ts like every relay row');
});

test('audit rows carry a Dutch label for the Dutch /account', () => {
  const m = SERVER.match(/const AUDIT_LABEL_NL = \{[\s\S]*?\n\};/);
  assert.ok(m, 'admin/server.js must hold Dutch labels for the audit rows');
  const labels = new Function(`${m[0]}; return AUDIT_LABEL_NL;`)();
  assert.strictEqual(labels.plan_cancellation_scheduled({}), 'Opzegging gepland');
  assert.strictEqual(labels.plan_changed({ from: 'community', to: 'pro' }), 'Plan gewijzigd van community naar pro');
  assert.strictEqual(labels.plan_downgraded({}), 'Plan verlaagd naar Community');
  assert.match(historyHandler(), /label_nl: labelNl \? labelNl\(meta\) : null/);
});

test('the cancellation mail is Dutch first, English below, with the date in both', () => {
  const tpl = require('../lib/email-templates');
  const msg = tpl.billingCancellationEmail({ planName: 'Firm', cancelDate: '5 December 2026', cancelDateNl: '5 december 2026' });
  assert.match(msg.subject, /^Uw Paramant-plan is opgezegd \/ Your Paramant plan has been cancelled$/);
  const nlAt = msg.text.indexOf('Stopt op: 5 december 2026');
  const enAt = msg.text.indexOf('Ends on: 5 December 2026');
  assert.ok(nlAt >= 0, 'the Dutch half names the Dutch date');
  assert.ok(enAt > nlAt, 'the English half follows the Dutch one');
  assert.match(msg.html, /Opzegging gepland/);
  assert.match(msg.html, /Cancellation scheduled/);
  assert.ok(!/\u2014/.test(msg.text), 'no em-dash in a customer mail');
});

test('the cancel route passes the Dutch date to the mail', () => {
  const m = SERVER.match(/async function sendCancellationScheduled[\s\S]*?\n\}/);
  assert.ok(m, 'sendCancellationScheduled must exist');
  assert.match(m[0], /toLocaleDateString\('nl-NL'/);
  assert.match(m[0], /billingCancellationEmail\(\{ planName, cancelDate, cancelDateNl \}\)/);
});
