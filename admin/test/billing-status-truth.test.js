'use strict';
// What GET /api/user/billing/status tells a customer about his money.
//
// Two statements in that response body were untrue, and both were untrue in the
// direction that costs trust rather than money.
//
//   stub_notice: 'Payment integration pending. No real charges apply.'
//     Shipped from the days before Mollie. It was still being served to
//     customers whom Mollie had genuinely charged 59.29 euro. The frontend guard
//     that was supposed to catch this (tests/ui-truthfulness.test.mjs) reads
//     frontend/account.html, and the sentence does not live in the HTML; it
//     comes off the API, so nothing saw it.
//
//   next_billing_date: read from paramant:user:billing:<id>, a Redis record
//     that NOTHING in this repository ever writes. Every read got null, so the
//     row the account page promises ("Your plan, renewal date and invoices are
//     below") never rendered, and POST /user/billing/cancel fell through to its
//     `now + 30 days` default and told a customer who had paid for a YEAR that
//     his plan would be downgraded next month.
//
// The date that does exist is paid_until_* on the relay, the end of the term the
// payment actually bought, and it arrives here through productPlanFields().
// Every checkout is a one-off for that term (frontend/terms.html), so the
// response says access_until and auto_renews:false rather than inventing a
// collection date.
//
// Structural, like user-plan-fields.test.js and for the same reason: reaching
// this handler needs Redis, a session cookie and a live relay, while what goes
// wrong here is a sentence.
// Run: node --test admin/test/billing-status-truth.test.js

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const SERVER = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');

// The handler with its comments stripped. A comment is allowed to name the
// sentence that was removed and why; only the code may be asserted on.
function handlerOf2(route) {
  const start = SERVER.indexOf(`api.post("${route}"`);
  assert.notEqual(start, -1, `admin/server.js must serve POST ${route}`);
  const end = SERVER.indexOf('\napi.', start + 1);
  return SERVER.slice(start, end === -1 ? start + 4000 : end);
}

function handlerOf(route) {
  const start = SERVER.indexOf(`api.get("${route}"`);
  assert.notEqual(start, -1, `admin/server.js must serve GET ${route}`);
  const end = SERVER.indexOf('\napi.', start + 1);
  const body = SERVER.slice(start, end === -1 ? start + 4000 : end);
  return body.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^[ \t]*\/\/.*$/gm, '');
}

test('the billing status of a paying customer claims no stub and no free ride', () => {
  const body = handlerOf('/user/billing/status');
  assert.doesNotMatch(body, /stub_notice/,
    'the stub notice predates Mollie and is false for every customer who has paid');
  assert.doesNotMatch(body, /No real charges apply|integration pending/i,
    'no wording of "nothing was charged" may reach a customer who was charged');
});

test('the status reports the end of the term that was actually bought', () => {
  const body = handlerOf('/user/billing/status');
  assert.match(body, /access_until:/,
    'the response must carry the day access stops');
  assert.match(body, /access_until:\s*accessUntil/,
    'and it must be the computed term end, not a value from elsewhere');
  assert.match(body, /termEndOf\(/,
    'access_until must be derived from the relay period, not from an unwritten Redis record');
  // auto_renews used to be the literal `false`, and this line used to pin it
  // there: production bills one-off, so nothing renews. That is true only while
  // BILLING_MODE is empty. Set it and checkout opens a Mollie mandate AND a
  // subscription, and the account page went on telling the customer that
  // nothing would be collected again while Mollie collected. A page may not
  // answer this question from a constant; it has to read the account. What is
  // pinned now is the source, not the answer.
  assert.match(body, /auto_renews:\s*renews\b/,
    'auto_renews must come from the relay record, never from a hard-coded false');
  assert.match(body, /"main",\s*"\/v2\/admin\/keys\?reveal=1"/,
    'the subscription pointers are written by the webhook on relay-main, so that '
    + 'is the relay this has to ask; health has never seen them');

  // The derivation itself: both products carry a term, only a term still in the
  // future counts, and the later of the two is the one access runs to.
  const helper = /function termEndOf\(fields\) \{[\s\S]*?\n\}/.exec(SERVER);
  assert.ok(helper, 'admin/server.js must define termEndOf()');
  assert.match(helper[0], /paid_until_parasign/, 'the ParaSign term must count');
  assert.match(helper[0], /paid_until_parasend/, 'the ParaSend term must count');
  assert.match(helper[0], /Math\.max/, 'the later of the two terms is the one access runs to');
  assert.match(helper[0], /> Date\.now\(\)/, 'a term that has already passed grants nothing');
});

test('nothing reads a renewal date out of a record no code writes', () => {
  // The key may still be READ for compatibility, but it may never be the only
  // source of the date shown, which is what made the row invisible.
  const writes = SERVER.match(/redis\(\)\.set\(`paramant:user:billing:/g) || [];
  const reads = SERVER.match(/paramant:user:billing:/g) || [];
  if (reads.length > 0) {
    assert.equal(writes.length, 0,
      'paramant:user:billing: is read but never written; if that changes, this test should too');
  }
  const body = handlerOf('/user/billing/status');
  const accessLine = /access_until:\s*accessUntil/.test(body);
  assert.ok(accessLine, 'access_until must come from the computed term end');
});

test('cancel schedules on the term that was bought, not on a made-up month', () => {
  const body = handlerOf2('/user/billing/cancel');
  assert.match(body, /termEndOf\(productPlanFields\(/,
    'the downgrade date must come from the term the customer actually paid for');
  const fallback = body.indexOf('30 * 86_400_000');
  const real = body.indexOf('termEndOf(');
  assert.ok(real !== -1 && (fallback === -1 || real < fallback),
    'now plus 30 days may only ever be a last resort, never the first answer');
  // Both surfaces must answer with one derivation, or the page shows one date
  // and the cancel mail promises another.
  assert.match(handlerOf('/user/billing/status'), /termEndOf\(/,
    'status and cancel must share the same term-end helper');
});

test('the account page renders the term end', () => {
  const js = fs.readFileSync(
    path.join(__dirname, '..', '..', 'frontend', 'js', 'account.inline1.js'), 'utf8');
  assert.match(js, /d\.access_until/,
    'the account page must read the term end the API now sends');

  const html = fs.readFileSync(
    path.join(__dirname, '..', '..', 'frontend', 'account.html'), 'utf8');
  assert.match(html, /Access until/, 'the row must name what the date is');
  assert.doesNotMatch(html, /Next billing date/,
    'nothing bills again by itself, so no row may promise a next billing date');
  assert.doesNotMatch(html, /renewal date and invoices are below/,
    'neither a renewal date nor an invoice is produced today');
});
