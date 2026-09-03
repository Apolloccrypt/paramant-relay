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
  assert.match(body, /paid_until_parasign/,
    'access_until must be derived from the relay period, not from an unwritten Redis record');
  assert.match(body, /paid_until_parasend/,
    'both products carry a term, and the later one is the one access runs to');
  assert.match(body, /auto_renews:\s*false/,
    'every checkout is a one-off for its term, so the response must not imply a renewal');
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

test('the account page renders the term end and does not offer to cancel a one-off', () => {
  const js = fs.readFileSync(
    path.join(__dirname, '..', '..', 'frontend', 'js', 'account.inline1.js'), 'utf8');
  assert.match(js, /d\.access_until/,
    'the account page must read the term end the API now sends');
  assert.match(js, /if \(d\.auto_renews\) document\.getElementById\('billing-cancel-btn'\)/,
    'Cancel stops a next collection; with none scheduled there is nothing to cancel');

  const html = fs.readFileSync(
    path.join(__dirname, '..', '..', 'frontend', 'account.html'), 'utf8');
  assert.match(html, /Access until/, 'the row must name what the date is');
  assert.doesNotMatch(html, /Next billing date/,
    'nothing bills again by itself, so no row may promise a next billing date');
  assert.doesNotMatch(html, /renewal date and invoices are below/,
    'neither a renewal date nor an invoice is produced today');
});
