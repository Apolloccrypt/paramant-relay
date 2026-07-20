'use strict';
// The quota/upgrade renderer (frontend/js/quota-upgrade.js) is a plain browser
// IIFE; load it in a vm sandbox with a stub window/document and test the pure
// render functions: the free 402 upgrade card, the pro hard-cap card, the
// legacy transfer notice, and the inline signNotice for the 200 quota block.
// Run: node relay/test/quota-upgrade-render.test.js (exits non-zero on failure).

const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const src = fs.readFileSync(path.join(__dirname, '..', '..', 'frontend', 'js', 'quota-upgrade.js'), 'utf8');
const sandbox = { window: {}, document: { addEventListener() {} } };
vm.runInNewContext(src, sandbox);
const q = sandbox.window.paQuotaUpgrade;

// The false "No cap, no block" claim must be gone from the source entirely.
assert(!src.includes('No cap, no block'), 'No cap, no block must be gone from quota-upgrade.js');

let passed = 0;
function ok(name) { passed++; console.log('  ok -', name); }

// What the client-side fallback computes (same recipe as the module).
function firstOfNextMonth() {
  const now = new Date();
  const next = new Date(now.getFullYear(), now.getMonth() + 1, 1);
  return next.getFullYear() + '-' + String(next.getMonth() + 1).padStart(2, '0') + '-01';
}

// ── isQuota402 ───────────────────────────────────────────────────────────────
assert(q && typeof q.isQuota402 === 'function' && typeof q.html === 'function' && typeof q.signNotice === 'function');
assert(q.isQuota402(402, { error: 'monthly_sign_quota_reached' }));
assert(q.isQuota402(402, { error: 'monthly_sign_hard_cap_reached' }));
assert(q.isQuota402(402, { error: 'monthly_transfer_quota_reached' }));
assert(!q.isQuota402(402, { error: 'something_else' }));
assert(!q.isQuota402(200, { error: 'monthly_sign_quota_reached' }));
assert(!q.isQuota402(402, null));
ok('isQuota402 accepts the three quota errors and nothing else');

// ── Free sign 402: the upgrade card, copy verbatim ──────────────────────────
const free = q.html({ error: 'monthly_sign_quota_reached', plan: 'free', limit: 2, used: 2, reset_date: '2026-08-01' });
for (const s of [
  "You've used both signatures this month.",
  'Free gives you 2 per month, with the same encryption, the same post-quantum signatures and the same public proof log as every paid plan. You never pay for security here. You pay for volume.',
  'Pro - EUR 49/month',
  '100 signatures per month, then EUR 0.40 each, up to 1,000. Unlimited transfers. API access.',
  'Upgrade to Pro',
  'Maybe later',
  'Your limit resets on 2026-08-01.',
]) {
  assert(free.includes(s), 'free 402 card misses: ' + s);
}
assert(free.includes('href="/pricing"'), 'Upgrade to Pro must link to /pricing');
assert(free.includes('data-pa-quota-dismiss'), 'Maybe later must be dismissable');
ok('free 402 renders the upgrade card with the copy verbatim');

// Missing/garbled reset_date falls back to the first of next month.
const freeNoDate = q.html({ error: 'monthly_sign_quota_reached', plan: 'free', limit: 2 });
assert(freeNoDate.includes('Your limit resets on ' + firstOfNextMonth() + '.'),
  'missing reset_date must fall back to the first of next month');
const freeBadDate = q.html({ error: 'monthly_sign_quota_reached', plan: 'free', limit: 2, reset_date: '<img>' });
assert(freeBadDate.includes('Your limit resets on ' + firstOfNextMonth() + '.'),
  'non-date reset_date must fall back, never be interpolated');
assert(!freeBadDate.includes('<img>'), 'reset_date must be shape-validated before interpolation');
ok('reset_date falls back client-side and is never interpolated raw');

// ── Pro hard cap 402 ────────────────────────────────────────────────────────
const cap = q.html({ error: 'monthly_sign_hard_cap_reached', plan: 'pro', limit: 1000, overage_count: 900, reset_date: '2026-08-01' });
assert(cap.includes('1,000 signatures this month, the Pro ceiling'), 'hard cap card names the Pro ceiling');
assert(cap.includes('Business gives you 1,000 included at EUR 299/month, which is already cheaper than what you\'re paying in overage.'), 'hard cap card pitches Business verbatim');
assert(cap.includes('Upgrade to Business') && cap.includes('href="/pricing"'), 'Upgrade to Business links to /pricing');
assert(!cap.includes('No cap, no block'), 'the false No cap, no block claim is gone');
ok('pro hard cap renders the upgrade card verbatim, linking to /pricing');

// ── Old backend: transfers keep the prior notice ────────────────────────────
const legacy = q.html({ error: 'monthly_transfer_quota_reached', dimension: 'transfers_month', plan: 'free', limit: 10 });
assert(legacy.includes('Free monthly limit reached.'), 'transfer 402 keeps the legacy notice');
assert(legacy.includes('ParaSend Pro'), 'transfer 402 keeps the ParaSend upgrade');
assert(legacy.includes('all 10 transfers'), 'transfer 402 keeps the limit interpolation');
ok('transfer 402 falls back to the existing notice');

// ── signNotice: the inline 200-response notices ─────────────────────────────
const second = q.signNotice({ used: 2, included: 2, overage_count: 0, overage_rate_eur: null, hard_cap: null, reset_date: '2026-08-01' });
assert(second.includes("That's your second signature this month. One more and you'll need Pro (EUR 49/month, 100 signatures)."),
  'free second-signature notice must carry the copy verbatim');
ok('free second signature renders the inline notice verbatim');

const over = q.signNotice({ used: 101, included: 100, overage_count: 1, overage_rate_eur: 0.4, hard_cap: 1000, reset_date: '2026-08-01' });
for (const s of [
  "You've passed 100 signatures this month. Everything keeps working. Additional signatures are EUR 0.40 each and appear on your next invoice, up to 1,000 per month.",
  'Signing more than 600 a month? Business (EUR 299) works out cheaper.',
  'Compare plans',
]) {
  assert(over.includes(s), 'pro overage notice misses: ' + s);
}
assert(over.includes('href="/pricing"'), 'Compare plans must link to /pricing');
ok('pro overage renders the inline notice verbatim, linking to /pricing');

// Nothing to say -> empty string (defensive against older backends and other plans).
assert.strictEqual(q.signNotice(undefined), '');
assert.strictEqual(q.signNotice({}), '');
assert.strictEqual(q.signNotice({ used: 1, included: 2 }), '');
assert.strictEqual(q.signNotice({ used: 2, included: 100 }), '', 'pro second signature must NOT trigger the free warning');
assert.strictEqual(q.signNotice({ used: 57, included: 100, overage_count: 0 }), '');
assert.strictEqual(q.signNotice({ used: 'x', included: 'y' }), '');
ok('signNotice stays silent on missing fields, other plans, and mid-quota signs');

console.log('quota-upgrade-render: ' + passed + ' checks passed');
