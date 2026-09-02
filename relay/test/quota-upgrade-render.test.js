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
const tiers = require('../lib/tiers');
const ent = require('../lib/entitlements');

const src = fs.readFileSync(path.join(__dirname, '..', '..', 'frontend', 'js', 'quota-upgrade.js'), 'utf8');
const sandbox = { window: {}, document: { addEventListener() {} } };
vm.runInNewContext(src, sandbox);
const q = sandbox.window.paQuotaUpgrade;

// The false "No cap, no block" claim must be gone from the source entirely.
assert(!src.includes('No cap, no block'), 'No cap, no block must be gone from quota-upgrade.js');

// And nothing in this file may promise anything unlimited. tiers.js gives every
// metered tier a finite transfers_month and entitlements.js caps even
// enterprise at ENTERPRISE_MONTHLY_CEILING, so a card that renders the word is
// selling a ceiling that does not exist. The ParaSign Pro pitch said
// "Unlimited transfers" while a Pro account is held to 500 a month. The word is
// banned site-wide next to "transfers" by tests/ui-truthfulness.test.mjs; here
// it is banned outright, comments included, because there is nothing in a quota
// card that could honestly carry it.
assert(!/unlimited/i.test(src),
  'quota-upgrade.js must not use the word "unlimited": every tier it renders has a finite plafond');
// "a higher limit" was the other half of the same evasion: the card knew the
// number and printed a vague promise instead.
assert(!src.includes('a higher limit'),
  'the upgrade card must name the ceiling of the rung above, not promise "a higher limit"');

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

// ── Community sign 402: the upgrade card, copy verbatim ─────────────────────
const free = q.html({ error: 'monthly_sign_quota_reached', plan: 'free', limit: 2, used: 2, reset_date: '2026-08-01' });
for (const s of [
  "You've used both signatures this month.",
  'Community gives you 2 a month, with the same encryption, the same post-quantum signatures and the same public proof log as every paid plan. You never pay for security here. You pay for volume.',
  'Pro - EUR 49/month',
  '100 signatures a month, then EUR 0.40 each, up to 1,000. API access.',
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

// ── The transfer 402 card ───────────────────────────────────────────────────
const legacy = q.html({ error: 'monthly_transfer_quota_reached', dimension: 'transfers_month', plan: 'free', limit: 10 });
assert(legacy.includes('Community monthly limit reached.'), 'transfer 402 keeps the legacy notice');
assert(legacy.includes('ParaSend Pro'), 'transfer 402 keeps the ParaSend upgrade');
assert(legacy.includes('all 10 transfers'), 'transfer 402 keeps the limit interpolation');
ok('transfer 402 falls back to the existing notice');

// ── Every ceiling the cards print is the one tiers.js/entitlements.js enforce ─
//
// The numbers are baked into frontend/js/quota-upgrade.js because it is a plain
// browser script that cannot require the relay module. This block is what makes
// that safe: it renders the real cards and compares each figure against the two
// modules the relay gates on, so a tier edit that does not reach the frontend
// turns red here instead of shipping a card that promises the old number.
// The ParaSign Pro pitch names NO transfer figure, and that is the point of the
// negative pin. It used to say "Unlimited transfers", which is false for every
// tier. Replacing it with 500 would have been false too, for a sharper reason:
// transfers are a ParaSEND capacity held on plan_parasend, and the grant behind
// this card (applyProductTier(acct,'parasign','pro'), the Mollie ParaSign Pro
// purchase) deliberately never touches that field. So a ParaSign Pro buyer
// keeps whatever ParaSend tier he already had.
//
// relay/test/parasign-pro-perks.test.js is the source, and it is READ here
// rather than restated, so the day a ParaSend entitlement IS bundled into
// ParaSign Pro this pin lifts itself instead of holding a true line off the
// card. Until then: no transfers number in a ParaSign pitch.
const parasignProSend = (() => {
  const acct = { key: 'k', account_id: 'k', plan: 'community', plan_parasend: 'community', plan_parasign: 'free' };
  ent.applyProductTier(acct, 'parasign', 'pro');
  return ent.getEntitlements(acct).parasend.quotas.transfers_month;
})();
if (parasignProSend === ent.PARASEND.pro.quotas.transfers_month) {
  assert(/transfers/i.test(free),
    'a parasign=pro grant now DOES deliver the ParaSend Pro transfers ceiling, so the Pro pitch may state it');
} else {
  assert(!/transfers/i.test(free),
    'the ParaSign Pro pitch names a transfers figure, but a parasign=pro grant leaves ParaSend at ' +
    parasignProSend + ' a month (see relay/test/parasign-pro-perks.test.js). Bundle the entitlement or drop the line.');
}
ok('the ParaSign Pro pitch claims no transfers ceiling the grant does not deliver');

// Per deciding tier: the header names THAT tier and the body its ceiling. The
// 402 body carries both since #361 (relay.js reports _psend.tier and its
// quotas.transfers_month, not the account's unified plan), and the card used to
// print "Community" and an upsell to Pro whoever was looking at it.
for (const [plan, tier, label] of [
  ['free', 'community', 'Community'],
  ['community', 'community', 'Community'],
  ['pro', 'pro', 'Pro'],
  ['business', 'business', 'Business'],
  ['enterprise', 'enterprise', 'Enterprise'],
]) {
  const limit = ent.PARASEND[tier].quotas.transfers_month;
  assert(Number.isFinite(limit), tier + ' must have a finite transfers ceiling');
  const card = q.html({ error: 'monthly_transfer_quota_reached', dimension: 'transfers_month', plan, limit });
  assert(card.includes(label + ' monthly limit reached.'),
    'the transfer 402 card must name the tier that decided (' + plan + ' -> ' + label + ')');
  assert(card.includes('You have used all ' + limit + ' transfers included in your plan this month.'),
    'the transfer 402 card must print the deciding tier ceiling (' + tier + ' = ' + limit + ')');
  // Only the tier below Pro is offered an upgrade; a Pro account is not sold Pro.
  if (tier === 'community') {
    assert(card.includes('Upgrade to ParaSend Pro (EUR 15/month excl. VAT) for ' +
      tiers.tierLimit('pro', 'transfers_month') + ' transfers a month'),
      'the Community transfer card must name the ParaSend Pro ceiling from tiers.js');
  } else {
    assert(!card.includes('Upgrade to'), tier + ' must not be upsold the tier it already has');
    assert(card.includes('Your quota resets next month.'), tier + ' still learns when the quota resets');
  }
}
ok('transfer 402 card: tier label, ceiling and upsell all come from tiers.js/entitlements.js');

// A backend older than #361 sends no limit; the card falls back to the table and
// the table is the same tiers.js number.
const noLimit = q.html({ error: 'monthly_transfer_quota_reached', dimension: 'transfers_month', plan: 'pro' });
assert(noLimit.includes('all ' + tiers.tierLimit('pro', 'transfers_month') + ' transfers'),
  'a 402 without a limit falls back to the tiers.js ceiling of the reported tier');
ok('missing limit falls back to the tiers.js ceiling, not to Community');

// ── signNotice: the inline 200-response notices ─────────────────────────────
const second = q.signNotice({ used: 2, included: 2, overage_count: 0, overage_rate_eur: null, hard_cap: null, reset_date: '2026-08-01' });
assert(second.includes("That's your second signature this month. One more and you'll need Pro (EUR 49/month, 100 signatures)."),
  'free second-signature notice must carry the copy verbatim');
ok('free second signature renders the inline notice verbatim');

const over = q.signNotice({ used: 101, included: 100, overage_count: 1, overage_rate_eur: 0.4, hard_cap: 1000, reset_date: '2026-08-01' });
for (const s of [
  "You've passed 100 signatures this month. Everything keeps working. Additional signatures are EUR 0.40 each and appear on your next invoice, up to 1,000 a month.",
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
