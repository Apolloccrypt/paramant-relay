'use strict';
// The rules a gift code is held to, without a relay and without a network.
//
// WHAT IS TESTED HERE AND WHAT IS NOT. This suite is the pure half: what a code
// may look like, what it may grant, how long a term runs when one is already
// running, and what the reader is told when the answer is no. The half that
// needs a real redis (the atomic claim, the hundred and first refusal, the
// route, the entitlements that follow) is relay/test/route-coupon.test.js,
// because a Lua script cannot be proved against a Map.
//
// The one rule worth stating twice: grantEnd is billing.extendFrom plus the
// days. A customer who paid for a year and then redeems a 90-day code must end
// up with a year and 90 days, not with 90 days. Handing a paying customer a
// SHORTER term than the one he bought is the only way a gift can cost him
// something, and it is the case a naive "now + days" gets wrong.
//
// Run: node --test relay/test/coupon.test.js

const { test, after } = require('node:test');
const assert = require('assert');
const coupon = require('../lib/coupon');
const entitlements = require('../lib/entitlements');
const { summary } = require('./_requires');

let checks = 0;
const did = () => { checks++; };
after(() => summary('coupon', checks));

// ── the code itself ──────────────────────────────────────────────────────────
test('a code is case-insensitive, and holds nothing a phone keyboard fights over', () => {
  for (const raw of ['coffee', 'COFFEE', ' Coffee ', 'CoFfEe']) {
    const r = coupon.normaliseCode(raw);
    assert.strictEqual(r.ok, true, `${JSON.stringify(raw)} must be a code`);
    assert.strictEqual(r.code, 'COFFEE', 'every spelling of one code has to be one code');
  }
  assert.strictEqual(coupon.normaliseCode('BMC-2026').code, 'BMC-2026', 'a dash is allowed');
  for (const bad of ['', '  ', 'AB', 'a'.repeat(33), 'COFFEE!', 'COF FEE', 'CAFÉ', 'COFFEE_1', null, undefined, 42, {}]) {
    assert.strictEqual(coupon.normaliseCode(bad).ok, false, `${JSON.stringify(bad)} is not a code`);
  }
  did();
});

// ── what it may grant ────────────────────────────────────────────────────────
test('the default campaign is both products on Pro for ninety days', () => {
  const g = coupon.validateGrants(coupon.DEFAULT_GRANTS);
  assert.strictEqual(g.ok, true);
  assert.deepStrictEqual(g.grants, [
    { product: 'parasign', tier: 'pro', days: 90 },
    { product: 'parasend', tier: 'pro', days: 90 },
  ]);
  assert.strictEqual(coupon.DEFAULT_MAX_REDEMPTIONS, 100, 'the campaign is the first hundred people');
  assert.strictEqual(coupon.describeGrants(g.grants), '3 months of ParaSign Pro and ParaSend Pro');
  did();
});

test('a grant is validated strictly, so a typo is a refusal and never a floor tier', () => {
  // The point of validateProductPlan over normalise*Tier: an unknown tier
  // FLOORS silently, which would mint a code that grants the plan the account
  // already has and looks like it worked.
  const cases = [
    [[{ product: 'parasignn', tier: 'pro', days: 90 }], 'invalid_product'],
    [[{ product: 'parasign', tier: 'platinum', days: 90 }], 'invalid_tier'],
    [[{ product: 'parasign', tier: 'free', days: 90 }], 'floor_tier'],
    [[{ product: 'parasend', tier: 'community', days: 90 }], 'floor_tier'],
    [[{ product: 'parasign', tier: 'pro', days: 0 }], 'bad_days'],
    [[{ product: 'parasign', tier: 'pro', days: -1 }], 'bad_days'],
    [[{ product: 'parasign', tier: 'pro', days: coupon.MAX_DAYS + 1 }], 'bad_days'],
    [[{ product: 'parasign', tier: 'pro', days: 90 }, { product: 'parasign', tier: 'business', days: 90 }], 'duplicate_product'],
    [[{ product: 'parasign', tier: 'pro', days: 90 }, { product: 'parasend', tier: 'pro', days: 30 }], 'mixed_days'],
    [[], 'no_grants'],
    ['nonsense', 'no_grants'],
  ];
  for (const [input, error] of cases) {
    const r = coupon.validateGrants(input);
    assert.strictEqual(r.ok, false, `${JSON.stringify(input)} must be refused`);
    assert.strictEqual(r.error, error, `${JSON.stringify(input)} -> ${r.error}, expected ${error}`);
  }
  // A tier that IS on the ladder passes, for both products, so the strictness
  // above is not simply "everything is refused".
  for (const tier of entitlements.PARASIGN_TIERS.filter((t) => t !== 'free')) {
    assert.strictEqual(coupon.validateGrants([{ product: 'parasign', tier, days: 30 }]).ok, true, `parasign ${tier} is sellable and giftable`);
  }
  did();
});

test('a cap is a real number: no code is unbounded, and none is zero', () => {
  assert.strictEqual(coupon.validateMax(undefined).max, coupon.DEFAULT_MAX_REDEMPTIONS);
  assert.strictEqual(coupon.validateMax(1).max, 1);
  assert.strictEqual(coupon.validateMax(100).max, 100);
  for (const bad of [0, -1, 'many', Infinity, NaN, coupon.MAX_REDEMPTIONS_CEILING + 1]) {
    assert.strictEqual(coupon.validateMax(bad).ok, false, `${bad} is not a cap`);
  }
  did();
});

test('an end date is optional, but a date we cannot read is refused rather than assumed', () => {
  assert.deepStrictEqual(coupon.validateValidUntil(undefined), { ok: true, ms: 0, iso: null });
  assert.deepStrictEqual(coupon.validateValidUntil(''), { ok: true, ms: 0, iso: null });
  const v = coupon.validateValidUntil('2026-12-31T23:59:59Z');
  assert.strictEqual(v.ok, true);
  assert.strictEqual(v.iso, '2026-12-31T23:59:59.000Z');
  assert.strictEqual(coupon.validateValidUntil('next christmas').ok, false,
    'an unreadable end date must not silently become "no end date"');
  did();
});

// ── the term ─────────────────────────────────────────────────────────────────
test('a gift is ADDED to a running term, never substituted for it', () => {
  const now = new Date('2026-09-04T00:00:00Z');

  // No term on file: the ninety days start now.
  assert.strictEqual(coupon.grantEnd(null, now, 90).toISOString(), '2026-12-03T00:00:00.000Z');

  // A term that is still running: the gift starts where that term ENDS. This is
  // the case that matters. A customer who paid for a year on 1 June and redeems
  // on 4 September must not be moved back to December.
  assert.strictEqual(coupon.grantEnd('2027-06-01T00:00:00Z', now, 90).toISOString(), '2027-08-30T00:00:00.000Z');

  // A term that has already lapsed is not a base: the gap is not retroactively
  // covered, so the ninety days start now, exactly as billing.extendFrom does
  // for a late renewal.
  assert.strictEqual(coupon.grantEnd('2026-01-01T00:00:00Z', now, 90).toISOString(), '2026-12-03T00:00:00.000Z');

  // An unreadable date on file is treated as no date, never as a date in the
  // past that would shorten the gift and never as one in the future.
  assert.strictEqual(coupon.grantEnd('not a date', now, 90).toISOString(), '2026-12-03T00:00:00.000Z');

  // The gift is never shorter than the days it promises, whatever is on file.
  for (const current of [null, '2026-01-01T00:00:00Z', '2027-06-01T00:00:00Z', '2030-01-01T00:00:00Z']) {
    const end = coupon.grantEnd(current, now, 90).getTime();
    assert.ok(end - now.getTime() >= 90 * 86400000,
      `a gift on top of ${current} came out shorter than the ninety days it promises`);
  }
  did();
});

// ── the words ────────────────────────────────────────────────────────────────
test('a duration is stated the way it was promised, and never rounded into a lie', () => {
  assert.strictEqual(coupon.humanDuration(90), '3 months');
  assert.strictEqual(coupon.humanDuration(30), '1 month');
  assert.strictEqual(coupon.humanDuration(365), '1 year');
  assert.strictEqual(coupon.humanDuration(730), '2 years');
  assert.strictEqual(coupon.humanDuration(45), '45 days');
  assert.strictEqual(coupon.humanDuration(1), '1 day');
  did();
});

test('the billing-history line names the code and what it gave', () => {
  const label = coupon.historyLabel('COFFEE', coupon.DEFAULT_GRANTS);
  assert.strictEqual(label, 'Gift: 3 months of ParaSign Pro and ParaSend Pro, code COFFEE');
  // A single-product code reads as one plan, not as a list of one.
  assert.strictEqual(
    coupon.historyLabel('SOLO', [{ product: 'parasign', tier: 'business', days: 365 }]),
    'Gift: 1 year of ParaSign Business, code SOLO');
  did();
});

test('every refusal is a sentence somebody can act on, never a code to look up', () => {
  for (const error of ['unknown', 'bad_code', 'revoked', 'expired', 'already_used', 'exhausted', 'no_redis', 'grant_failed']) {
    const msg = coupon.messageFor(error);
    assert.ok(msg && msg.length > 20, `${error} has no readable message`);
    assert.ok(/[.!?]$/.test(msg), `${error}: "${msg}" is not a finished sentence`);
    assert.ok(!/[_:]/.test(msg), `${error}: "${msg}" leaks a machine string to the reader`);
    assert.ok(!/\u2014/.test(msg), 'no em-dashes on this site');
  }
  // An error nobody thought of still gets a sentence rather than "undefined".
  assert.strictEqual(coupon.messageFor('something_new'), coupon.MESSAGES.unknown);
  did();
});

test('the success sentence names the plans, the dates, and that nothing was charged', () => {
  const msg = coupon.successMessage([
    { product: 'parasign', tier: 'pro', ends: '2026-12-03T00:00:00Z' },
    { product: 'parasend', tier: 'pro', ends: '2026-12-03T00:00:00Z' },
  ]);
  assert.ok(msg.includes('ParaSign Pro until 3 December 2026'), msg);
  assert.ok(msg.includes('ParaSend Pro until 3 December 2026'), msg);
  assert.ok(msg.includes('Nothing was charged'), msg);
  assert.ok(!/\u2014/.test(msg), 'no em-dashes on this site');
  did();
});

test('the confirmation mail says what was given and that no money moved', () => {
  const msg = coupon.redeemMail({
    code: 'COFFEE',
    grants: [{ product: 'parasign', tier: 'pro', days: 90, ends: '2026-12-03T00:00:00Z' }],
    siteUrl: 'https://paramant.app',
  });
  assert.ok(msg, 'a mail must be built for a real grant');
  assert.strictEqual(msg.subject, 'Your code COFFEE is redeemed');
  assert.ok(msg.text.includes('ParaSign Pro until 3 December 2026'), msg.text);
  assert.ok(msg.text.includes('Nothing was charged and nothing will be.'), msg.text);
  // It is not a subscription mail. The reader must not be left looking for
  // something to cancel.
  assert.ok(msg.text.includes('not a subscription'), msg.text);
  assert.ok(msg.html.includes('<h1'), 'the html half must be a document, not the text again');
  assert.ok(!/\u2014/.test(msg.text) && !/\u2014/.test(msg.html), 'no em-dashes on this site');
  // Nothing to send when nothing was granted.
  assert.strictEqual(coupon.redeemMail({ code: 'X', grants: [] }), null);
  did();
});

// ── the shape of the thing that must not drift ───────────────────────────────
test('the claim is one script, and everything it decides on is read inside it', () => {
  // A JavaScript claim reads the count, decides, and writes, and two requests
  // that read the same 99 both write a hundredth seat. So the whole decision
  // has to be inside the script redis runs to completion. If a check ever moves
  // out of it, this goes red before the hundred and first customer notices.
  const lua = coupon.CLAIM_LUA;
  for (const must of ['max_redemptions', 'revoked_at', 'valid_until_ms', 'HEXISTS', 'HLEN', 'HSET']) {
    assert.ok(lua.includes(must), `the claim script no longer reads ${must}; that decision moved out of the atomic step`);
  }
  for (const status of ['unknown', 'revoked', 'expired', 'already_used', 'exhausted', 'ok']) {
    assert.ok(lua.includes(`'${status}'`), `the claim script no longer answers ${status}`);
  }
  did();
});
