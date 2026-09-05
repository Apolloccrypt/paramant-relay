/* Paramant quota upgrade + sign-quota notices. Plain external script (CSP: no
 * inline JS); exposes window.paQuotaUpgrade for both classic scripts
 * (parashare) and modules (sign-flow, co-sign).
 *
 * 402 input (relay JSON, passed through by the admin proxy):
 *   sign quota:       { error:'monthly_sign_quota_reached', plan, limit, used, reset_date }
 *   transfers:        { error:'monthly_transfer_quota_reached', dimension, plan, limit }
 *                     `plan`/`limit` are the tier that DECIDED and its ceiling
 *                     (relay.js, #361), not the account's unified plan.
 * 200 input (sign response): quota { used, included, reset_date } ->
 *   signNotice() renders the inline notice when the last signature the plan
 *   includes has just been used. Older backends send none of these fields: the
 *   transfer notice keeps its prior rendering and signNotice returns ''.
 *
 * ONE sign 402, because there is one stop: the quota the plan includes. The
 * second, higher stop this file used to render (monthly_sign_hard_cap_reached
 * at 1,000 for Firm) belonged to a meter that charged EUR 0.40 a signature
 * above 100 and put it on the next invoice. No invoice ever carried that line,
 * so the meter is gone and so is the card that explained it.
 *
 * Prices shown excl. VAT and kept in ONE place here. This file only renders
 * the notices; the limits themselves live server-side and are unchanged. Every
 * ceiling it prints is mirrored from relay/lib/tiers.js (see CEILINGS below)
 * and pinned against it by relay/test/quota-upgrade-render.test.js. */
(function () {
  'use strict';

  var PRODUCTS = {
    transfers_month: { unit: 'transfers'  },
    signs_month:     { unit: 'signatures' }
  };

  // Every monthly ceiling this file prints, per dimension and per tier, copied
  // from relay/lib/tiers.js (transfers_month, signs_month) with the enterprise
  // row taking the finite plafond relay/lib/entitlements.js applies to a
  // metered dimension (ENTERPRISE_MONTHLY_CEILING). NO tier is unbounded, which
  // is why no card here may call a ceiling absent, and why the word itself is
  // banned from this file by the render test.
  //
  // These are TRANSFER numbers and they belong to a TRANSFER card. When the two
  // Pro plans were sold apart, the signing pitch could not promise transfers:
  // transfers are a ParaSend capacity on plan_parasend, and
  // applyProductTier(acct,'parasign','pro') never touched it, so a signing
  // buyer kept the ParaSend tier he already had. Firm removes that split by
  // paying for both products in one payment, which is why the card below may
  // name both ceilings. relay/test/quota-upgrade-render.test.js renders every
  // card and pins the numbers.
  //
  // Baked in because this is a plain browser script with no way to require the
  // relay module. relay/test/quota-upgrade-render.test.js renders every card
  // and compares each number against tiers.js and entitlements.js, so a tier
  // edit that does not reach this file turns the suite red.
  var CEILINGS = {
    transfers_month: { community: 50, pro: 500, business: 2000, enterprise: 1000000 },
    signs_month:     { community: 2,  pro: 100, business: 1000, enterprise: 1000000 }
  };

  // The rung above the tier that decided, with the ceiling that rung carries
  // and the price /pricing lists for it (excl. btw, one basis for the whole
  // site). A tier with no entry gets no upsell: offering Firm to an account
  // that already has it is what a hardcoded upsell does, and since #361 the 402
  // says which tier it was. Firm is one rung for both dimensions now: the two
  // separate Pro plans it replaced are off sale, and one payment lifts both
  // ceilings at once.
  var NEXT = {
    transfers_month: {
      community: { name: 'Firm', price: 'EUR 29/month excl. VAT', limit: 500 }
    },
    signs_month: {
      community: { name: 'Firm',              price: 'EUR 29/month excl. VAT', limit: 100 },
      pro:       { name: 'ParaSign Business', price: 'EUR 299/month excl. VAT', limit: 1000 }
    }
  };

  // The tier that DECIDED the 402, as the relay reports it. Since #361 the
  // monthly_transfer_quota_reached body carries `plan` = the ParaSend
  // entitlement tier and `limit` = that tier's ceiling, instead of the unified
  // account plan. The card printed "Community" whatever came back, so a Firm
  // account over its 500 was told it was on Community. Unknown or absent falls
  // back to community, which is what this card assumed unconditionally before.
  var PLAN_LABEL = {
    community: 'Community', free: 'Community', dev: 'Community',
    pro: 'Firm', business: 'Business', enterprise: 'Enterprise', licensed: 'Enterprise'
  };
  var PLAN_KEY = {
    community: 'community', free: 'community', dev: 'community',
    pro: 'pro', business: 'business', enterprise: 'enterprise', licensed: 'enterprise'
  };

  function planKey(data) {
    var v = data && typeof data.plan === 'string' ? data.plan.toLowerCase() : '';
    return PLAN_KEY[v] || 'community';
  }

  function isQuota402(status, data) {
    return status === 402 && !!data &&
      (data.error === 'monthly_transfer_quota_reached' ||
       data.error === 'monthly_sign_quota_reached');
  }

  // First day of the next month (client clock), the fallback when the 402 body
  // carries no usable reset_date (older backend).
  function firstOfNextMonth() {
    var now = new Date();
    var next = new Date(now.getFullYear(), now.getMonth() + 1, 1);
    var mm = String(next.getMonth() + 1);
    if (mm.length < 2) mm = '0' + mm;
    return next.getFullYear() + '-' + mm + '-01';
  }

  function resetDate(data) {
    var v = data && data.reset_date;
    return (typeof v === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(v)) ? v : firstOfNextMonth();
  }

  // All interpolated values are server-controlled and coerced (Number) or
  // validated (reset_date shape) -- no user input reaches this HTML.

  // Community plan, third signature blocked: the purchase moment.
  function freeSignHtml(data) {
    return '<div class="pa-quota-upsell pa-quota-card" role="status">' +
      '<strong>You\'ve used both signatures this month.</strong>' +
      '<span>Community gives you 2 a month, with the same encryption, the same post-quantum signatures and the same public proof log as every paid plan. You never pay for security here. You pay for volume.</span>' +
      '<span><strong>Firm - EUR 29/month</strong><br>100 signatures a month. API access. 500 transfers a month on ParaSend, in the same payment.</span>' +
      '<span class="pa-quota-actions">' +
        '<a class="btn btn-primary" href="/pricing">Upgrade to Firm</a>' +
        '<button type="button" class="btn btn-secondary" data-pa-quota-dismiss>Maybe later</button>' +
      '</span>' +
      '<span>Your limit resets on ' + resetDate(data) + '.</span>' +
      '</div>';
  }

  function legacyHtml(data) {
    var dim = (data && data.dimension) || 'transfers_month';
    if (!PRODUCTS[dim]) dim = 'transfers_month';
    var p = PRODUCTS[dim];
    var plan = planKey(data);
    // The 402 body's own limit first: that is the ceiling of the tier that
    // actually decided. The table is the fallback for a backend older than
    // #361, which sent no limit at all.
    var limit = data && isFinite(Number(data.limit)) ? Number(data.limit) : CEILINGS[dim][plan];
    var used = limit != null
      ? 'You have used all ' + limit + ' ' + p.unit + ' included in your plan this month.'
      : 'You have used all ' + p.unit + ' included in your plan this month.';
    // Name the ceiling of the rung above. The card used to promise a vaguely
    // higher one while the number was sitting right here; every tier has a
    // finite plafond, so it can say which one it is.
    var next = NEXT[dim][plan];
    var offer = next
      ? ' Upgrade to ' + next.name + ' (' + next.price + ') for ' + next.limit + ' ' +
        p.unit + ' a month, or wait until your quota resets next month.'
      : ' Your quota resets next month.';
    return '<div class="pa-quota-upsell" role="status">' +
      '<strong>' + PLAN_LABEL[plan] + ' monthly limit reached.</strong>' +
      '<span>' + used + offer + '</span>' +
      '<a class="btn btn-primary" href="/pricing">View plans</a>' +
      '</div>';
  }

  function html(data) {
    if (data && data.error === 'monthly_sign_quota_reached' &&
        (data.plan === 'free' || data.plan == null)) return freeSignHtml(data);
    return legacyHtml(data);
  }

  // Inline notice after a SUCCESSFUL sign (200 quota block). Returns '' when
  // there is nothing to say or the fields are absent (older backend).
  // included distinguishes the plan (2 = free, 100 = the paid floor) so a Firm
  // account's second signature never triggers the free warning.
  function signNotice(quota) {
    if (!quota || typeof quota !== 'object') return '';
    var used = Number(quota.used);
    var included = Number(quota.included);
    if (!isFinite(used) || !isFinite(included)) return '';
    if (included === 2 && used === 2) {
      return '<div class="pa-sign-note" role="status">' +
        '<span>That\'s your second signature this month. One more and you\'ll need Firm (EUR 29/month, 100 signatures).</span>' +
        '</div>';
    }
    // The last signature Firm includes. Said once, when it happens, so nobody
    // discovers the limit only by being stopped by it. It used to say the next
    // signature would cost EUR 0.40 on the next invoice; there is no such line
    // and no such invoice, so it now says what does happen: signing waits for
    // the new month, or for a bigger plan.
    if (included === 100 && used === 100) {
      return '<div class="pa-sign-note" role="status">' +
        '<span>That was the 100th signature your Firm plan includes this month. Signing starts again on ' + resetDate(quota) + '. Business (EUR 299/month) includes 1,000 a month. <a href="/pricing">Compare plans</a></span>' +
        '</div>';
    }
    return '';
  }

  // "Maybe later": remove the card. Delegated so it works wherever callers
  // inject the HTML (innerHTML on status banners, CTA slots).
  if (typeof document !== 'undefined' && document.addEventListener) {
    document.addEventListener('click', function (ev) {
      var t = ev.target && ev.target.closest ? ev.target.closest('[data-pa-quota-dismiss]') : null;
      if (!t) return;
      var card = t.closest('.pa-quota-card');
      if (card && card.parentNode) card.parentNode.removeChild(card);
    });
  }

  window.paQuotaUpgrade = { isQuota402: isQuota402, html: html, signNotice: signNotice };
})();
