/* Paramant quota upgrade + sign-quota notices. Plain external script (CSP: no
 * inline JS); exposes window.paQuotaUpgrade for both classic scripts
 * (parashare) and modules (sign-flow, co-sign).
 *
 * 402 input (relay JSON, passed through by the admin proxy):
 *   free sign quota:  { error:'monthly_sign_quota_reached', plan, limit, used, reset_date }
 *   pro hard cap:     { error:'monthly_sign_hard_cap_reached', plan, limit, overage_count, reset_date }
 *   transfers:        { error:'monthly_transfer_quota_reached', dimension, plan, limit }
 *                     `plan`/`limit` are the tier that DECIDED and its ceiling
 *                     (relay.js, #361), not the account's unified plan.
 * 200 input (sign response): quota { used, included, overage_count,
 *   overage_rate_eur, hard_cap, reset_date } -> signNotice() renders the
 *   inline notices (free second signature, pro overage). Older backends send
 *   none of the new fields: the transfer notice keeps its prior rendering and
 *   signNotice returns ''.
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
  // These are TRANSFER numbers and they belong to a TRANSFER card. The ParaSign
  // Pro pitch below used to end by promising transfers with no cap, and the
  // honest version of that sentence is no sentence: transfers are a ParaSend
  // capacity on plan_parasend, and applyProductTier(acct,'parasign','pro')
  // deliberately never touches it, so a ParaSign Pro buyer keeps the ParaSend
  // tier he already had (10 a month for a free account). Naming 500 there would
  // have been as untrue as naming none. relay/test/parasign-pro-perks.test.js
  // is the source for that; relay/test/quota-upgrade-render.test.js pins the
  // pitch negatively against it.
  //
  // Baked in because this is a plain browser script with no way to require the
  // relay module. relay/test/quota-upgrade-render.test.js renders every card
  // and compares each number against tiers.js and entitlements.js, so a tier
  // edit that does not reach this file turns the suite red.
  var CEILINGS = {
    transfers_month: { community: 10, pro: 500, business: 2000, enterprise: 1000000 },
    signs_month:     { community: 2,  pro: 100, business: 1000, enterprise: 1000000 }
  };

  // The rung above the tier that decided, with the ceiling that rung carries
  // and the price /pricing lists for it (excl. btw, one basis for the whole
  // site). A tier with no entry gets no upsell: offering ParaSend Pro to a Pro
  // account is what a hardcoded upsell does, and since #361 the 402 says which
  // tier it was.
  var NEXT = {
    transfers_month: {
      community: { name: 'ParaSend Pro', price: 'EUR 15/month excl. VAT', limit: 500 }
    },
    signs_month: {
      community: { name: 'ParaSign Pro',      price: 'EUR 49/month excl. VAT', limit: 100 },
      pro:       { name: 'ParaSign Business', price: 'EUR 299/month excl. VAT', limit: 1000 }
    }
  };

  // The tier that DECIDED the 402, as the relay reports it. Since #361 the
  // monthly_transfer_quota_reached body carries `plan` = the ParaSend
  // entitlement tier and `limit` = that tier's ceiling, instead of the unified
  // account plan. The card printed "Community" whatever came back, so a Pro
  // account over its 500 was told it was on Community. Unknown or absent falls
  // back to community, which is what this card assumed unconditionally before.
  var PLAN_LABEL = {
    community: 'Community', free: 'Community', dev: 'Community',
    pro: 'Pro', business: 'Business', enterprise: 'Enterprise', licensed: 'Enterprise'
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
       data.error === 'monthly_sign_quota_reached' ||
       data.error === 'monthly_sign_hard_cap_reached');
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
      '<span><strong>Pro - EUR 49/month</strong><br>100 signatures a month, then EUR 0.40 each, up to 1,000. API access.</span>' +
      '<span class="pa-quota-actions">' +
        '<a class="btn btn-primary" href="/pricing">Upgrade to Pro</a>' +
        '<button type="button" class="btn btn-secondary" data-pa-quota-dismiss>Maybe later</button>' +
      '</span>' +
      '<span>Your limit resets on ' + resetDate(data) + '.</span>' +
      '</div>';
  }

  // Pro hard cap at 1,000, the Pro ceiling: the upgrade moment. Business includes 1,000.
  function hardCapHtml(data) {
    return '<div class="pa-quota-upsell pa-quota-card" role="status">' +
      '<strong>You\'ve reached 1,000 signatures this month, the Pro ceiling.</strong>' +
      '<span>Business gives you 1,000 included at EUR 299/month, which is already cheaper than what you\'re paying in overage.</span>' +
      '<span class="pa-quota-actions">' +
        '<a class="btn btn-primary" href="/pricing">Upgrade to Business</a>' +
      '</span>' +
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
    if (data && data.error === 'monthly_sign_hard_cap_reached') return hardCapHtml(data);
    if (data && data.error === 'monthly_sign_quota_reached' &&
        (data.plan === 'free' || data.plan == null)) return freeSignHtml(data);
    return legacyHtml(data);
  }

  // Inline notice after a SUCCESSFUL sign (200 quota block). Returns '' when
  // there is nothing to say or the fields are absent (older backend).
  // included distinguishes the plan (2 = free, 100 = pro) so a pro account's
  // second signature never triggers the free warning.
  function signNotice(quota) {
    if (!quota || typeof quota !== 'object') return '';
    var used = Number(quota.used);
    var included = Number(quota.included);
    if (!isFinite(used) || !isFinite(included)) return '';
    if (included === 2 && used === 2) {
      return '<div class="pa-sign-note" role="status">' +
        '<span>That\'s your second signature this month. One more and you\'ll need Pro (EUR 49/month, 100 signatures).</span>' +
        '</div>';
    }
    var over = Number(quota.overage_count);
    if (included === 100 && isFinite(over) && over >= 1) {
      return '<div class="pa-sign-note" role="status">' +
        '<span>You\'ve passed 100 signatures this month. Everything keeps working. Additional signatures are EUR 0.40 each and appear on your next invoice, up to 1,000 a month.</span>' +
        '<span>Signing more than 600 a month? Business (EUR 299) works out cheaper. <a href="/pricing">Compare plans</a></span>' +
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
