/* Paramant quota upgrade + sign-quota notices. Plain external script (CSP: no
 * inline JS); exposes window.paQuotaUpgrade for both classic scripts
 * (parashare) and modules (sign-flow, co-sign).
 *
 * 402 input (relay JSON, passed through by the admin proxy):
 *   free sign quota:  { error:'monthly_sign_quota_reached', plan, limit, used, reset_date }
 *   pro hard cap:     { error:'monthly_sign_hard_cap_reached', plan, limit, overage_count, reset_date }
 *   transfers (as before): { error:'monthly_transfer_quota_reached', dimension, plan, limit }
 * 200 input (sign response): quota { used, included, overage_count,
 *   overage_rate_eur, hard_cap, reset_date } -> signNotice() renders the
 *   inline notices (free second signature, pro overage). Older backends send
 *   none of the new fields: the transfer notice keeps its prior rendering and
 *   signNotice returns ''.
 *
 * Prices shown excl. VAT and kept in ONE place here. This file only renders
 * the notices; the limits themselves live server-side and are unchanged. */
(function () {
  'use strict';

  var PRODUCTS = {
    transfers_month: { unit: 'transfers',  upgrade: 'ParaSend Pro', price: 'EUR 15/month excl. VAT' },
    signs_month:     { unit: 'signatures', upgrade: 'ParaSign Pro', price: 'EUR 49/month excl. VAT' }
  };

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

  // Free plan, third signature blocked: the purchase moment.
  function freeSignHtml(data) {
    return '<div class="pa-quota-upsell pa-quota-card" role="status">' +
      '<strong>You\'ve used both signatures this month.</strong>' +
      '<span>Free gives you 2 per month, with the same encryption, the same post-quantum signatures and the same public proof log as every paid plan. You never pay for security here. You pay for volume.</span>' +
      '<span><strong>Pro - EUR 49/month</strong><br>100 signatures per month, then EUR 0.40 each, up to 1,000. Unlimited transfers. API access.</span>' +
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
    var p = PRODUCTS[data && data.dimension] || PRODUCTS.transfers_month;
    var limit = data && isFinite(Number(data.limit)) ? Number(data.limit) : null;
    var used = limit !== null
      ? 'You have used all ' + limit + ' ' + p.unit + ' included in your plan this month.'
      : 'You have used all ' + p.unit + ' included in your plan this month.';
    return '<div class="pa-quota-upsell" role="status">' +
      '<strong>Free monthly limit reached.</strong>' +
      '<span>' + used + ' Upgrade to ' + p.upgrade + ' (' + p.price +
      ') for a higher limit, or wait until your quota resets next month.</span>' +
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
        '<span>You\'ve passed 100 signatures this month. Everything keeps working. Additional signatures are EUR 0.40 each and appear on your next invoice, up to 1,000 per month.</span>' +
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
