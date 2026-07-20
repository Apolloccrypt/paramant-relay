/* Paramant quota upgrade notice. Plain external script (CSP: no inline JS);
 * exposes window.paQuotaUpgrade for both classic scripts (parashare) and
 * modules (sign-flow, co-sign). Input is the relay's 402 JSON:
 *   { error, dimension, plan, limit }
 * Prices shown excl. VAT and kept in ONE place here. This file only renders
 * the notice; the limits themselves live server-side and are unchanged. */
(function () {
  'use strict';

  var PRODUCTS = {
    transfers_month: { unit: 'transfers',  upgrade: 'ParaSend Pro', price: 'EUR 15/month excl. VAT' },
    signs_month:     { unit: 'signatures', upgrade: 'ParaSign Pro', price: 'EUR 49/month excl. VAT' }
  };

  function isQuota402(status, data) {
    return status === 402 && !!data &&
      (data.error === 'monthly_transfer_quota_reached' || data.error === 'monthly_sign_quota_reached');
  }

  // All interpolated values are server-controlled and coerced (Number) or
  // fixed literals -- no user input reaches this HTML.
  function html(data) {
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

  window.paQuotaUpgrade = { isQuota402: isQuota402, html: html };
})();
