/* Pricing buttons: API-checkout only. Never an unattributable payment.
 *
 * Signed-in buyers (session cookie) get a Mollie payment created via
 * POST /v2/billing/checkout, which carries metadata {accountId, product, plan,
 * interval}. The webhook needs that metadata to grant the tier: without it
 * lib/billing.js refuses with 'missing_metadata' and the buyer gets nothing.
 *
 * This used to fall back to the static Mollie payment link in the button's href
 * on ANY failure, including "not signed in". Those links carry no metadata, so
 * the money arrived and the grant never happened -- silently, with the buyer
 * left staring at the free-tier wall. That is exactly what happened to the
 * first paying customer (2026-07-21). A checkout we cannot attribute is now
 * refused loudly instead: sign-in first, or a visible error, never a charge we
 * cannot honour. The href stays as a real link so it survives without JS, but
 * every scripted click goes through checkout.
 *
 * CSP-safe: external file, no inline script. Same session->key bridge as
 * dashboard-history.js (/api/user/account/key, never persisted).
 */
(function () {
  'use strict';

  var buttons = document.querySelectorAll('a[data-billing-product]');
  if (!buttons.length) return;

  var keyPromise = null;
  function getApiKey() {
    if (keyPromise) return keyPromise;
    keyPromise = fetch('/api/user/account/key', {
      credentials: 'include', headers: { Accept: 'application/json' }, cache: 'no-store'
    }).then(function (r) {
      if (!r.ok) throw new Error('key_http_' + r.status);
      return r.json();
    }).then(function (j) {
      if (!j || !j.api_key) throw new Error('key_unavailable');
      return j.api_key;
    });
    return keyPromise;
  }

  function checkout(btn) {
    return getApiKey().then(function (key) {
      return fetch('/v2/billing/checkout', {
        method: 'POST',
        headers: { 'X-Api-Key': key, 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({
          product: btn.getAttribute('data-billing-product'),
          plan: btn.getAttribute('data-billing-plan'),
          interval: btn.getAttribute('data-billing-interval')
        })
      });
    }).then(function (r) {
      if (!r.ok) throw new Error('checkout_http_' + r.status);
      return r.json();
    }).then(function (j) {
      if (!j || !j.ok || !j.checkout_url) throw new Error('checkout_no_url');
      return j.checkout_url;
    });
  }

  /* Inline, next to the button that failed. No alert(): a modal on a pricing
   * page reads as a browser problem rather than an answer. */
  function showError(btn, text) {
    var id = 'billing-error-' + (btn.getAttribute('data-billing-product') || 'x') + '-' +
             (btn.getAttribute('data-billing-interval') || 'x');
    var box = document.getElementById(id);
    if (!box) {
      box = document.createElement('div');
      box.id = id;
      box.setAttribute('role', 'alert');
      box.style.cssText = 'margin-top:.6rem;font-size:.85rem;line-height:1.4;color:#8a1c1c;' +
        'background:#fdeaea;border:1px solid #f0bcbc;border-radius:6px;padding:.5rem .6rem';
      if (btn.parentNode) btn.parentNode.insertBefore(box, btn.nextSibling);
    }
    box.textContent = text;
  }

  Array.prototype.forEach.call(buttons, function (btn) {
    btn.addEventListener('click', function (ev) {
      ev.preventDefault();
      var orig = btn.textContent;
      btn.textContent = 'One moment...';
      btn.setAttribute('aria-busy', 'true');
      checkout(btn).then(function (url) {
        window.location.href = url;
      }).catch(function (err) {
        btn.textContent = orig;
        btn.removeAttribute('aria-busy');
        var msg = String((err && err.message) || '');
        /* No session: send them to sign-in and straight back here. An account
         * is what makes the payment attributable, so it is a precondition, not
         * an obstacle to route around. */
        if (msg.indexOf('key_http_401') === 0 || msg.indexOf('key_http_403') === 0 ||
            msg === 'key_unavailable' || msg.indexOf('checkout_http_401') === 0 ||
            msg.indexOf('checkout_http_403') === 0) {
          window.location.href = '/login?next=' + encodeURIComponent(location.pathname + location.search);
          return;
        }
        showError(btn, 'Could not start checkout. Nothing has been charged. ' +
          'Please try again, or mail privacy@paramant.app and we will sort it out.');
      });
    });
  });
})();
