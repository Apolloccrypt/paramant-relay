/* Pricing buttons: API-checkout first, static Mollie payment link as fallback.
 *
 * Signed-in buyers (session cookie) get a Mollie payment created via
 * POST /v2/billing/checkout, so the webhook can grant their tier automatically
 * (no manual reconciliation). Anyone else -- or any failure at all, including
 * billing not being configured on the server -- falls through to the static
 * payment link the button already points at. Dormant by construction: until
 * the server has a Mollie key, every click behaves exactly as before.
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

  Array.prototype.forEach.call(buttons, function (btn) {
    btn.addEventListener('click', function (ev) {
      ev.preventDefault();
      var orig = btn.textContent;
      btn.textContent = 'One moment...';
      btn.setAttribute('aria-busy', 'true');
      checkout(btn).then(function (url) {
        window.location.href = url;
      }).catch(function () {
        /* Not signed in, billing dormant, or any hiccup: static link. */
        btn.textContent = orig;
        btn.removeAttribute('aria-busy');
        window.location.href = btn.href;
      });
    });
  });
})();
