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
 * CSP-safe: external file, no inline script.
 *
 * THE CREDENTIAL. This page used to fetch the account's pgp_ key from
 * /api/user/account/key and send it as X-Api-Key on the checkout call. That key
 * has no expiry and no scope, so a click on a price button left a full
 * data-plane credential in the tab for as long as it stayed open. It now runs
 * on the same kind of short-lived scoped token /parashare got in #401: js/
 * app-session-token.js mints a pst_ token with purpose `app`, which the relay
 * accepts on POST /v2/billing/checkout, the redeem route the code field on this
 * page uses, and the dashboard reads, and refuses everywhere else. Fifteen minutes, held in memory, never persisted.
 *
 * NOTHING IS FETCHED ON LOAD. The token is minted on the first click, not when
 * the page opens, so simply reading the prices asks for no credential at all.
 * tests/app-pages-no-api-key.test.mjs pins that.
 */
(function () {
  'use strict';

  var buttons = document.querySelectorAll('a[data-billing-product]');
  if (!buttons.length) return;

  function checkout(btn) {
    /* A missing helper is a broken page, not a reason to reach for the key. The
     * error travels the same route as a failed mint, so the buyer sees the same
     * honest message instead of a silent no-op.
     *
     * withToken does the one retry on 401 with a freshly minted token: a tab
     * left open past the fifteen minutes must not send the buyer to the login
     * page for a session that is still perfectly valid. A second 401 is a real
     * refusal and falls through to the sign-in branch below. */
    if (!window.paAppToken) return Promise.reject(new Error('token_unavailable'));
    return window.paAppToken.withToken(function (tok) {
      return fetch('/v2/billing/checkout', {
        method: 'POST',
        headers: {
          Authorization: 'Bearer ' + tok,
          'Content-Type': 'application/json',
          Accept: 'application/json'
        },
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

  /* The choice a visitor made before we sent them away to sign in.
   *
   * Clicking a price button while signed out used to end here: we redirected to
   * /auth/login?next=/pricing, and after signing in the visitor landed back on a
   * page full of buttons with no memory of which one they had pressed. They had
   * to find it again and click a second time. Every new customer had to want it
   * twice, and the moment they were most willing to pay was the moment we threw
   * their choice away.
   *
   * sessionStorage, not a query parameter: the plan is not a secret but it is
   * also nobody's business in a URL that gets shared, logged and pasted. It dies
   * with the tab, which is exactly the lifetime of a purchase decision. */
  var INTENT = 'paramant.checkout.intent.v1';

  function rememberIntent(btn) {
    try {
      sessionStorage.setItem(INTENT, JSON.stringify({
        product: btn.getAttribute('data-billing-product'),
        plan: btn.getAttribute('data-billing-plan'),
        interval: btn.getAttribute('data-billing-interval'),
        at: new Date().toISOString()
      }));
    } catch (e) { /* private mode: the visitor just clicks again, no worse than before */ }
  }

  function takeIntent() {
    var raw = null;
    try { raw = sessionStorage.getItem(INTENT); sessionStorage.removeItem(INTENT); }
    catch (e) { return null; }
    if (!raw) return null;
    try {
      var i = JSON.parse(raw);
      if (!i || !i.product || !i.plan || !i.interval) return null;
      return i;
    } catch (e) { return null; }
  }

  /* Find the button that matches a remembered choice, so resuming presses the
   * real button: same request, same error handling, same visible state. A
   * separate resume path would be a second way to buy, and the second way is
   * always the one that rots. */
  function buttonFor(i) {
    for (var n = 0; n < buttons.length; n++) {
      var b = buttons[n];
      if (b.getAttribute('data-billing-product') === i.product &&
          b.getAttribute('data-billing-plan') === i.plan &&
          b.getAttribute('data-billing-interval') === i.interval) return b;
    }
    return null;
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
         * an obstacle to route around.
         *
         * The route is /auth/login (frontend/auth/login.html). It was written
         * as /login here, which is a 404, so from the day this file shipped
         * every signed-out visitor who clicked a price button landed on the
         * error page. The rest of the site already linked /auth/login; this
         * one line was the odd one out. */
        if (msg.indexOf('token_http_401') === 0 || msg.indexOf('token_http_403') === 0 ||
            msg === 'token_unavailable' || msg.indexOf('checkout_http_401') === 0 ||
            msg.indexOf('checkout_http_403') === 0) {
          rememberIntent(btn);
          window.location.href = '/auth/login?next=' + encodeURIComponent(location.pathname + location.search);
          return;
        }
        showError(btn, 'Could not start checkout. Nothing has been charged. ' +
          'Please try again, or mail privacy@paramant.app and we will sort it out.');
      });
    });
  });

  /* Back from signing in with a choice still pending: press it for them. Only
   * once, because takeIntent clears the store as it reads. A failure here shows
   * the same inline error as a normal click, so a visitor is never left on a
   * page that silently did nothing. */
  var pending = takeIntent();
  if (pending) {
    var target = buttonFor(pending);
    if (target) {
      var note = document.createElement('div');
      note.setAttribute('role', 'status');
      note.style.cssText = 'margin-top:.6rem;font-size:.85rem;color:#334155';
      note.textContent = 'Picking up where you left off.';
      if (target.parentNode) target.parentNode.insertBefore(note, target.nextSibling);
      target.click();
    }
  }
})();
