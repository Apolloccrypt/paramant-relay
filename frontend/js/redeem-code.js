/* "Have a code?": spending a gift code from the browser.
 *
 * WHAT IT IS FOR. A supporter is handed a code and has to be able to type it
 * in somewhere. There are exactly two places worth putting that box: /pricing,
 * where somebody who has just read the prices finds out he does not have to pay
 * them, and /account, next to the plan the code changes. One file drives both,
 * because two copies of a form that grants a paid tier is two chances for them
 * to disagree about what happened.
 *
 * THE CREDENTIAL. The same short-lived scoped token the price buttons run on:
 * js/app-session-token.js mints a pst_ token with purpose `app`, fifteen
 * minutes, held in memory and never persisted, and the relay accepts it on the
 * five routes in relay/lib/session-token.js APP_SCOPE. POST /v2/billing/redeem
 * is one of them. It never falls back to the account's api-key. A fallback
 * would put an unscoped, non-expiring credential in the tab on exactly the day
 * something else is already wrong, which is the trade #401 took out of these
 * pages.
 *
 * NOTHING IS FETCHED ON LOAD. The token is minted by the submit, not by the
 * page opening, so reading the prices asks for no credential at all.
 * tests/app-pages-no-api-key.test.mjs pins that for every script these pages
 * load.
 *
 * THE ACCOUNT IS NOT IN THE REQUEST. The body is the code and nothing else. The
 * relay resolves the account from the token it just checked, so a code can only
 * ever be spent on the account that is signed in.
 *
 * EVERY MESSAGE COMES FROM THE SERVER. The relay answers with a `message` field
 * in plain English for both halves, success and refusal, and this file prints
 * it. Writing the sentences here as well would mean the mail, the billing
 * history and the page each had their own idea of what a code gave you.
 *
 * CSP-safe: external file, no inline script, no innerHTML.
 * ASCII-only. Vanilla JS, no libraries.
 */
(function () {
  'use strict';

  var forms = document.querySelectorAll('[data-redeem-form]');
  if (!forms.length) return;

  var BUSY = 'Checking your code...';
  var NO_HELPER = 'This page could not start. Reload and try again.';
  var OFFLINE = 'We could not reach the server. Please try again in a minute.';
  var EMPTY = 'Enter your code first.';

  function say(form, text, kind) {
    var el = form.querySelector('[data-redeem-message]');
    if (!el) return;
    el.textContent = text;
    el.hidden = !text;
    /* The colour is the only thing that differs, and it is never the only thing:
     * the sentence itself always says which of the two happened. */
    el.style.color = kind === 'error' ? 'var(--brick-ink, #8a2b1f)' : 'var(--ink)';
  }

  function busy(form, on) {
    var btn = form.querySelector('[data-redeem-submit]');
    if (btn) btn.disabled = !!on;
    var input = form.querySelector('[data-redeem-input]');
    if (input) input.readOnly = !!on;
  }

  /* A 401 means the token was refused, which on these pages means "not signed
   * in". Send him to sign in and come back here, never to /login, which 404s. */
  function toLogin() {
    window.location.href = '/auth/login?next=' + encodeURIComponent(
      window.location.pathname + window.location.search);
  }

  function submit(form, ev) {
    if (ev) ev.preventDefault();
    var input = form.querySelector('[data-redeem-input]');
    var code = input ? String(input.value || '').trim() : '';
    if (!code) { say(form, EMPTY, 'error'); if (input) input.focus(); return; }

    if (!window.paAppToken) { say(form, NO_HELPER, 'error'); return; }

    busy(form, true);
    say(form, BUSY, 'info');

    window.paAppToken.withToken(function (tok) {
      return fetch('/v2/billing/redeem', {
        method: 'POST',
        headers: {
          Authorization: 'Bearer ' + tok,
          'Content-Type': 'application/json',
          Accept: 'application/json'
        },
        body: JSON.stringify({ code: code })
      });
    }).then(function (res) {
      if (res.status === 401) { toLogin(); return null; }
      return res.json().then(function (data) { return { status: res.status, data: data || {} }; });
    }).then(function (out) {
      if (!out) return;
      busy(form, false);
      if (out.status === 200 && out.data.ok) {
        say(form, out.data.message || 'Your code is redeemed.', 'info');
        if (input) input.value = '';
        /* The plan on this page is now out of date. Let whichever page we are
         * on refresh the block that shows it, without this file knowing which
         * page that is. */
        try {
          document.dispatchEvent(new CustomEvent('paramant:plan-changed', { detail: out.data }));
        } catch (e) { /* an old browser simply keeps the stale block */ }
        return;
      }
      say(form, out.data.message || OFFLINE, 'error');
    }).catch(function () {
      busy(form, false);
      say(form, OFFLINE, 'error');
    });
  }

  Array.prototype.forEach.call(forms, function (form) {
    form.addEventListener('submit', function (ev) { submit(form, ev); });
    var btn = form.querySelector('[data-redeem-submit]');
    /* A button inside a form already submits; this covers a button that was
     * placed outside one. */
    if (btn && !form.contains(btn)) btn.addEventListener('click', function (ev) { submit(form, ev); });
  });
})();
