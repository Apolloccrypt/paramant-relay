/* /redeem: the one thing this page does, and the one way it used to break.
 *
 * WHAT THIS FILE IS FOR. The code field itself is js/redeem-code.js and is not
 * copied here: it mints the scoped token, posts to POST /v2/billing/redeem and
 * prints whatever sentence the relay sends back. This file owns the three
 * things that are true of this page and of neither /pricing nor /account:
 *
 *   1. THE CODE MAY ARRIVE IN THE LINK. /redeem?code=COFFEE fills the box, so
 *      somebody who was mailed a code presses one button and is done. The
 *      parameter is written by whoever made the link and is therefore not
 *      trusted: it is trimmed, uppercased, refused unless it is shaped like a
 *      code (the same rule relay/lib/coupon.js normaliseCode applies), and it
 *      only ever reaches input.value. Nothing on this page is built out of it
 *      as markup.
 *
 *   2. SIGNED OUT IS THE NORMAL CASE HERE. Everywhere else the field sits on a
 *      page you reach by signing in first. The hundred people this page was
 *      built for have no account at all. On /pricing and /account a signed-out
 *      press is answered by a 401 and js/redeem-code.js sends him to the
 *      sign-in; here that would be the whole page failing at the last request,
 *      which is exactly the shape #442 took off /sign. So the session is asked
 *      once, up front, and the button says what it will do before it is
 *      pressed: "Create a free account" or "Redeem code", never the first
 *      wearing the label of the second. The button ships disabled and is
 *      enabled by that answer, so there is no window in which it means neither.
 *      tests/redeem-signed-out-dead-end.test.mjs is the gate.
 *
 *      THE CODE SURVIVES THE DETOUR, twice over. The sign-in link carries
 *      ?next=/redeem?code=..., which frontend/js/auth-login.js honours as-is
 *      (it accepts any local path, query string included). Signup does not
 *      carry next yet and finishes through an emailed link, so the code is ALSO
 *      kept in this browser's localStorage and typed back into the box when he
 *      lands here again. It is a coupon code, not a credential: it grants
 *      nothing without an account, and it is dropped the moment it is spent.
 *
 *   3. THE ENDING. On success js/redeem-code.js fires paramant:plan-changed
 *      with the relay's answer. This page swaps the form for the shared end
 *      screen (done-state.css): what you now have, until when, one button. The
 *      heading and the sentence are cut from the relay's own message, so no
 *      page here ever names a plan or a date the relay did not name.
 *
 * CSP-safe: external file, no inline script, no innerHTML. ASCII-only, vanilla.
 */
(function () {
  'use strict';

  var form = document.querySelector('[data-redeem-form]');
  var input = document.getElementById('rd-code');
  var submit = document.getElementById('rd-submit');
  var signedOutNote = document.getElementById('rd-signedout');
  var serviceNote = document.getElementById('rd-service-note');
  var signinLine = document.getElementById('rd-signin-line');
  var signinLink = document.getElementById('rd-signin-link');
  var panel = document.getElementById('rd-panel');
  var done = document.getElementById('rd-done');
  var doneTitle = document.getElementById('rd-done-title');
  var doneLine = document.getElementById('rd-done-line');
  if (!form || !input || !submit) return;

  /* relay/lib/coupon.js CODE_RE, written out rather than guessed: three to
   * thirty-two of capitals, digits and hyphens. Kept in step by
   * tests/redeem-signed-out-dead-end.test.mjs, which reads both. */
  var CODE_RE = /^[A-Z0-9-]{3,32}$/;
  var STORE_KEY = 'paramant.redeem.code';
  /* If the probe never answers, the button still has to work. The relay stays
   * the authority on the session either way; this is only about which promise
   * the label is allowed to make. */
  var PROBE_WAIT_MS = 4000;

  var state = 'unknown';   /* 'unknown' | 'in' | 'out' */
  var settled = false;

  /* Normalise the way the relay does, and refuse rather than repair: silently
   * deleting the space out of "COF FEE" would send a code he did not type. */
  function clean(raw) {
    var code = String(raw === null || raw === undefined ? '' : raw).trim().toUpperCase();
    if (code.length > 32) return '';
    return CODE_RE.test(code) ? code : '';
  }

  function remember(code) { try { if (code) window.localStorage.setItem(STORE_KEY, code); } catch (e) { /* private mode simply forgets */ } }
  function recall() { try { return clean(window.localStorage.getItem(STORE_KEY)); } catch (e) { return ''; } }
  function forget() { try { window.localStorage.removeItem(STORE_KEY); } catch (e) { /* nothing to clean up */ } }

  function typed() { return clean(input.value); }

  function backHere(code) {
    return '/redeem' + (code ? '?code=' + encodeURIComponent(code) : '');
  }

  /* ---- the box ---------------------------------------------------------- */

  function fillFromLinkOrBrowser() {
    var fromLink = '';
    try { fromLink = clean(new URLSearchParams(window.location.search).get('code')); } catch (e) { fromLink = ''; }
    var code = fromLink || recall();
    if (code) { input.value = code; remember(code); }
  }

  /* ---- the session ------------------------------------------------------ */

  function showServiceNote() {
    var errors = (typeof self !== 'undefined') && self.paramantErrors;
    if (serviceNote && errors) { serviceNote.textContent = errors.SUPPORT_FAILURE_MESSAGE; serviceNote.hidden = false; }
  }

  function updateSigninLink() {
    if (signinLink) signinLink.setAttribute('href', '/auth/login?next=' + encodeURIComponent(backHere(typed())));
  }

  function settle(next) {
    if (settled) return;
    settled = true;
    state = next;
    if (state === 'out') {
      if (signedOutNote) signedOutNote.hidden = false;
      if (signinLine) signinLine.hidden = false;
      updateSigninLink();
      submit.textContent = 'Create a free account';
    }
    submit.disabled = false;
  }

  function probe() {
    var answered = false;
    window.setTimeout(function () { if (!answered) settle('unknown'); }, PROBE_WAIT_MS);
    fetch('/api/user/session/verify', { credentials: 'include', cache: 'no-store' })
      .then(function (res) {
        answered = true;
        /* Broken is not the same event as signed out, and saying so would tell
         * a paying customer his account is gone. */
        if (res.status >= 500) { showServiceNote(); settle('unknown'); return null; }
        if (res.status === 401 || res.status === 403) { settle('out'); return null; }
        if (!res.ok) { settle('unknown'); return null; }
        return res.json().then(function (data) {
          if (!data || typeof data.authenticated !== 'boolean') { settle('unknown'); return null; }
          settle(data.authenticated ? 'in' : 'out');
          return null;
        }, function () { settle('unknown'); return null; });
      }, function () { answered = true; settle('unknown'); });
  }

  /* ---- the gate --------------------------------------------------------- */

  /* js/redeem-code.js asks this before it sends anything. Returning false stops
   * the send because this page has somewhere better to put him than a 401.
   * /pricing and /account define nothing here and are unchanged. */
  window.paRedeemBeforeSubmit = function () {
    if (state !== 'out') return true;
    var code = typed();
    remember(code);
    window.location.href = '/signup?next=' + encodeURIComponent(backHere(code));
    return false;
  };

  /* ---- the ending ------------------------------------------------------- */

  /* The relay's message is one paragraph: "Your code is redeemed." and then
   * what was given and until when. The end screen wants a heading and a
   * sentence, so it is cut at the first full stop and both halves stay the
   * relay's words. A message that does not split keeps the heading the page
   * shipped with. */
  function showDone(message) {
    var text = String(message || '').trim();
    var cut = text.indexOf('. ');
    if (cut > 0) {
      if (doneTitle) doneTitle.textContent = text.slice(0, cut + 1);
      if (doneLine) doneLine.textContent = text.slice(cut + 2).trim();
    } else if (doneLine) {
      doneLine.textContent = text;
      doneLine.hidden = !text;
    }
    if (panel) panel.hidden = true;
    if (done) done.hidden = false;
    var main = document.getElementById('main-content');
    if (main && typeof main.focus === 'function') { try { main.focus(); } catch (e) { /* focus is a courtesy */ } }
  }

  document.addEventListener('paramant:plan-changed', function (ev) {
    forget();
    showDone(ev && ev.detail ? ev.detail.message : '');
  });

  /* ---- wiring ----------------------------------------------------------- */

  input.addEventListener('input', function () {
    if (state === 'out') { updateSigninLink(); }
  });
  if (signinLink) signinLink.addEventListener('click', function () { remember(typed()); });

  fillFromLinkOrBrowser();
  probe();
})();
