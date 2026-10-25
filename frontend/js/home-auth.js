/* The homepage for somebody who is signed in: not a second overview, a door.
 *
 * Until 25 October 2026 the homepage drew its own workbench for a signed-in
 * visitor (a big figure, the inbox, the month balance) next to /dashboard,
 * which drew the same documents again. Two screens counted one document twice
 * and drifted (see js/document-state.js). Now there is one screen, "Je
 * documenten" on /dashboard, and this file only decides who goes there.
 *
 * HOW. It is loaded in the <head>, blocking, so it runs before the first
 * paint. A browser that carries the sign-in mark of nav-auth.js
 * (paramant.local.owner, set at sign-in, wiped at sign-out) hides the pitch
 * with data-session="checking" while the server is asked. A signed-in answer
 * replaces the page with /dashboard; anything else shows the pitch. A visitor
 * without the mark sees the pitch at once and is only moved on if the server
 * says he is signed in after all.
 *
 * A busy server (429, 5xx) is not "signed out". When this browser was signed
 * in and nobody signed out, the visitor goes to /dashboard, which says in
 * words that it could not load and offers to try again (fase 2 SITE-02-K).
 *
 * No key and no credential pass through here: the check rides the session
 * cookie, and the answer is only used to choose a page.
 */
(function () {
  'use strict';

  var html = document.documentElement;
  var LP = html.lang === 'en' ? '/en' : '';
  var TARGET = LP + '/dashboard';

  function signedInHere() {
    try { return !!localStorage.getItem('paramant.local.owner'); } catch (e) { return false; }
  }
  function showPitch() { html.removeAttribute('data-session'); }
  function go() {
    html.setAttribute('data-session', 'in');
    location.replace(TARGET);
  }

  var mark = signedInHere();
  if (mark) html.setAttribute('data-session', 'checking');
  // Never leave a page blank on a server that does not answer.
  var guard = setTimeout(function () { if (mark) go(); else showPitch(); }, 8000);

  function verify(attempt) {
    return fetch('/api/user/session/verify', { credentials: 'include', cache: 'no-store' })
      .then(function (r) {
        // Asked three times in all, as before (fase 1 SITE-02-K), honouring a
        // short Retry-After, before the answer counts as unknown.
        if ((r.status === 429 || r.status >= 500) && attempt < 2) {
          var wait = Math.min(2, Number(r.headers.get('Retry-After')) || 1);
          return new Promise(function (res) { setTimeout(res, wait * 1000); })
            .then(function () { return verify(attempt + 1); });
        }
        if (r.status === 429 || r.status >= 500) return { unknown: true };
        return r.ok ? r.json() : null;
      });
  }

  verify(0).then(function (data) {
    clearTimeout(guard);
    if (data && data.authenticated) return go();
    if (data && data.unknown && mark) return go();
    showPitch();
  }).catch(function () {
    clearTimeout(guard);
    showPitch();
  });
})();
