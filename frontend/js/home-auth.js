/* Homepage state swap.
 *
 * The homepage ships the logged-out pitch by default (so it works with JS off
 * and is what link scrapers see). When a valid session is present, swap to the
 * logged-in variant: "Welcome back" + quick actions, marketing badges gone.
 *
 * Uses the same probe the nav uses (GET /api/user/session/verify, credentials
 * included). CSP-safe: external file, no inline script, no eval. Best-effort,
 * tolerant: any failure leaves the logged-out pitch in place.
 */
(function () {
  'use strict';
  var out = document.querySelector('[data-home="out"]');
  var inn = document.querySelector('[data-home="in"]');
  if (!out || !inn) return;

  fetch('/api/user/session/verify', { credentials: 'include', cache: 'no-store' })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (data) {
      if (!data || !data.authenticated) return;

      // Personalise with the email local-part if we have it (textContent, so
      // no markup injection). Falls back to a plain "Welcome back." otherwise.
      var nameEl = inn.querySelector('[data-home-name]');
      if (nameEl && data.email) {
        var at = String(data.email).indexOf('@');
        var local = at > 0 ? String(data.email).slice(0, at) : String(data.email);
        if (local) nameEl.textContent = ', ' + local;
      }

      out.hidden = true;
      inn.hidden = false;
    })
    .catch(function () { /* stay on the logged-out pitch */ });
})();
