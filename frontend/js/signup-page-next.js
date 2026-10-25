// /signup?next=<path>: where the visitor goes once the account exists (test
// with a stranger, 13-10-2026). The page says it in one sentence, the sign-in
// links on it keep the same way back, and on "Doorgaan" this browser keeps the
// path (js/signup-next.js) so the setup page, two mails later and in another
// tab, can send him there.
import { safeLocalPath, stashSignupNext, isPricingPath } from '/js/signup-next.js?v=1';

const EN = /^en\b/i.test(document.documentElement.lang || '');
const L = (nl, en) => (EN ? en : nl);

const next = safeLocalPath(new URLSearchParams(location.search).get('next'));
if (next) {
  const note = document.getElementById('signup-next-note');
  if (note) {
    note.textContent = isPricingPath(next)
      ? L('Eerst maak je een gratis account. Daarna reken je af: na het instellen ga je terug naar het plan dat je koos.',
        'First you make a free account. Then you pay: after the setup you go back to the plan you chose.')
      : L('Na het instellen van je account ga je verder waar je was.',
        'After setting up your account you continue where you were.');
    note.hidden = false;
  }
  const login = (EN ? '/en' : '') + '/auth/login?next=' + encodeURIComponent(next);
  document.querySelectorAll('a[data-signup-login]').forEach((a) => { a.href = login; });
  const form = document.getElementById('signup-form');
  if (form) {
    form.addEventListener('submit', () => {
      try { stashSignupNext(window.localStorage, next); } catch { /* storage off: the welcome screen shows its default */ }
    }, true);
  }
}
