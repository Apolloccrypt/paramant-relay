// After "Alles staat klaar": a new account that was made from a signing
// invitation ("Maak er gratis een" on /co-sign) goes straight back to that
// document (acceptance r5, A). The address waits in this browser
// (login-return.js); this page only reads the path and never the address.
//
// Both ways of setting up end on the welcome screen. The app route gets
// there through auth-setup.js; the passkey route went to the dashboard, so
// with a document waiting its finish button opens the welcome screen too.
//
// Any other page works the same way since 13-10-2026 (test with a stranger):
// /signup?next=<path> keeps that path (js/signup-next.js), from /pricing, from
// /sign?herstel=1, from wherever the sign-in sent him to make an account. The
// signing invitation goes first; it is the more specific of the two.
import { signupReturnPath } from '/js/login-return.js?v=2';
import { signupNextPath, takeSignupNext, isPricingPath } from '/js/signup-next.js?v=1';

const EN = /^en\b/i.test(document.documentElement.lang || '');
const WAIT_MS = 2500;

let path = null;
let generic = false;
try { path = signupReturnPath(window.localStorage); } catch { path = null; }
if (!path) {
  try { path = signupNextPath(window.localStorage); generic = !!path; } catch { path = null; }
}

const welcome = document.getElementById('state-welcome');
if (path && welcome) {
  let gone = false;
  const goBack = () => {
    if (gone) return;
    gone = true;
    const box = document.getElementById('welcome-doc-return');
    const link = document.getElementById('welcome-doc-link');
    const rest = document.getElementById('welcome-default');
    if (link) link.href = path;
    if (generic) {
      try { takeSignupNext(window.localStorage); } catch { /* storage off */ }
      const lede = box ? box.querySelector('.lede') : null;
      const buy = isPricingPath(path);
      if (lede) {
        lede.textContent = buy
          ? (EN ? 'Your account is active. You now go back to the plan you chose, to pay.' : 'Uw account is actief. U gaat nu terug naar het plan dat u koos, om af te rekenen.')
          : (EN ? 'Your account is active. You now continue where you were.' : 'Uw account is actief. U gaat nu verder waar u was.');
      }
      if (link) link.textContent = buy ? (EN ? 'Back to your plan' : 'Terug naar uw plan') : (EN ? 'Continue where I was' : 'Verder waar ik was');
    }
    if (box) box.hidden = false;
    if (rest) rest.hidden = true;
    setTimeout(() => { location.assign(path); }, WAIT_MS);
  };
  const shown = () => !welcome.classList.contains('hidden');
  new MutationObserver(() => { if (shown()) goBack(); }).observe(welcome, { attributes: true, attributeFilter: ['class'] });
  if (shown()) goBack();

  const pkFinish = document.getElementById('passkey-finish-btn');
  if (pkFinish) pkFinish.textContent = generic ? (EN ? 'Continue' : 'Verder') : (EN ? 'Continue to the document' : 'Verder naar het document');
  // Capture on the document runs before passkey.js's own listener on the
  // button, which would go to the dashboard.
  document.addEventListener('click', (ev) => {
    const btn = ev.target && ev.target.closest ? ev.target.closest('#passkey-finish-btn') : null;
    if (!btn) return;
    ev.stopPropagation();
    ev.preventDefault();
    document.querySelectorAll('section[id^="state-"]').forEach((s) => s.classList.add('hidden'));
    welcome.classList.remove('hidden');
    window.scrollTo(0, 0);
  }, true);
}
