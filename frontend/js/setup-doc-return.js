// After "Alles staat klaar": a new account that was made from a signing
// invitation ("Maak er gratis een" on /co-sign) goes straight back to that
// document (acceptance r5, A). The address waits in this browser
// (login-return.js); this page only reads the path and never the address.
//
// Both ways of setting up end on the welcome screen. The app route gets
// there through auth-setup.js; the passkey route went to the dashboard, so
// with a document waiting its finish button opens the welcome screen too.
import { signupReturnPath } from '/js/login-return.js?v=2';

const EN = /^en\b/i.test(document.documentElement.lang || '');
const WAIT_MS = 2500;

let path = null;
try { path = signupReturnPath(window.localStorage); } catch { path = null; }

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
    if (box) box.hidden = false;
    if (rest) rest.hidden = true;
    setTimeout(() => { location.assign(path); }, WAIT_MS);
  };
  const shown = () => !welcome.classList.contains('hidden');
  new MutationObserver(() => { if (shown()) goBack(); }).observe(welcome, { attributes: true, attributeFilter: ['class'] });
  if (shown()) goBack();

  const pkFinish = document.getElementById('passkey-finish-btn');
  if (pkFinish) pkFinish.textContent = EN ? 'Continue to the document' : 'Verder naar het document';
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
