// The appearance choice, applied before the first paint.
//
// Why this file exists. Dark mode on the app screens used to follow
// prefers-color-scheme on its own. Measured on 2026-09-03 with a dark OS and no
// choice made: /index and /pricing stayed light, while /dashboard, /sign,
// /parashare, /account and /auth/login came up on rgb(10,15,22). Signing in was
// a jump from creme to black in one click. Dark is now something a reader picks
// on /account, never something the operating system decides for them.
//
// How the default holds. Without a stored choice this script sets NOTHING, so
// <html> carries no data-theme, the media block in /app-2026.css is scoped to
// [data-theme="auto"] and does not match, and the app is light. That is also
// what happens with JavaScript off: the light default does not depend on this
// file running. What this file does is apply a choice that was made.
//
// Why it is external and why it blocks. The site runs under script-src 'self',
// so an inline script is dead in the browser (scripts/check-csp-inline.sh). It
// is a plain <script> at the end of the <head> of every app page: it runs while
// the head is being parsed, before the body exists and before the first paint,
// so a reader who chose dark never sees a light flash.
//
// Storage. localStorage['paramant.theme.v1'], one of 'auto', 'light', 'dark'.
// Anything else, and a browser that refuses storage, reads as no choice. The
// key is documented in docs/site-claims.md and pinned by
// tests/ui-truthfulness.test.mjs; the behaviour is gated by
// tests/app-theme.test.mjs.
(function () {
  var KEY = 'paramant.theme.v1';
  var CHOICES = ['auto', 'light', 'dark'];
  // The two page grounds, kept in step with --paper in /app-2026.css. This is
  // the browser chrome, not the page: leaving it on a media query would tint
  // the address bar dark above a light page.
  var CHROME = { light: '#FBFAF7', dark: '#0A0F16' };

  function read() {
    try {
      var stored = localStorage.getItem(KEY);
      return CHOICES.indexOf(stored) === -1 ? null : stored;
    } catch (error) {
      return null; // private mode, or storage switched off
    }
  }

  function systemIsDark() {
    try {
      return !!(window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
    } catch (error) {
      return false;
    }
  }

  // What the reader actually sees, after the choice and the system are both in.
  function resolved(choice) {
    if (choice === 'dark') return 'dark';
    if (choice === 'auto') return systemIsDark() ? 'dark' : 'light';
    return 'light';
  }

  function apply(choice) {
    var root = document.documentElement;
    if (choice === null) root.removeAttribute('data-theme');
    else root.setAttribute('data-theme', choice);
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', CHROME[resolved(choice)]);
  }

  function save(choice) {
    if (CHOICES.indexOf(choice) === -1) return;
    try { localStorage.setItem(KEY, choice); } catch (error) { /* choice lives for this page only */ }
    apply(choice);
  }

  apply(read());

  window.paramantTheme = {
    KEY: KEY,
    CHOICES: CHOICES,
    read: read,
    save: save,
    apply: apply,
    resolved: resolved
  };
}());
