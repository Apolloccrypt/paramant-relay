// The appearance choice, applied before the first paint.
//
// Why this file exists. The site stands on the bone: light paper, navy ink,
// one cobalt accent, on every page and on every app screen. That is the
// default and it needs no script. What a reader can do on /account is ask for
// the night instead, or hand the decision to their operating system.
//
// How the default holds. Without a stored choice this script sets NOTHING, so
// <html> carries no data-theme, the two night blocks in /app-2026.css are
// scoped to [data-theme="dark"] and [data-theme="auto"] and neither matches,
// and the app is light. That is also what happens with JavaScript off: the
// default does not depend on this file running. What this file does is apply a
// choice that was made.
//
// Why it is external and why it blocks. The site runs under script-src 'self',
// so an inline script is dead in the browser (scripts/check-csp-inline.sh). It
// is a plain <script> at the end of the <head> of every app page: it runs while
// the head is being parsed, before the body exists and before the first paint,
// so a reader who chose the night never sees a light flash.
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
  var CHROME = { light: '#FFFFFF', dark: '#15191C' };

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
  // No choice is light, because light is what the whole site stands on.
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
