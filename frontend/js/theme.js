// The appearance choice, applied before the first paint, on every page.
//
// Why this file exists. The site has two editions of one theme: the light one
// (white ground, navy ink, one cobalt accent) and its dark counterpart (deep
// ink-navy ground, light ink, the same cobalt family). Both are one set of
// tokens in /design-system.css; the dark set sits under [data-theme="dark"].
// This script decides which one a page opens in.
//
// The rule.
//   no choice   -> the operating system decides: dark when it asks for dark,
//                  light otherwise
//   'auto'      -> the same, because someone asked for it on /account
//   'light'     -> light, whatever the operating system says
//   'dark'      -> dark,  whatever the operating system says
// With JavaScript off there is no attribute and the page is light.
//
// What it writes. <html data-theme> always carries the RESOLVED edition,
// 'light' or 'dark', so the stylesheets need one gate and no media query. The
// sun | moon switch in the shared nav and the three radios on /account both
// write the same key through save() below: one mechanism, two doors.
//
// Why it is external and why it blocks. The site runs under script-src 'self',
// so an inline script is dead in the browser (scripts/check-csp-inline.sh). It
// is a plain <script> in the <head> of every page: it runs while the head is
// being parsed, before the body exists and before the first paint, so a reader
// on the dark edition never sees a light flash. The critical <style> of each
// page paints the dark ground under the same attribute.
//
// Motion. Switching fades the colours over 180ms (html.theme-fade in
// /design-system.css), because it shows the reader what changed. Nothing moves
// on load, and prefers-reduced-motion switches without a fade.
//
// Storage. localStorage['paramant.theme.v1'], one of 'auto', 'light', 'dark'.
// Anything else, and a browser that refuses storage, reads as no choice. The
// key is documented in docs/site-claims.md and pinned by
// tests/ui-truthfulness.test.mjs; the behaviour is gated by
// tests/app-theme.test.mjs and tests/theme-toggle.test.mjs.
(function () {
  var KEY = 'paramant.theme.v1';
  var CHOICES = ['auto', 'light', 'dark'];
  // The browser chrome follows the page ground. Light keeps whatever the page
  // itself declared, dark is the dark ground.
  var DARK_CHROME = '#0E141B';
  var root = document.documentElement;
  var lightChrome = null;

  function read() {
    try {
      var stored = localStorage.getItem(KEY);
      return CHOICES.indexOf(stored) === -1 ? null : stored;
    } catch (error) {
      return null; // private mode, or storage switched off
    }
  }

  function systemQuery() {
    try { return window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null; }
    catch (error) { return null; }
  }

  function systemIsDark() {
    var query = systemQuery();
    return !!(query && query.matches);
  }

  // What the reader actually sees, after the choice and the system are both in.
  function resolved(choice) {
    if (choice === 'dark') return 'dark';
    if (choice === 'light') return 'light';
    return systemIsDark() ? 'dark' : 'light';
  }

  function chrome(mode) {
    var meta = document.querySelector('meta[name="theme-color"]');
    if (!meta) {
      if (!document.head) return;
      meta = document.createElement('meta');
      meta.setAttribute('name', 'theme-color');
      meta.setAttribute('content', '#FFFFFF');
      document.head.appendChild(meta);
    }
    if (lightChrome === null) lightChrome = meta.getAttribute('content') || '#FFFFFF';
    meta.setAttribute('content', mode === 'dark' ? DARK_CHROME : lightChrome);
  }

  // Every switch on the page says which edition is on.
  function sync(mode) {
    var buttons = document.querySelectorAll('[data-theme-toggle]');
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].setAttribute('aria-pressed', mode === 'dark' ? 'true' : 'false');
    }
  }

  function apply(choice) {
    var mode = resolved(choice);
    root.setAttribute('data-theme', mode);
    chrome(mode);
    sync(mode);
    return mode;
  }

  function reducedMotion() {
    try { return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches); }
    catch (error) { return true; }
  }

  // A short colour fade, only when the reader switches, never on load.
  var fadeTimer = null;
  function fade() {
    if (reducedMotion()) return;
    root.classList.add('theme-fade');
    clearTimeout(fadeTimer);
    fadeTimer = setTimeout(function () { root.classList.remove('theme-fade'); }, 240);
  }

  function save(choice) {
    if (CHOICES.indexOf(choice) === -1) return;
    try { localStorage.setItem(KEY, choice); } catch (error) { /* choice lives for this page only */ }
    fade();
    apply(choice);
  }

  // The nav switch: one press flips to the other edition and remembers it.
  function toggle() {
    save(resolved(read()) === 'dark' ? 'light' : 'dark');
  }

  apply(read());

  // Delegated, so it works on every page and on a drawer that nav-auth.js
  // re-renders, without waiting for any other script.
  document.addEventListener('click', function (event) {
    var target = event.target;
    var button = target && target.closest ? target.closest('[data-theme-toggle]') : null;
    if (!button) return;
    event.preventDefault();
    toggle();
  });
  document.addEventListener('DOMContentLoaded', function () { sync(resolved(read())); });

  // Without a fixed choice the page follows the system live, and a choice made
  // in another tab arrives here too.
  var query = systemQuery();
  if (query) {
    var follow = function () { var c = read(); if (c === null || c === 'auto') apply(c); };
    if (query.addEventListener) query.addEventListener('change', follow);
    else if (query.addListener) query.addListener(follow);
  }
  window.addEventListener('storage', function (event) { if (event.key === KEY) apply(read()); });

  window.paramantTheme = {
    KEY: KEY,
    CHOICES: CHOICES,
    read: read,
    save: save,
    apply: apply,
    resolved: resolved,
    toggle: toggle
  };
}());
