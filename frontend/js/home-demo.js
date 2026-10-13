/* The landing demo: the dashboard in a signed-out, example state.
 *
 * Every tile on the homepage is a link into a real tool (/sign, /parashare,
 * /verify), so without this file a visitor still gets somewhere. With it, a
 * tap opens the dashboard's own detail dialog: one heading, one sentence of
 * what the tool does, one button into it, the steps folded underneath.
 * Nothing is drawn or played; the real tool is one tap away.
 */
(function () {
  'use strict';
  var root = document.querySelector('[data-wp-demo]');
  if (!root) return;

  // The example dates, counted back from today (13-10-2026). A date typed into
  // the markup ages, and an overview whose newest row is three months old looks
  // abandoned. Each <time data-wp-when> says how many days back it lies
  // (data-wp-ago) and, for a send, at what time (data-wp-at); it is written
  // with js/format-date.js, the formatter /dashboard uses: paramantDate.day for
  // a document ("Gemaakt 12 oktober 2026"), paramantDate.localMoment for a send
  // ("Verstuurd 13 oktober 2026 om 09:12 (CEST)"). Without script, or without
  // the formatter, the date in the markup stays.
  (function fillDates() {
    var f = window.paramantDate;
    if (!f || !f.day || !f.localMoment) return;
    var now = new Date();
    Array.prototype.forEach.call(root.querySelectorAll('time[data-wp-when]'), function (el) {
      var ago = Number(el.getAttribute('data-wp-ago')) || 0;
      var at = /^(\d{1,2}):(\d{2})$/.exec(el.getAttribute('data-wp-at') || '') || [0, 12, 0];
      var d = new Date(now.getFullYear(), now.getMonth(), now.getDate() - ago, Number(at[1]), Number(at[2]));
      // "today at 09:12" before 09:12 would lie in the future: then it was yesterday.
      if (d > now) d.setDate(d.getDate() - 1);
      el.setAttribute('datetime', d.toISOString());
      el.textContent = el.getAttribute('data-wp-when') === 'moment' ? f.localMoment(d) : f.day(d);
    });
  })();

  // The stages sit in the hero's markup, inside .home-state, which is its own
  // stacking context (z-index 2). Moved to <body> they cover the nav as a
  // dialog should, instead of opening underneath it.
  Array.prototype.forEach.call(document.querySelectorAll('[data-wp-stage]'), function (stage) {
    document.body.appendChild(stage);
  });

  var open = null;      // the stage that is showing
  var opener = null;    // the tile that opened it, to give focus back

  function focusables(el) {
    return Array.prototype.filter.call(
      el.querySelectorAll('a[href], button:not([disabled]), summary'),
      function (n) { return n.offsetParent !== null; }
    );
  }

  function show(name, tile) {
    var stage = document.querySelector('[data-wp-stage="' + name + '"]');
    if (!stage) return false;
    opener = tile || null;
    open = stage;
    stage.hidden = false;
    document.documentElement.style.overflow = 'hidden';
    var close = stage.querySelector('[data-wp-close]');
    if (close) close.focus({ preventScroll: true });
    if (tile) tile.setAttribute('data-wp-seen', '');
    return true;
  }

  function hide() {
    if (!open) return;
    open.hidden = true;
    open = null;
    document.documentElement.style.overflow = '';
    if (opener) opener.focus({ preventScroll: true });
  }

  root.addEventListener('click', function (ev) {
    var tile = ev.target.closest && ev.target.closest('[data-wp-open]');
    if (!tile) return;
    // A modified click (new tab, new window) goes where the link says.
    if (ev.metaKey || ev.ctrlKey || ev.shiftKey || ev.altKey || ev.button > 0) return;
    if (show(tile.getAttribute('data-wp-open'), tile)) ev.preventDefault();
  });

  document.addEventListener('click', function (ev) {
    if (!open) return;
    if (ev.target === open || (ev.target.closest && ev.target.closest('[data-wp-close]'))) hide();
  });

  document.addEventListener('keydown', function (ev) {
    if (!open) return;
    if (ev.key === 'Escape') { ev.preventDefault(); hide(); return; }
    if (ev.key !== 'Tab') return;
    var f = focusables(open);
    if (!f.length) return;
    var first = f[0], last = f[f.length - 1];
    if (ev.shiftKey && document.activeElement === first) { ev.preventDefault(); last.focus(); }
    else if (!ev.shiftKey && document.activeElement === last) { ev.preventDefault(); first.focus(); }
  });
})();
