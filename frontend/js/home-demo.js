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
