/* The landing demo: the dashboard in a signed-out, example state.
 *
 * Every tile on the homepage is a link into a real tool (/sign, /parashare,
 * /verify), so without this file a visitor still gets somewhere. With it, a
 * tap opens the dashboard's own detail dialog and plays a short mini-flow of
 * what that tool does: one class per step on the stage (s1, s2, ...), the
 * matching step in the list under it on the yellow sign, and at the end one
 * button into the real tool. The flow plays once and stops; it never loops.
 *
 * prefers-reduced-motion: the stage opens on its end state, every step ticked,
 * so the same information arrives without the movement.
 */
(function () {
  'use strict';
  var root = document.querySelector('[data-wp-demo]');
  if (!root) return;

  // Milliseconds per step, per flow. The first step starts right after the
  // dialog has risen in, so the reader sees the empty state for a moment and
  // knows what changed.
  var TIMING = {
    sign: [500, 1500, 2900, 4300],
    send: [500, 1700, 3300],
    verify: [500, 1500, 2900]
  };

  // The stages sit in the hero's markup, inside .home-state, which is its own
  // stacking context (z-index 2). Moved to <body> they cover the nav as a
  // dialog should, instead of opening underneath it.
  Array.prototype.forEach.call(document.querySelectorAll('[data-wp-stage]'), function (stage) {
    document.body.appendChild(stage);
  });

  var reduce = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : { matches: false };
  var timers = [];
  var open = null;      // the stage that is showing
  var opener = null;    // the tile that opened it, to give focus back

  function clearTimers() { timers.forEach(clearTimeout); timers = []; }

  function setStep(stage, n, total) {
    var play = stage.querySelector('[data-wp-play]');
    var steps = stage.querySelectorAll('[data-wp-steps] li');
    for (var i = 1; i <= 4; i++) play.classList.toggle('s' + i, i === n);
    for (var j = 0; j < steps.length; j++) {
      steps[j].classList.toggle('is-now', j === n - 1 && n < total);
      steps[j].classList.toggle('is-past', j < n - 1 || n >= total);
      if (j === n - 1) steps[j].setAttribute('aria-current', 'step'); else steps[j].removeAttribute('aria-current');
    }
    stage.classList.toggle('is-done', n >= total);
    // At the end, the one button comes into view if the panel scrolls (a
    // phone): the flow finishes where the reader can act on it.
    if (n >= total && n > 0) {
      var panel = stage.querySelector('.dh-doc-dialog-panel');
      if (panel && panel.scrollHeight > panel.clientHeight + 4) {
        panel.scrollTo({ top: panel.scrollHeight, behavior: reduce.matches ? 'auto' : 'smooth' });
      }
    }
  }

  function play(stage) {
    clearTimers();
    var name = stage.getAttribute('data-wp-stage');
    var plan = TIMING[name] || [];
    var total = plan.length;
    if (reduce.matches) { setStep(stage, total, total); return; }
    setStep(stage, 0, total);
    plan.forEach(function (at, i) {
      timers.push(setTimeout(function () { setStep(stage, i + 1, total); }, at));
    });
  }

  function focusables(el) {
    return Array.prototype.filter.call(
      el.querySelectorAll('a[href], button:not([disabled])'),
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
    play(stage);
    if (tile) tile.setAttribute('data-wp-seen', '');
    return true;
  }

  function hide() {
    if (!open) return;
    clearTimers();
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
    if (ev.target === open || (ev.target.closest && ev.target.closest('[data-wp-close]'))) { hide(); return; }
    if (ev.target.closest && ev.target.closest('[data-wp-replay]')) play(open);
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
