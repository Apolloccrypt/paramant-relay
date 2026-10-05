// ready.js — sticky readiness signals between scripts on the same page.
//
// THE BUG THIS EXISTS TO KILL
//
// A module loader announced itself with a one-shot event:
//
//     window.dispatchEvent(new Event('mlkem-ready'));          // loader, module
//     window.addEventListener('mlkem-ready', () => init());    // consumer, defer
//
// Module scripts and deferred classic scripts run after parsing in DOCUMENT
// ORDER, and the loader sits above the consumer in the HTML. So the event fired
// while nobody was listening, the consumer's callback never ran, and /ontvang
// sat on "Generating keypair..." forever. Every asset loaded, every global was
// set, the console was clean. Nothing to see and nothing to grep for. Measured
// on production 2026-07-28; broken since the CSP extraction of 2026-07-02 moved
// the listener out of the page and into a deferred file.
//
// A one-shot event is only safe when the listener is guaranteed to exist first,
// and script order gives no such guarantee. So do not use events for readiness.
//
// THE CONTRACT
//
//   Producer:  ready.signal('mlkem', ml_kem768)
//   Consumer:  const lib = await ready.when('mlkem')
//
// A signal is STICKY: it is remembered, so `when()` resolves whether it is
// called before or after `signal()`. Order stops mattering, which is the point.
//
// This file must load as a plain <script> in <head> — no defer, no async, no
// type="module" — so it is guaranteed to run before every module and deferred
// script on the page. tests/frontend-ready-contract.test.mjs enforces that, and
// enforces that no page goes back to bare readiness events.
'use strict';

(function () {
  // Idempotent: a page may include this file more than once via a partial.
  if (window.ready && window.ready.__paramant) return;

  var values = Object.create(null);   // name -> resolved value (never undefined)
  var waiters = Object.create(null);  // name -> [resolve, ...]

  function signal(name, value) {
    if (!name) throw new Error('ready.signal() needs a name');
    // `true` stands in for "ready, no value", so `when()` can resolve either way
    // without a separate "has it fired" flag.
    values[name] = value === undefined ? true : value;
    var queued = waiters[name] || [];
    waiters[name] = [];
    for (var i = 0; i < queued.length; i++) queued[i](values[name]);
  }

  function when(name) {
    if (name in values) return Promise.resolve(values[name]);
    return new Promise(function (resolve) {
      (waiters[name] = waiters[name] || []).push(resolve);
    });
  }

  // Same as when(), but rejects if the producer never shows up. Use it where a
  // silent hang is worse than an error the user can act on — which is the whole
  // reason this file exists.
  function within(name, ms, what) {
    if (name in values) return Promise.resolve(values[name]);
    return new Promise(function (resolve, reject) {
      var timer = setTimeout(function () {
        reject(new Error((what || name) + ' failed to load'));
      }, ms);
      when(name).then(function (v) { clearTimeout(timer); resolve(v); });
    });
  }

  function done(name) { return name in values; }

  window.ready = { signal: signal, when: when, within: within, done: done, __paramant: true };
})();
