'use strict';
/* Shared CSP-safe event delegation for the public site.
   Replaces inline on* handlers so script-src can drop 'unsafe-inline'.
   Elements declare data-click / data-change / data-input = "actionName" (+ any
   data-* args). Pages register handlers with window.act(type, name, fn). The
   single document-level listeners here dispatch to the registry.
   Registered before page scripts load (this file is included first), so a page
   handler that calls stopImmediatePropagation() wins over later listeners. */
(function () {
  var ACTIONS = { click: {}, change: {}, input: {} };
  window.act = function (type, name, fn) {
    if (ACTIONS[type]) ACTIONS[type][name] = fn;
  };
  function delegate(type) {
    var attr = 'data-' + type;
    return function (ev) {
      var el = ev.target.closest('[' + attr + ']');
      if (!el) return;
      var fn = ACTIONS[type][el.getAttribute(attr)];
      if (fn) fn(el, ev);
    };
  }
  document.addEventListener('click', delegate('click'));
  document.addEventListener('change', delegate('change'));
  document.addEventListener('input', delegate('input'));
})();
