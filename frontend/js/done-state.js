// done-state.js - the small helper behind the one end screen.
//
// WHAT IT IS FOR
//
// done-state.css gives the four end screens their shape. This gives them their
// words at runtime, because most of what an end screen says is only known once
// the job is finished: the file name, the code that was compared, the link and
// the moment it stops working.
//
// It is deliberately three functions and no state. Every page keeps owning its
// own flow; all this does is write into the three slots the markup already has
// (.done-title, .done-line, .done-payload) and wire the quiet line under the
// button to a file the browser saves.
//
// WHAT THE QUIET LINE SAVES, and why it may be called a receipt
//
// POST /v2/inbound answers with `merkle_proof`: the leaf hash of this transfer,
// its index, the audit path and the signed tree head of the public CT log. That
// is a real inclusion proof for the public log at /ct-log, signed by the relay,
// and it is handed to the sender at upload time. So the file this writes is
// proof and not a note-to-self, and `paramantDone.proof()` refuses to offer the
// line at all when the caller has nothing of the kind to put in it. An end
// screen never offers a receipt it does not have.
'use strict';

(function () {
  if (window.paramantDone && window.paramantDone.__paramant) return;

  function $(root) {
    return typeof root === 'string' ? document.getElementById(root) : root;
  }

  function slot(root, cls) {
    var el = $(root);
    return el ? el.querySelector('.' + cls) : null;
  }

  // Title and sentence. Both optional: a page that already has the right words
  // in its markup passes only the one it has to change.
  function fill(root, words) {
    words = words || {};
    var t = slot(root, 'done-title');
    if (t && words.title != null) t.textContent = words.title;
    var l = slot(root, 'done-line');
    if (l && words.line != null) l.textContent = words.line;
    return $(root);
  }

  // The thing the reader came for, if there is one: a link to copy, a file to
  // save. Takes nodes, never a string, so no end screen can grow an innerHTML
  // sink on a file name somebody else chose.
  function payload(root, nodes) {
    var host = slot(root, 'done-payload');
    if (!host) return null;
    host.textContent = '';
    if (!nodes) return host;
    (Array.isArray(nodes) ? nodes : [nodes]).forEach(function (n) {
      if (n) host.appendChild(n);
    });
    return host;
  }

  // The quiet line under the primary button. `data` is the proof itself: an
  // object that gets written out as JSON. Nothing to prove means no line, and
  // the caller does not have to check first.
  function proof(root, opts) {
    var btn = slot(root, 'done-quiet');
    if (!btn) return null;
    opts = opts || {};
    if (!opts.data) { btn.hidden = true; return btn; }
    btn.hidden = false;
    if (opts.label) btn.textContent = opts.label;
    var name = opts.filename || 'paramant-receipt.json';
    var text = JSON.stringify(opts.data, null, 2);
    if (btn._paDone) btn.removeEventListener('click', btn._paDone);
    btn._paDone = function (e) {
      e.preventDefault();
      var blob = new Blob([text], { type: 'application/json' });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 0);
    };
    btn.addEventListener('click', btn._paDone);
    return btn;
  }

  window.paramantDone = {
    __paramant: true,
    fill: fill,
    payload: payload,
    proof: proof,
  };
})();
