// protocol-trail.js - what protected this transfer or signature, row by row,
// while it happens.
//
// WHAT IT IS FOR
//
// While a file is sent, collected, signed or checked, a narrow list under the
// progress shows each step as it really happens: encrypted on this device,
// sent to the server, recorded in the public log. Each row carries the name of
// the protocol that did the work, small, after the ordinary words.
//
// THE ONE RULE: A NAME IS MEASURED, NEVER TYPED
//
// No row and no protocol name is written into a page by hand. Every name comes
// out of the execution it describes, through the measure functions below:
//
//   tls(response)     the X-Paramant-Tls header the TLS edge sets per request
//                     (deploy/caddy/Caddyfile). The browser cannot read the TLS
//                     version itself, so without that header there is no name.
//   aes(cryptoKey)    the algorithm of the WebCrypto key that sealed or opened
//                     the file, read back from the key object.
//   hybrid(wire)      the header of the sealed block the WASM code produced:
//                     KEM ciphertext length and sender key length tell which
//                     ML-KEM set and which curve were used. Format byte 0x02 or
//                     0x03 is AES-256-GCM in crypto-wasm/src/lib.rs.
//   mlDsa(pk, sig)    the byte lengths of the public key and the signature that
//                     were made, against the FIPS 204 sizes.
//
// A measure that cannot tell returns null, and a row without a measured name
// shows its words only, or is not shown at all. Guessing is the one thing this
// file does not do.
//
// Classic script on window.paramantTrail, so the classic pages and the module
// pages can both use it. Text only through textContent.
'use strict';

(function () {
  if (window.paramantTrail && window.paramantTrail.__paramant) return;

  var LANG = ((document.documentElement && document.documentElement.lang) || 'nl').slice(0, 2) === 'en' ? 'en' : 'nl';

  // [while it happens, once it happened]
  var WORDS = {
    nl: {
      label: 'Wat er gebeurt',
      seal: ['Versleutelen op dit apparaat', 'Versleuteld op dit apparaat'],
      send: ['Onderweg naar de server', 'Verstuurd naar de server'],
      kept: ['Bewaard tot het wordt opgehaald', 'Bewaard tot het wordt opgehaald'],
      log: ['Vastleggen in het openbare logboek', 'Vastgelegd in het openbare logboek'],
      fetch: ['Ophalen van de server', 'Opgehaald van de server'],
      open: ['Ontsleutelen op dit apparaat', 'Ontsleuteld op dit apparaat'],
      wiped: ['Wissen van de server', 'Van de server gewist'],
      sign: ['Ondertekenen op dit apparaat', 'Ondertekend op dit apparaat'],
      match: ['Bestand vergelijken', 'Bestand is het ondertekende document'],
      sigOk: ['Handtekening controleren', 'Handtekening klopt'],
      sigsOk: ['Handtekeningen controleren', function (n) { return 'Alle ' + n + ' handtekeningen kloppen'; }],
      seal2: ['Zegel van Paramant controleren', 'Zegel van Paramant klopt'],
      logIndex: function (i) { return 'logboek #' + i; },
    },
    en: {
      label: 'What is happening',
      seal: ['Encrypting on this device', 'Encrypted on this device'],
      send: ['On its way to the server', 'Sent to the server'],
      kept: ['Kept until it is collected', 'Kept until it is collected'],
      log: ['Recording in the public log', 'Recorded in the public log'],
      fetch: ['Collecting from the server', 'Collected from the server'],
      open: ['Decrypting on this device', 'Decrypted on this device'],
      wiped: ['Wiping from the server', 'Wiped from the server'],
      sign: ['Signing on this device', 'Signed on this device'],
      match: ['Comparing the file', 'File is the signed document'],
      sigOk: ['Checking the signature', 'Signature checks out'],
      sigsOk: ['Checking the signatures', function (n) { return 'All ' + n + ' signatures check out'; }],
      seal2: ['Checking Paramant’s seal', 'Paramant’s seal checks out'],
      logIndex: function (i) { return 'log #' + i; },
    },
  };
  var W = WORDS[LANG];

  // ── Measures ─────────────────────────────────────────────────────────────

  // "tls1.3 TLS_AES_128_GCM_SHA256" (Caddy) or "TLSv1.3 TLS_AES_128_GCM_SHA256"
  // (nginx). Anything else is not a measurement.
  function parseTls(v) {
    if (typeof v !== 'string') return null;
    var m = v.trim().match(/^(?:tls|TLSv)(1\.[0-3])(?:\s+([A-Za-z0-9_-]{4,80}))?$/);
    if (!m) return null;
    return { name: 'TLS ' + m[1], suite: m[2] || '' };
  }
  function tls(response) {
    try {
      return parseTls(response && response.headers && response.headers.get('X-Paramant-Tls'));
    } catch (e) { return null; }
  }

  function aes(key) {
    var a = key && key.algorithm;
    if (!a || a.name !== 'AES-GCM') return null;
    return [128, 192, 256].indexOf(a.length) >= 0 ? 'AES-' + a.length + '-GCM' : null;
  }

  // FIPS 203 ciphertext sizes, and the uncompressed P-256 point.
  var KEM_BY_CT = { 768: 'ML-KEM-512', 1088: 'ML-KEM-768', 1568: 'ML-KEM-1024' };
  function hybrid(wire) {
    if (!(wire instanceof Uint8Array) || wire.length < 9) return null;
    if (wire[0] !== 0x02 && wire[0] !== 0x03) return null;
    var dv = new DataView(wire.buffer, wire.byteOffset, wire.byteLength);
    var kemLen = dv.getUint32(1, false);
    var kem = KEM_BY_CT[kemLen];
    var at = 5 + kemLen;
    if (!kem || at + 5 > wire.length) return null;
    var pubLen = dv.getUint32(at, false);
    if (pubLen !== 65 || wire[at + 4] !== 0x04) return null;
    return { kem: kem, ecdh: 'ECDH P-256', aead: 'AES-256-GCM', name: kem + ' + ECDH P-256 · AES-256-GCM' };
  }

  // FIPS 204 public key and signature sizes.
  var DSA = [[1312, 2420, 'ML-DSA-44'], [1952, 3309, 'ML-DSA-65'], [2592, 4627, 'ML-DSA-87']];
  function len(x) {
    if (x == null) return -1;
    if (typeof x === 'string') {
      try { return atob(x.replace(/-/g, '+').replace(/_/g, '/')).length; } catch (e) { return -1; }
    }
    return typeof x.length === 'number' ? x.length : -1;
  }
  function mlDsa(pk, sig) {
    var p = len(pk), s = len(sig);
    for (var i = 0; i < DSA.length; i++) if (DSA[i][0] === p && DSA[i][1] === s) return DSA[i][2];
    return null;
  }

  // ── The list ─────────────────────────────────────────────────────────────

  function words(key, done, n) {
    var pair = W[key];
    if (!pair) return '';
    var w = pair[done ? 1 : 0];
    return typeof w === 'function' ? w(n) : w;
  }

  function create(host) {
    var list = document.createElement('ol');
    list.className = 'pa-trail';
    list.setAttribute('aria-label', W.label);
    list.setAttribute('aria-live', 'polite');
    var rows = {};

    function mount(where) {
      var el = typeof where === 'string' ? document.getElementById(where) : where;
      if (el && list.parentNode !== el) el.appendChild(list);
      return api;
    }

    // step(key, 'now'|'done', tech?, opts?) adds the row if it is new and moves
    // it to the given state. tech is a measured name or nothing.
    function step(key, state, tech, opts) {
      opts = opts || {};
      var done = state === 'done';
      var row = rows[key];
      if (!row) {
        row = document.createElement('li');
        row.className = 'pa-trail-row';
        row.dataset.step = key;
        var dot = document.createElement('span');
        dot.className = 'pa-trail-dot';
        dot.setAttribute('aria-hidden', 'true');
        var text = document.createElement('span');
        text.className = 'pa-trail-text';
        var t = document.createElement('span');
        t.className = 'pa-trail-tech';
        t.hidden = true;
        row.appendChild(dot);
        row.appendChild(text);
        row.appendChild(t);
        list.appendChild(row);
        rows[key] = row;
      }
      row.classList.toggle('is-now', !done);
      row.classList.toggle('is-done', done);
      row.querySelector('.pa-trail-text').textContent = words(key, done, opts.n);
      var techEl = row.querySelector('.pa-trail-tech');
      if (tech !== undefined) {
        techEl.textContent = tech || '';
        techEl.hidden = !tech;
        if (opts.title) techEl.title = opts.title; else techEl.removeAttribute('title');
      }
      return api;
    }

    // A row that turned out not to have happened leaves the list.
    function drop(key) {
      var row = rows[key];
      if (row && row.parentNode) row.parentNode.removeChild(row);
      delete rows[key];
      return api;
    }

    // On a failure the step that was under way did not happen. Rows that
    // finished stay: they did.
    function settle() {
      Object.keys(rows).forEach(function (k) { if (rows[k].classList.contains('is-now')) drop(k); });
      return api;
    }

    function clear() {
      Object.keys(rows).forEach(drop);
      return api;
    }

    var api = { el: list, mount: mount, step: step, drop: drop, settle: settle, clear: clear, has: function (k) { return !!rows[k]; } };
    if (host) mount(host);
    return api;
  }

  // The transport row, written the same way everywhere: the row is real
  // (the request came back), the name only when the edge said which.
  function sent(trail, key, response) {
    var m = tls(response);
    trail.step(key, 'done', m ? m.name : null, m && m.suite ? { title: m.suite } : null);
    return m;
  }

  window.paramantTrail = {
    __paramant: true,
    lang: LANG,
    create: create,
    sent: sent,
    logIndex: function (i) { return Number.isInteger(i) && i >= 0 ? W.logIndex(i) : null; },
    measure: { tls: tls, parseTls: parseTls, aes: aes, hybrid: hybrid, mlDsa: mlDsa },
  };
})();
