// handshake-meta.js - one reading of the ParaSend handshake field.
//
// THE BUG THIS EXISTS TO KILL
//
// A live ParaSend hand-over ends with the sender posting a small record to
// /v2/pubkey under the key `<session>_ready`. The relay has exactly two free
// text fields there, `ecdh_pub` and `kyber_pub`, so the sender borrows the
// second one to say what is coming: the file name, how many sealed blocks it
// was cut into, and how long our copy is held.
//
// The two sides had drifted apart. frontend/js/parashare.page.js wrote three
// fields:
//
//     IMG_4276.jpeg|1|86400000            name | chunks | ttl in ms
//
// and frontend/js/ontvang.page.js read two, the format from before a name was
// ever put in there:
//
//     1|86400000                          chunks | ttl in ms
//
// So the receiver took the file name for the block count and the block count
// for the time to live. A single-block transfer became `ttl_ms = 1`, and
// /ontvang printed a line saying our copy had auto-expired at a clock time
// worked out from it. The line was removed on 4 September 2026 (#427); this
// file removes the reason it could be written.
//
// THE RULE
//
// Neither page parses the field itself any more. Both call this, so the writing
// and the reading can only ever change together.
//
// THE FORMAT, and how an old sender still gets through
//
//   named   name|chunks|ttl        what parashare.page.js writes today
//           vault|count|ttl        the same shape for a multi-file vault
//   legacy  chunks|ttl             a sender minted before the name was added
//
// Told apart on the number of fields, not on guesswork about the contents: a
// third field means the first one is a name. The numbers are read from the END
// of the string rather than the start, so a file name that itself contains a
// "|" still comes back whole and still leaves chunks and ttl in the right
// place. A file named exactly "vault" is the one case the shape cannot settle
// on its own, so `kind` is a hint and the caller confirms it: /ontvang treats
// the record as a vault only when the other field really does hold a JSON list.
'use strict';

(function () {
  if (window.paramantHandshake && window.paramantHandshake.__paramant) return;

  // What a receiver falls back to when the field says nothing usable. One hour
  // is the shortest life any plan gives a blob, so it is the safe assumption.
  var DEFAULT_TTL_MS = 3600000;
  var VAULT_NAME = 'vault';

  function positiveInt(value, fallback) {
    var n = parseInt(value, 10);
    return isFinite(n) && n > 0 ? n : fallback;
  }

  // Write the field. `kind` is 'vault' for a multi-file send and 'file' for one
  // file; a vault carries its file count where a single send carries its block
  // count, which is what the old code did too.
  function encode(meta) {
    meta = meta || {};
    var ttlMs = positiveInt(meta.ttlMs, DEFAULT_TTL_MS);
    var chunks = positiveInt(meta.chunks, 1);
    var name = meta.kind === 'vault' ? VAULT_NAME : String(meta.name == null ? '' : meta.name);
    return name + '|' + chunks + '|' + ttlMs;
  }

  // Read the field. Always answers with the same four keys, whatever came in,
  // so no caller has to check the shape before using it.
  function decode(value) {
    var raw = String(value == null ? '' : value);
    var parts = raw.split('|');
    var out = { kind: 'file', name: '', chunks: 1, ttlMs: DEFAULT_TTL_MS, format: 'unknown' };
    if (parts.length < 2) return out;
    out.ttlMs = positiveInt(parts[parts.length - 1], DEFAULT_TTL_MS);
    out.chunks = positiveInt(parts[parts.length - 2], 1);
    if (parts.length === 2) {
      out.format = 'legacy';
      return out;
    }
    out.format = 'named';
    var name = parts.slice(0, parts.length - 2).join('|');
    if (name === VAULT_NAME) {
      out.kind = 'vault';
      return out;
    }
    out.name = name;
    return out;
  }

  window.paramantHandshake = {
    __paramant: true,
    encode: encode,
    decode: decode,
    VAULT_NAME: VAULT_NAME,
    DEFAULT_TTL_MS: DEFAULT_TTL_MS,
  };
})();
