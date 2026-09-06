// handshake-meta.js - one reading of the ParaSend handshake field.
//
// WHAT THE FIELD IS
//
// A live ParaSend hand-over ends with the sender posting a small record to
// /v2/pubkey under the key `<session>_ready`. The relay has exactly two free
// text fields there, `ecdh_pub` and `kyber_pub`, so the sender borrows the
// second one to say what is coming: whether it is one file or a vault, how many
// sealed blocks it was cut into, and how long our copy is held.
//
// WHY THERE IS NO FILE NAME IN IT ANY MORE
//
// Until 5 September 2026 the first field was the file name, in the clear:
//
//     opzegging-huurcontract.pdf|1|86400000
//
// The relay stored that verbatim for an hour and handed it back to anyone who
// knew the session token. /dpa promises the opposite, in a contract customers
// sign: "Filenames not stored in plaintext (enc_meta ciphertext only)". A file
// name is not a label for the content, it very often IS the content.
//
// The name was never needed here. It already travels inside the sealed bytes,
// in the chunk-0 metadata header that ML-KEM-768 + ECDH P-256 + AES-256-GCM
// protects, and /ontvang overwrites the handshake value with that one before it
// opens the save dialog or paints anything. So the plaintext copy was a
// duplicate with no reader, and the fix is not to encrypt it twice but to stop
// writing the duplicate.
//
// The first field is therefore a KIND and never user content. This module has
// no parameter that could carry a name, which is what keeps the promise true
// when somebody adds the next caller.
//
// THE BUG THIS ALSO EXISTS TO KILL
//
// The two sides had drifted apart. parashare.page.js wrote three fields and
// ontvang.page.js read two, so the receiver took the file name for the block
// count and the block count for the time to live. A single-block transfer
// became `ttl_ms = 1`, and /ontvang printed a line saying our copy had expired
// at a clock time worked out from it. The line was removed on 4 September 2026
// (#427). Neither page parses the field itself any more; both call this, so the
// writing and the reading can only ever change together.
//
// THE FORMAT, and how an older sender still gets through
//
//   kinded  file|chunks|ttl        one file, cut into `chunks` sealed blocks
//           vault|count|ttl        a multi-file vault of `count` files
//   named   <name>|chunks|ttl      a sender minted before 5 September 2026
//   legacy  chunks|ttl             a sender minted before the first field existed
//
// Told apart on the number of fields: a third field is the kind. The numbers
// are read from the END of the string, so a legacy sender whose file name
// contained a "|" still leaves chunks and ttl in the right place. A first field
// that is neither `file` nor `vault` is an old sender's file name, and it is
// dropped on the floor here rather than handed on: no caller can use what it
// never receives. `kind` stays a hint that the caller confirms, because a
// pre-5-September file named exactly "vault" is a case the shape cannot settle
// on its own; /ontvang treats the record as a vault only when the other field
// really does hold a JSON list.

'use strict';

(function () {
  if (window.paramantHandshake && window.paramantHandshake.__paramant) return;

  // What a receiver falls back to when the field says nothing usable. One hour
  // is the shortest life any plan gives a blob, so it is the safe assumption.
  var DEFAULT_TTL_MS = 3600000;
  var VAULT_KIND = 'vault';
  var FILE_KIND = 'file';

  function positiveInt(value, fallback) {
    var n = parseInt(value, 10);
    return isFinite(n) && n > 0 ? n : fallback;
  }

  // Write the field. `kind` is 'vault' for a multi-file send and 'file' for one
  // file; a vault carries its file count where a single send carries its block
  // count, which is what the old code did too. There is deliberately no way to
  // put a file name in here.
  function encode(meta) {
    meta = meta || {};
    var ttlMs = positiveInt(meta.ttlMs, DEFAULT_TTL_MS);
    var chunks = positiveInt(meta.chunks, 1);
    var kind = meta.kind === VAULT_KIND ? VAULT_KIND : FILE_KIND;
    return kind + '|' + chunks + '|' + ttlMs;
  }

  // Read the field. Always answers with the same three keys, whatever came in,
  // so no caller has to check the shape before using it. There is no `name` in
  // the answer: an old sender's name is read off the wire and discarded here.
  function decode(value) {
    var raw = String(value == null ? '' : value);
    var parts = raw.split('|');
    var out = { kind: FILE_KIND, chunks: 1, ttlMs: DEFAULT_TTL_MS, format: 'unknown' };
    if (parts.length < 2) return out;
    out.ttlMs = positiveInt(parts[parts.length - 1], DEFAULT_TTL_MS);
    out.chunks = positiveInt(parts[parts.length - 2], 1);
    if (parts.length === 2) {
      out.format = 'legacy';
      return out;
    }
    var first = parts.slice(0, parts.length - 2).join('|');
    if (first === VAULT_KIND) {
      out.kind = VAULT_KIND;
      out.format = 'kinded';
      return out;
    }
    out.format = first === FILE_KIND ? 'kinded' : 'named';
    return out;
  }

  window.paramantHandshake = {
    __paramant: true,
    encode: encode,
    decode: decode,
    VAULT_KIND: VAULT_KIND,
    FILE_KIND: FILE_KIND,
    DEFAULT_TTL_MS: DEFAULT_TTL_MS,
  };
})();
