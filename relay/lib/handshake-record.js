'use strict';
// handshake-record.js - what the `<session>_ready` slot is allowed to hold.
//
// A live ParaSend hand-over ends with the sender posting to POST /v2/pubkey
// under `<session>_ready`, borrowing the two free text fields there: `kyber_pub`
// says what is coming, `ecdh_pub` says where the sealed blocks are. The relay
// keeps that record in memory for an hour and hands it back to anyone who knows
// the session token, without an API key.
//
// WHAT WENT WRONG. Until 5 September 2026 those two fields carried, in the
// clear, the file name ("opzegging-huurcontract.pdf|1|86400000") and, for a
// multi-file send, a JSON manifest with every file name and every file size.
// /dpa promises customers the opposite, in an article 28 agreement they sign
// electronically: "Filenames not stored in plaintext (enc_meta ciphertext
// only)". The name was never needed on the wire: it already travels inside the
// sealed chunk-0 header and the receiver reads it from there.
//
// WHY THIS FILE EXISTS RATHER THAN A FIX IN THE CLIENT. The client no longer
// sends a name, but "our client does not do that" is a convention, not a
// technical measure, and a DPA promises measures. This is the measure: on a
// `_ready` slot both fields must match a grammar with nowhere to put a name.
// Anything else is refused at the door, so the relay cannot come to hold a
// readable filename even when the thing talking to it is not our page.
//
// The grammar, in full:
//   kyber_pub   (file|vault)|<chunks>|<ttl ms>     kind and two counts
//   ecdh_pub    <48 hex>[,<48 hex>...]             one file, its blocks
//               [{"tokens":[<48 hex>,...]}, ...]   a vault, one entry per file
//
// A download token is 24 random bytes hex-encoded (relay.js mints them with
// randomBytes(24)), so it is 48 hex characters and can carry no meaning.

// Kind, block count, time to live. No third thing.
const READY_META_RE = /^(file|vault)\|\d{1,10}\|\d{1,15}$/;
const DL_TOKEN_RE = /^[a-f0-9]{48}$/;

// A vault of a thousand files is already far past anything the product sells;
// the cap is here so a malformed list cannot cost an unbounded parse.
const MAX_VAULT_FILES = 1000;

function isReadyMeta(value) {
  return typeof value === 'string' && READY_META_RE.test(value);
}

function isReadyLocation(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 65535) return false;
  // One file: a comma-separated list of download tokens.
  if (DL_TOKEN_RE.test(value.split(',')[0] || '')) {
    return value.split(',').every((t) => DL_TOKEN_RE.test(t));
  }
  // A vault: one token array per file, and not one key more on any entry. The
  // key count is what keeps a `name` or a `size` out; a whitelist of allowed
  // keys would quietly admit the next field somebody adds.
  let parsed;
  try { parsed = JSON.parse(value); } catch { return false; }
  if (!Array.isArray(parsed) || parsed.length === 0 || parsed.length > MAX_VAULT_FILES) return false;
  return parsed.every((f) => f && typeof f === 'object' && !Array.isArray(f)
    && Object.keys(f).length === 1 && Array.isArray(f.tokens)
    && f.tokens.length > 0 && f.tokens.every((t) => DL_TOKEN_RE.test(t)));
}

// The whole gate, as the route asks it.
function isCleanReadyRecord(kyberPub, ecdhPub) {
  return isReadyMeta(kyberPub) && isReadyLocation(ecdhPub);
}

module.exports = { isReadyMeta, isReadyLocation, isCleanReadyRecord, READY_META_RE, DL_TOKEN_RE };
