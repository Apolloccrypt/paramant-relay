/* Wrapping the file key for one named recipient.
 *
 * WHY THIS EXISTS. In the ordinary one-link flow the file key rides in the
 * fragment of the URL, after the #, which browsers never send to a server. That
 * is what lets Paramant say it cannot open what it stores.
 *
 * A send to a group cannot use that trick: we post the invitations, so anything
 * in the link travels through a mail provider anyway. Putting the key there
 * would mean the provider can open the file, and the code we mail afterwards
 * would be no extra lock at all, because it goes to the very same mailbox.
 *
 * So the key is wrapped here, in the sender's browser, under a key derived from
 * each recipient's own token. The relay gets the wrapping and the HASH of the
 * token. The mail carries the token and never the wrapping.
 *
 *   relay          holds a locked box, and no key to it
 *   mail provider  carries a key, and has never seen the box
 *
 * Neither half is enough. That is the whole point, and it is why the relay must
 * not write the token down, not even for the length of a send.
 *
 * Used by both ends: parashare.page.js wraps, ophalen.page.js unwraps. Keep the
 * two in step by keeping them in this one file.
 */
(function (global) {
  'use strict';

  // Domain separation. A key derived for wrapping must never collide with any
  // other value derived from the same token elsewhere in the product.
  var LABEL = 'paramant/send-wrap/v1\u0000';
  var TOKEN_BYTES = 32;

  function b64url(u8) {
    var s = '';
    for (var i = 0; i < u8.length; i += 0x8000) {
      s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
    }
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function fromB64url(s) {
    var b = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
    while (b.length % 4) b += '=';
    var raw = atob(b);
    var out = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
    return out;
  }

  function concat() {
    var total = 0, i;
    for (i = 0; i < arguments.length; i++) total += arguments[i].length;
    var out = new Uint8Array(total), at = 0;
    for (i = 0; i < arguments.length; i++) { out.set(arguments[i], at); at += arguments[i].length; }
    return out;
  }

  function newToken() {
    return b64url(crypto.getRandomValues(new Uint8Array(TOKEN_BYTES)));
  }

  // The wrapping key for one token. SHA-256 over a label and the token: the
  // token is 256 bits of randomness, so there is nothing to stretch and a KDF
  // would add ceremony without adding strength.
  async function wrapKeyFor(token) {
    var material = concat(new TextEncoder().encode(LABEL),
                          new TextEncoder().encode(String(token || '')));
    var digest = new Uint8Array(await crypto.subtle.digest('SHA-256', material));
    return crypto.subtle.importKey('raw', digest, { name: 'AES-GCM' }, false,
                                   ['encrypt', 'decrypt']);
  }

  // secret is the 44 bytes the one-link flow puts in the fragment: the 32-byte
  // file key followed by its 12-byte IV. Returns base64url of iv || ciphertext.
  async function wrap(token, secret) {
    var key = await wrapKeyFor(token);
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, secret));
    return b64url(concat(iv, ct));
  }

  // Throws when the token does not belong to this wrapping, which is what an
  // altered link or a swapped record looks like. The caller turns that into a
  // refusal rather than a broken download.
  async function unwrap(token, wrapped) {
    var raw = fromB64url(wrapped);
    if (raw.length < 13) throw new Error('wrapped key too short');
    var key = await wrapKeyFor(token);
    var iv = raw.subarray(0, 12);
    var ct = raw.subarray(12);
    var plain = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct));
    if (plain.length !== 44) throw new Error('unexpected key material');
    return { rawKey: plain.subarray(0, 32), iv: plain.subarray(32, 44) };
  }

  // ── a code the sender passes on in person ─────────────────────────────────
  //
  // WHY. The token travels in the invitation, and the code that proves the
  // mailbox goes to that same mailbox. Whoever can read that mailbox, or the
  // mail provider that carries both, holds everything the wrapping above asks
  // for. When the sender ticks "Ik geef de code zelf door", a third half is
  // added that never touches a mail or a server: a code this browser makes and
  // the sender reads out over the phone or sends through an app.
  //
  // THE SHAPE. Ten characters from 31: the digits 2 to 9 and the capitals
  // without I, L and O, so nothing on the phone can be mistaken for something
  // else (no 0/O, no 1/I/L). Shown as two groups of five. That is 49.5 bits.
  // Words would be easier to say, but four words from a list small enough to
  // ship here are around 44 bits, and a word list in two languages is a second
  // thing to keep in step.
  //
  // WHY THAT IS ENOUGH. Guessing has two doors and both are closed.
  //   online   the relay only hands out the wrapping after the proof below
  //            matches, and five wrong proofs close the link for good.
  //   offline  only somebody holding the token AND the stored wrapping AND the
  //            stored check can try codes at home. Every guess then costs one
  //            PBKDF2-SHA256 run of 600 000 rounds (the OWASP figure for this
  //            hash), so 2^48 guesses on average is centuries of GPU time.
  //
  // THE ORDER OF DERIVATION. PBKDF2 runs once per send, over the code and a
  // random salt, because thirty recipients times a second of stretching is a
  // sender waiting half a minute. Each recipient's keys then come from HKDF
  // over that result with their own token as salt, so the relay, which never
  // has a token, cannot test a guess against what it stores either.
  //
  // Out of HKDF come 64 bytes: the first 32 are the AES key that wraps the
  // file key, the last 32 are the PROOF. The relay keeps SHA-256 of the proof,
  // the recipient's page sends the proof itself when it collects. Neither is
  // the code, and neither opens the wrapping.
  var CODE_ALPHABET = '23456789ABCDEFGHJKMNPQRSTUVWXYZ';
  var CODE_LEN = 10;
  var CODE_ROUNDS = 600000;
  var CODE_SALT_BYTES = 16;
  var CODE_LABEL = 'paramant/send-wrap/sender-code/v1\u0000';

  function newSenderCode() {
    var out = '';
    // Rejection sampling: 248 is the largest multiple of 31 under 256, so every
    // character is equally likely and the 49.5 bits are real.
    while (out.length < CODE_LEN) {
      var b = crypto.getRandomValues(new Uint8Array(16));
      for (var i = 0; i < b.length && out.length < CODE_LEN; i++) {
        if (b[i] < 248) out += CODE_ALPHABET.charAt(b[i] % 31);
      }
    }
    return out;
  }

  // What a person typed, as the code it was meant to be. Spaces, dashes and
  // lower case are forgiven; anything outside the alphabet is not guessed at.
  function normaliseCode(input) {
    var s = String(input || '').toUpperCase().replace(/[\s\-_.]+/g, '');
    if (s.length !== CODE_LEN) return '';
    for (var i = 0; i < s.length; i++) {
      if (CODE_ALPHABET.indexOf(s.charAt(i)) < 0) return '';
    }
    return s;
  }

  function formatCode(code) {
    var s = normaliseCode(code) || String(code || '');
    return s.slice(0, 5) + '-' + s.slice(5);
  }

  function newCodeSalt() {
    return b64url(crypto.getRandomValues(new Uint8Array(CODE_SALT_BYTES)));
  }

  // The slow half, once per send. Returns raw bytes for codeKeysFor.
  async function stretchCode(code, saltB64) {
    var schoon = normaliseCode(code);
    if (!schoon) throw new Error('bad sender code');
    var basis = await crypto.subtle.importKey('raw', new TextEncoder().encode(schoon),
                                              'PBKDF2', false, ['deriveBits']);
    var salt = concat(new TextEncoder().encode(CODE_LABEL), fromB64url(saltB64));
    return new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt: salt, iterations: CODE_ROUNDS }, basis, 256));
  }

  // The fast half, once per recipient: the wrap key and the proof.
  async function codeKeysFor(token, stretched) {
    var ikm = await crypto.subtle.importKey('raw', stretched, 'HKDF', false, ['deriveBits']);
    var bits = new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256',
        salt: new TextEncoder().encode(String(token || '')),
        info: new TextEncoder().encode(CODE_LABEL + 'keys') }, ikm, 512));
    var key = await crypto.subtle.importKey('raw', bits.subarray(0, 32), { name: 'AES-GCM' },
                                            false, ['encrypt', 'decrypt']);
    var proof = bits.slice(32, 64);
    var check = new Uint8Array(await crypto.subtle.digest('SHA-256', proof));
    return { key: key, proof: b64url(proof), check: b64url(check) };
  }

  // Wrap under the token AND the code. The token layer stays exactly as it is,
  // and the code layer goes round it: without the code the outer box does not
  // open, without the token the inner one does not.
  async function wrapWithCode(token, secret, stretched) {
    var inner = fromB64url(await wrap(token, secret));
    var k = await codeKeysFor(token, stretched);
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, k.key, inner));
    return { wrapped_key: b64url(concat(iv, ct)), code_check: k.check };
  }

  async function unwrapWithCode(token, wrapped, stretched) {
    var raw = fromB64url(wrapped);
    if (raw.length < 13) throw new Error('wrapped key too short');
    var k = await codeKeysFor(token, stretched);
    var inner = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: raw.subarray(0, 12) }, k.key, raw.subarray(12)));
    return unwrap(token, b64url(inner));
  }

  async function proofFor(token, stretched) {
    return (await codeKeysFor(token, stretched)).proof;
  }

  global.paramantSendWrap = { newToken, wrap, unwrap, b64url, fromB64url, concat, TOKEN_BYTES,
    newSenderCode, normaliseCode, formatCode, newCodeSalt, stretchCode, codeKeysFor,
    wrapWithCode, unwrapWithCode, proofFor,
    CODE_ALPHABET, CODE_LEN, CODE_ROUNDS };
})(window);
