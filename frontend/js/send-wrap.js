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

  global.paramantSendWrap = { newToken, wrap, unwrap, b64url, fromB64url, concat, TOKEN_BYTES };
})(window);
