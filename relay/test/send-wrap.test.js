'use strict';

// The wrapping that keeps the promise.
//
// In the one-link flow the file key rides in the fragment of the URL, which a
// browser never sends to a server. A send to a group cannot do that: we post
// the invitations, so anything in the link passes through a mail provider.
//
// So the sender's browser wraps the file key under a key derived from each
// recipient's own token. The relay stores the wrapping and the hash of the
// token; the mail carries the token and never the wrapping. Neither half opens
// the file on its own, and these tests are what holds that apart.
//
// The module is written for a browser, so it gets a window and the two base64
// helpers here. Everything else it uses (crypto.subtle) is in Node as well,
// which is the point: the same code runs on both ends of the send.

const assert = require('node:assert/strict');
const test = require('node:test');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const SOURCE = fs.readFileSync(
  path.join(__dirname, '..', '..', 'frontend', 'js', 'send-wrap.js'), 'utf8');

const scope = { crypto: globalThis.crypto, TextEncoder, TextDecoder, Uint8Array,
                btoa: globalThis.btoa, atob: globalThis.atob, Error, String, Math, JSON };
scope.window = scope;
vm.createContext(scope);
vm.runInContext(SOURCE, scope);
const wrapLib = scope.paramantSendWrap;

// 32-byte file key plus its 12-byte IV: exactly what the one-link flow puts in
// the fragment today.
function geheim() {
  const u = new Uint8Array(44);
  globalThis.crypto.getRandomValues(u);
  return u;
}

test('a token opens its own wrapping and nothing else', async () => {
  const sleutel = geheim();
  const token = wrapLib.newToken();
  const pakket = await wrapLib.wrap(token, sleutel);

  const terug = await wrapLib.unwrap(token, pakket);
  assert.deepEqual(Array.from(terug.rawKey), Array.from(sleutel.subarray(0, 32)));
  assert.deepEqual(Array.from(terug.iv), Array.from(sleutel.subarray(32, 44)));

  const ander = wrapLib.newToken();
  await assert.rejects(() => wrapLib.unwrap(ander, pakket),
    'another recipient\'s token must not open this wrapping');
});

test('the wrapping does not contain the key it wraps', async () => {
  const sleutel = geheim();
  const token = wrapLib.newToken();
  const pakket = await wrapLib.wrap(token, sleutel);

  // What the relay stores, next to the raw bytes it is supposed to hide.
  const opgeslagen = wrapLib.fromB64url(pakket);
  const naald = Array.from(sleutel).join(',');
  assert.ok(!Array.from(opgeslagen).join(',').includes(naald),
    'the stored wrapping must not carry the key in the clear');
  assert.ok(!pakket.includes(token), 'nor the token that opens it');
});

test('two recipients of the same file get different wrappings', async () => {
  const sleutel = geheim();
  const anna = wrapLib.newToken();
  const bob = wrapLib.newToken();
  const eenA = await wrapLib.wrap(anna, sleutel);
  const eenB = await wrapLib.wrap(bob, sleutel);

  assert.notEqual(eenA, eenB, 'same key, different tokens, different wrappings');
  // And each opens only its own, so one leaked link does not open another's.
  assert.deepEqual(Array.from((await wrapLib.unwrap(anna, eenA)).rawKey),
                   Array.from((await wrapLib.unwrap(bob, eenB)).rawKey),
                   'both still recover the same file key');
  await assert.rejects(() => wrapLib.unwrap(anna, eenB));
});

test('wrapping the same key twice with the same token still differs', async () => {
  const sleutel = geheim();
  const token = wrapLib.newToken();
  const een = await wrapLib.wrap(token, sleutel);
  const twee = await wrapLib.wrap(token, sleutel);
  assert.notEqual(een, twee, 'a fresh IV each time, or the wrappings leak equality');
  assert.deepEqual(Array.from((await wrapLib.unwrap(token, een)).rawKey),
                   Array.from((await wrapLib.unwrap(token, twee)).rawKey));
});

test('a tampered wrapping is refused, not quietly opened', async () => {
  const sleutel = geheim();
  const token = wrapLib.newToken();
  const pakket = await wrapLib.wrap(token, sleutel);

  const bytes = wrapLib.fromB64url(pakket);
  bytes[bytes.length - 1] ^= 0x01;              // one bit in the tag
  await assert.rejects(() => wrapLib.unwrap(token, wrapLib.b64url(bytes)),
    'AES-GCM has to catch this, or a changed file would open as if it were fine');
});

test('rubbish in the place of a wrapping is refused', async () => {
  const token = wrapLib.newToken();
  for (const bad of ['', 'x', 'not-base64!!', wrapLib.b64url(new Uint8Array(4))]) {
    await assert.rejects(() => wrapLib.unwrap(token, bad));
  }
});

test('a token is 256 bits of randomness, and never repeats', () => {
  const gezien = new Set();
  for (let i = 0; i < 200; i++) {
    const t = wrapLib.newToken();
    assert.equal(wrapLib.fromB64url(t).length, wrapLib.TOKEN_BYTES);
    assert.ok(!gezien.has(t));
    gezien.add(t);
  }
});
