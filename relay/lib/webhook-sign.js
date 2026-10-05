'use strict';
// Webhook signatures with a timestamp (review #555, LAAG).
//
// X-Paramant-Sig is an HMAC over the body alone, so a captured delivery can be
// replayed to the receiver at any later time and still verify. Next to it
// every delivery now carries
//
//   X-Paramant-Timestamp: <unix seconds>
//   X-Paramant-Signature: t=<unix seconds>,v1=<hex HMAC_SHA256(secret, "<t>.<body>")>
//
// so the time is inside the signature and a receiver can refuse anything
// older than its replay window (verifySignature below, default 300 s).
// X-Paramant-Sig stays for receivers that already check it.
const crypto = require('crypto');

const DEFAULT_TOLERANCE_S = 300;

function hmacHex(secret, data) {
  return crypto.createHmac('sha256', String(secret)).update(data).digest('hex');
}

function signatureHeaders(secret, payload, nowMs = Date.now()) {
  if (!secret) return {};
  const t = Math.floor(nowMs / 1000);
  return {
    'X-Paramant-Timestamp': String(t),
    'X-Paramant-Signature': `t=${t},v1=${hmacHex(secret, `${t}.${payload}`)}`,
  };
}

// For receivers (and the tests): true only for a signature over this body,
// made with this secret, inside the replay window.
function verifySignature(secret, payload, header, { toleranceS = DEFAULT_TOLERANCE_S, nowMs = Date.now() } = {}) {
  const m = /^t=(\d{1,12}),v1=([0-9a-f]{64})$/.exec(String(header || ''));
  if (!m || !secret) return false;
  const t = Number(m[1]);
  if (Math.abs(Math.floor(nowMs / 1000) - t) > toleranceS) return false;
  const want = Buffer.from(hmacHex(secret, `${t}.${payload}`), 'hex');
  const got = Buffer.from(m[2], 'hex');
  return want.length === got.length && crypto.timingSafeEqual(want, got);
}

module.exports = { signatureHeaders, verifySignature, DEFAULT_TOLERANCE_S };
