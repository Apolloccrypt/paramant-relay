'use strict';

// A valid `sealed` block for a list of addresses.
//
// A send to named recipients is refused without one, and that refusal is the
// point: the file key is wrapped in the sender's browser under each
// recipient's own token, and a send whose recipients cannot open the bytes is
// worse than no send at all. So every test that makes a send has to bring the
// wrappings a real browser would, and this is the one place that shape is
// written down.
//
// The wrappings here are random bytes, not real ones. Tests that care about
// the crypto itself use frontend/js/send-wrap.js through send-wrap.test.js;
// the layers below only ever store the wrapping and hand it back.

const crypto = require('crypto');
const tiers = require('../lib/tiers');

function b64url(buf) {
  return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function nieuwToken() {
  return b64url(crypto.randomBytes(32));
}

// Keyed on the NORMALISED address, because that is what checkRecipients hands
// back and therefore what buildRecipients looks up.
function sealedVoor(lijst) {
  const uit = Object.create(null);
  for (const raw of (Array.isArray(lijst) ? lijst : [lijst])) {
    const adres = tiers.normaliseAddress(raw);
    if (!adres) continue;
    uit[adres] = { token: nieuwToken(), wrapped_key: b64url(crypto.randomBytes(60)) };
  }
  return uit;
}

module.exports = { sealedVoor, nieuwToken, b64url };
