#!/usr/bin/env node
'use strict';
// Make the NEXT identity key of a relay before it is used, so it can be pinned
// first. RUNBOOK.md, "Relay identity key rotation".
//
// WHY. A relay signs its tree heads with its identity key, and the other relays
// only mirror heads from the key pinned for its name (lib/fleet-pins.js). If a
// relay simply starts with a fresh key, its heads are refused by the fleet and
// it stops gossiping itself, until a release pins the new key. Made this way,
// the new key exists before the switch: the release that pins it (and retires
// the old one) and the switch can go out in one deploy.
//
// Inside the relay container, where the volume and the crypto core are:
//   docker compose exec relay-health node lib/relay-identity-next.js /data/relay-identity.next.json
//
// Writes the file with mode 600 in the same format the relay reads
// (RELAY_IDENTITY_FILE), refuses to overwrite anything, and prints only the
// PUBLIC key and its fingerprint. The secret key never reaches stdout.

const fs = require('fs');
const crypto = require('crypto');

function main(argv) {
  const out = argv[2];
  if (!out) {
    console.error('usage: node lib/relay-identity-next.js <path for the new identity file>');
    return 2;
  }
  if (fs.existsSync(out)) {
    console.error(`refusing: ${out} already exists. An identity file is never overwritten.`);
    return 1;
  }
  require('../crypto/bootstrap').bootstrap();
  const kp = require('../crypto/registry').getSig(0x0002).generateKeyPair();
  const sk = Buffer.from(kp.secretKey);
  const pk = Buffer.from(kp.publicKey);
  const fingerprint = crypto.createHash('sha3-256').update(pk).digest('hex');
  fs.writeFileSync(out, JSON.stringify({ sk: sk.toString('base64'), pk: pk.toString('base64'), created_at: new Date().toISOString() }),
    { mode: 0o600, flag: 'wx' });
  console.log(JSON.stringify({ file: out, alg: 'ML-DSA-65', fingerprint, key: pk.toString('base64') }, null, 2));
  return 0;
}

if (require.main === module) process.exit(main(process.argv));
module.exports = { main };
