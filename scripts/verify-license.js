#!/usr/bin/env node
/**
 * Paramant License Key Verifier
 *
 * Verifies a plk_ license key using the hardcoded Ed25519 public key.
 * This is the same verification logic as relay.js — useful for debugging.
 *
 * Usage:
 *   node scripts/verify-license.js <plk_key>
 *   node scripts/verify-license.js plk_eyJtYXhfa2V5cyI6InVubGltaXRlZCIs...
 */

'use strict';
const crypto = require('crypto');

// Same public key hardcoded in relay.js
const ED25519_PUBLIC_KEY  = 'ed8a6201c86f013b16718b3e6d9ded62362ca82ef7ae334308c12d71d18ae4e6';
const ED25519_DER_PREFIX  = Buffer.from('302a300506032b6570032100', 'hex');

function b64urlDecode(s) {
  const p = s.replace(/-/g, '+').replace(/_/g, '/');
  return Buffer.from(p + '='.repeat((4 - p.length % 4) % 4), 'base64');
}

const rawKey = process.argv[2] || '';
if (!rawKey) {
  console.error('Usage: node scripts/verify-license.js <plk_key>');
  process.exit(1);
}

if (!rawKey.startsWith('plk_')) {
  console.error('Error: key must start with plk_');
  process.exit(1);
}

try {
  const combined   = b64urlDecode(rawKey.slice(4));
  if (combined.length < 65) throw new Error('token too short');
  const sig        = combined.subarray(combined.length - 64);
  const payloadBuf = combined.subarray(0, combined.length - 64);

  const pubDer = Buffer.concat([ED25519_DER_PREFIX, Buffer.from(ED25519_PUBLIC_KEY, 'hex')]);
  const pubKey = crypto.createPublicKey({ key: pubDer, format: 'der', type: 'spki' });
  const valid  = crypto.verify(null, payloadBuf, pubKey, sig);

  const payload = JSON.parse(payloadBuf.toString('utf8'));
  const expiresAt = new Date(payload.expires_at);
  const expired = expiresAt < new Date();

  console.log('\nPayload:');
  console.log(JSON.stringify(payload, null, 2));
  console.log(`\nSignature: ${valid ? 'VALID' : 'INVALID'}`);
  if (valid) {
    console.log(`Expiry:    ${payload.expires_at} (${expired ? 'EXPIRED' : 'valid'})`);
    console.log(`Max keys:  ${payload.max_keys}`);
    console.log(`Issued to: ${payload.issued_to}`);
    if (expired) {
      console.log('\nWARNING: This key is expired. The relay will fall back to Community Edition.');
      process.exit(2);
    }
  } else {
    console.error('\nERROR: Signature verification failed — key is invalid or was not issued by Paramant.');
    process.exit(1);
  }
} catch (e) {
  console.error(`\nError: ${e.message}`);
  process.exit(1);
}
