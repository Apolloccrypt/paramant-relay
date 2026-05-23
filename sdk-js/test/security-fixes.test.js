// Regression tests for the 3.1.0 security fixes (audit 2026-05-23).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'paramant-secfix-'));
process.env.HOME = HOME; process.env.USERPROFILE = HOME;

const { GhostPipe, GhostPipeError, SignatureError, SIG, computeFingerprint,
        wireEncode, wireDecode, buildAAD } = await import('../index.js');
const { ml_dsa65 } = await import('@noble/post-quantum/ml-dsa.js');

const gp = (device, opts = {}) => new GhostPipe({ apiKey: 'pgp_testkey_0123456789abcdef',
  device, relay: 'https://offline.invalid', checkCapabilities: false, ...opts });
const TE = (s) => new TextEncoder().encode(s);
const concat = (...a) => { const t = a.reduce((s, x) => s + x.length, 0), o = new Uint8Array(t); let k = 0; for (const x of a) { o.set(x, k); k += x.length; } return o; };

test('F1: tampered signature is rejected', async () => {
  const s = gp('s'), r = gp('r');
  const { blob } = await s._encrypt(TE('authentic'), (await r._loadKeypair()).kem_pub, { padBlock: 64 * 1024 });
  const p = wireDecode(blob);
  const bad = Uint8Array.from(p.signature); bad[0] ^= 0xff;
  const forged = wireEncode({ kemId: p.kemId, sigId: p.sigId, ctKem: p.ctKem, senderPub: p.senderPub,
    signature: bad, nonce: p.nonce, ciphertext: p.ciphertext });
  await assert.rejects(() => r._decrypt(forged), SignatureError);
});

test('F1: swapped sender key rejected when pinned', async () => {
  const s = gp('s2'), r = gp('r2');
  const { blob } = await s._encrypt(TE('authentic'), (await r._loadKeypair()).kem_pub, { padBlock: 64 * 1024 });
  const p = wireDecode(blob);
  const atk = ml_dsa65.keygen();
  const aad = buildAAD({ kemId: p.kemId, sigId: p.sigId, chunkIndex: 0 });
  const msg = concat(p.ctKem, atk.publicKey, p.nonce, p.ciphertext, aad);
  const forged = wireEncode({ kemId: p.kemId, sigId: p.sigId, ctKem: p.ctKem, senderPub: atk.publicKey,
    signature: ml_dsa65.sign(msg, atk.secretKey), nonce: p.nonce, ciphertext: p.ciphertext });
  assert.equal(new TextDecoder().decode(await r._decrypt(forged)), 'authentic'); // valid for attacker key
  const real = Uint8Array.from(Buffer.from((await s._loadKeypair()).sig_pub, 'hex'));
  await assert.rejects(() => r._decrypt(forged, '', { expectedSenderSigPub: real }), SignatureError);
});

test('F3: fingerprint binds the signing key (5 groups, 20 hex)', async () => {
  const kem = 'aa'.repeat(1184);
  const fp1 = await computeFingerprint(kem, 'bb'.repeat(1952));
  const fp2 = await computeFingerprint(kem, 'cc'.repeat(1952));
  assert.notEqual(fp1, fp2);
  assert.equal(fp1.replace(/-/g, '').length, 20);
});

test('F4: unimplemented algorithm id throws at construction', () => {
  assert.throws(() => gp('x', { kemId: 0x00ff }));
});

test('F2: receipt verified locally; forgery and missing-key rejected', async () => {
  const relayId = ml_dsa65.keygen();
  const receipt = { hash: 'abc', burn_confirmed: true, sector: 'health' };
  const canon = (v) => Array.isArray(v) ? '[' + v.map(canon).join(',') + ']'
    : (v && typeof v === 'object') ? '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + canon(v[k])).join(',') + '}'
    : JSON.stringify(v);
  const sig = Buffer.from(ml_dsa65.sign(TE(canon(receipt)), relayId.secretKey)).toString('hex');
  const pinned = gp('r', { relayIdentityPub: Buffer.from(relayId.publicKey).toString('hex') });
  assert.ok((await pinned.verifyReceipt({ ...receipt, sig })).verified_locally);
  await assert.rejects(() => pinned.verifyReceipt({ ...receipt, burn_confirmed: false, sig }), GhostPipeError);
  await assert.rejects(() => gp('r2').verifyReceipt({ ...receipt, sig }), GhostPipeError);
});
