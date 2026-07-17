// Unit tests for the ParaID issuer registry: DID binding, duplicates, bad keys,
// revocation visibility, and reload from disk.
import test from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'module';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import crypto from 'crypto';
const require = createRequire(import.meta.url);
const { createRegistry, MLDSA65_PK_BYTES } = require('../relay/lib/paraid-registry.js');

function freshRegistry() {
  const file = join(mkdtempSync(join(tmpdir(), 'paraid-')), 'issuers.json');
  const reg = createRegistry({ file });
  reg.load();
  return { reg, file };
}

test('R1 add derives the DID from the key and lists it active', () => {
  const { reg } = freshRegistry();
  const pk = crypto.randomBytes(MLDSA65_PK_BYTES);
  const r = reg.add({ label: 'Gemeente Demo', publicKeyB64: pk.toString('base64') });
  assert.equal(r.ok, true);
  const expect = 'did:paramant:' + crypto.createHash('sha3-256').update(pk).digest('base64url').slice(0, 32);
  assert.equal(r.issuer.did, expect);
  assert.equal(reg.list().length, 1);
  assert.equal(reg.list()[0].status, 'active');
});

test('R2 duplicate active issuer is rejected', () => {
  const { reg } = freshRegistry();
  const pk = crypto.randomBytes(MLDSA65_PK_BYTES);
  assert.equal(reg.add({ label: 'Een', publicKeyB64: pk.toString('base64') }).ok, true);
  assert.equal(reg.add({ label: 'Twee', publicKeyB64: pk.toString('base64') }).ok, false);
});

test('R3 malformed keys and labels are rejected', () => {
  const { reg } = freshRegistry();
  assert.equal(reg.add({ label: 'Kapot', publicKeyB64: 'AAAA' }).ok, false);
  assert.equal(reg.add({ label: '', publicKeyB64: crypto.randomBytes(MLDSA65_PK_BYTES).toString('base64') }).ok, false);
  assert.equal(reg.add({ label: 'x'.repeat(200), publicKeyB64: crypto.randomBytes(MLDSA65_PK_BYTES).toString('base64') }).ok, false);
});

test('R4 revocation stays visible in the public list', () => {
  const { reg } = freshRegistry();
  const r = reg.add({ label: 'Bank Demo', publicKeyB64: crypto.randomBytes(MLDSA65_PK_BYTES).toString('base64') });
  assert.equal(reg.revoke(r.issuer.did).ok, true);
  assert.equal(reg.list().length, 1);
  assert.equal(reg.list()[0].status, 'revoked');
  assert.ok(reg.list()[0].revoked_at);
  assert.equal(reg.revoke(r.issuer.did).ok, false);
  assert.equal(reg.revoke('did:paramant:bestaatniet').ok, false);
});

test('R5 registry survives a reload from disk', async () => {
  const { reg, file } = freshRegistry();
  const r = reg.add({ label: 'Persist', publicKeyB64: crypto.randomBytes(MLDSA65_PK_BYTES).toString('base64') });
  await new Promise((res) => setTimeout(res, 80));
  const reg2 = createRegistry({ file });
  assert.equal(reg2.load(), 1);
  assert.equal(reg2.get(r.issuer.did).label, 'Persist');
});
