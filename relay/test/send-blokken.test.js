'use strict';

// A file that does not fit in one block, end to end.
//
// A link is one sealed 5 MB block, because /get fetches a single token. A send
// to named recipients does not have that constraint: the blocks go up one by
// one and POST /v2/sends joins them. Before this, the browser refused anything
// over 5 MB on BOTH paths, so the whole feature -- built for a care provider
// who wanted to send one document to twenty people -- could not carry a real
// document at all.
//
// The join has to be exact. These bytes are one AES-GCM ciphertext whose tag
// covers the whole file: one byte out of place anywhere and the recipient gets
// an OperationError instead of their document, with their one-time link spent.

const assert = require('node:assert/strict');
const test = require('node:test');
const crypto = require('crypto');

const LINK_MAX_BLOB = 5 * 1024 * 1024;

// What the sender's browser does: seal once, then cut the ciphertext up.
async function verzegel(naam, inhoud) {
  const naamBytes = Buffer.from(naam, 'utf8');
  const kop = Buffer.alloc(4);
  kop.writeUInt32LE(naamBytes.length, 0);
  const plain = Buffer.concat([kop, naamBytes, inhoud]);

  const rawKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', rawKey, iv);
  const ct = Buffer.concat([c.update(plain), c.final(), c.getAuthTag()]);

  const stukken = [];
  for (let at = 0; at < ct.length; at += LINK_MAX_BLOB) {
    stukken.push(ct.subarray(at, Math.min(at + LINK_MAX_BLOB, ct.length)));
  }
  return { rawKey, iv, stukken, ct };
}

// What the recipient's browser does with what the relay hands back.
function open(rawKey, iv, bytes) {
  const tag = bytes.subarray(bytes.length - 16);
  const body = bytes.subarray(0, bytes.length - 16);
  const d = crypto.createDecipheriv('aes-256-gcm', rawKey, iv);
  d.setAuthTag(tag);
  const plain = Buffer.concat([d.update(body), d.final()]);
  const naamLen = plain.readUInt32LE(0);
  return { naam: plain.subarray(4, 4 + naamLen).toString('utf8'),
           inhoud: plain.subarray(4 + naamLen) };
}

test('a 12 MB document survives being cut up and joined again', async () => {
  const inhoud = crypto.randomBytes(12 * 1024 * 1024);
  const { rawKey, iv, stukken } = await verzegel('jaarrekening-2025.pdf', inhoud);

  assert.equal(stukken.length, 3, 'twelve megabytes is three blocks of five');
  for (const s of stukken) {
    assert.ok(s.length <= LINK_MAX_BLOB, 'no block may be over the wire ceiling');
  }

  // This is POST /v2/sends: Buffer.concat over the blocks, in order.
  const uit = open(rawKey, iv, Buffer.concat(stukken));
  assert.equal(uit.naam, 'jaarrekening-2025.pdf');
  assert.ok(uit.inhoud.equals(inhoud), 'byte for byte the file that went in');
});

test('blocks joined in the wrong order are refused, not quietly opened', async () => {
  const { rawKey, iv, stukken } = await verzegel('a.pdf', crypto.randomBytes(11 * 1024 * 1024));
  const omgedraaid = [stukken[1], stukken[0], stukken[2]];
  assert.throws(() => open(rawKey, iv, Buffer.concat(omgedraaid)),
    'the tag covers the whole file, so a swap has to fail loudly');
});

test('one missing block is refused', async () => {
  const { rawKey, iv, stukken } = await verzegel('a.pdf', crypto.randomBytes(11 * 1024 * 1024));
  assert.throws(() => open(rawKey, iv, Buffer.concat([stukken[0], stukken[2]])));
});

test('a file under five megabytes is still exactly one block', async () => {
  const { stukken } = await verzegel('brief.pdf', crypto.randomBytes(1024));
  assert.equal(stukken.length, 1,
    'the one-link flow must keep working unchanged, and it fetches one token');
});

test('the block count is what the route and the plan have to allow', async () => {
  const tiers = require('../lib/tiers');
  // 512 hashes is the route ceiling; file_mb is what the plan sells. The two
  // have to leave room for each other or a send the plan allows is refused on
  // a technicality the sender cannot see.
  for (const plan of ['community', 'pro', 'business']) {
    const mb = tiers.tierLimitNum(plan, 'file_mb');
    const blokken = Math.ceil((mb * 1048576) / LINK_MAX_BLOB);
    assert.ok(blokken <= 512,
      plan + ' sells ' + mb + ' MB, which is ' + blokken + ' blocks, over the route ceiling of 512');
  }
});
