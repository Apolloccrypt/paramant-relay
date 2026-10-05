'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { scanKeys } = require('../lib/redis');

function fakeClient(yields) {
  return { scanIterator: async function* () { for (const y of yields) yield y; } };
}

async function collect(gen) { const out = []; for await (const k of gen) out.push(k); return out; }

test('scanKeys vlakt v5/v6-batches (arrays) af naar losse keys', async () => {
  const c = fakeClient([['a:1', 'a:2'], ['a:3'], []]);
  assert.deepEqual(await collect(scanKeys(c, {})), ['a:1', 'a:2', 'a:3']);
});

test('scanKeys laat v4-stijl losse strings ongemoeid', async () => {
  const c = fakeClient(['a:1', 'a:2']);
  assert.deepEqual(await collect(scanKeys(c, {})), ['a:1', 'a:2']);
});

test('scanKeys op lege scan levert niets', async () => {
  assert.deepEqual(await collect(scanKeys(fakeClient([]), {})), []);
});

test('elke afgevlakte key is een string met werkende .split (de crash-site)', async () => {
  const c = fakeClient([['paramant:user:audit:pgp_x'], 'paramant:user:audit:pgp_y']);
  for (const k of await collect(scanKeys(c, {}))) {
    assert.equal(typeof k, 'string');
    assert.ok(k.split(':').pop().startsWith('pgp_'));
  }
});
