'use strict';

// One store, two products, no shared namespace.
//
// Sending a file to a named group needs what signing already has: storage that
// survives a restart, encrypted at rest, with a TTL. Building a second one would
// mean a second implementation of seal and unseal, so the existing store takes a
// prefix instead.
//
// The danger in that move is the namespace. If two products shared a key prefix
// one could read the other's documents; if they shared the AAD prefix, a sealed
// blob from one could be unsealed under the other's id even with separate keys.
// These tests hold both apart.

const assert = require('node:assert/strict');
const test = require('node:test');

const { createParaSignStore, seal, unseal } = require('../lib/parasign-store');

const KEY = Buffer.alloc(32, 7);

test('the default prefix is unchanged, so signing keeps its own keys', async () => {
  const signing = createParaSignStore({});
  await signing.putBlob('doc-1', Buffer.from('a signed document'), 60_000);
  assert.equal((await signing.getBlob('doc-1')).toString(), 'a signed document');
});

test('a second product cannot read the first product\'s documents', async () => {
  const signing = createParaSignStore({});
  const sending = createParaSignStore({ prefix: 'psend', aadPrefix: 'parasend' });

  await signing.putBlob('same-id', Buffer.from('signing side'), 60_000);
  assert.equal(await sending.getBlob('same-id'), null,
    'the same id in another namespace must be a miss, not a read');

  await sending.putBlob('same-id', Buffer.from('sending side'), 60_000);
  assert.equal((await sending.getBlob('same-id')).toString(), 'sending side');
  assert.equal((await signing.getBlob('same-id')).toString(), 'signing side',
    'and neither write disturbs the other');
});

test('deleting on one side leaves the other alone', async () => {
  const signing = createParaSignStore({});
  const sending = createParaSignStore({ prefix: 'psend', aadPrefix: 'parasend' });

  await signing.putBlob('shared', Buffer.from('keep me'), 60_000);
  await sending.putBlob('shared', Buffer.from('drop me'), 60_000);
  await sending.delBlob('shared');

  assert.equal(await sending.getBlob('shared'), null);
  assert.equal((await signing.getBlob('shared')).toString(), 'keep me');
});

test('the AAD moves with the prefix, so a sealed blob cannot cross over', () => {
  // Sealed under one product's AAD, opened under the other's: the tag must fail
  // even though the encryption key is identical. This is the half that keeps
  // separate prefixes from being cosmetic.
  const sealed = seal(Buffer.from('confidential'), KEY, 'parasign:blob:x');
  assert.equal(unseal(sealed, KEY, 'parasign:blob:x').toString(), 'confidential');
  assert.throws(() => unseal(sealed, KEY, 'parasend:blob:x'),
    'a blob sealed for signing must not open for sending');
});

test('an id that looks like a namespace cannot climb out of its own', async () => {
  const sending = createParaSignStore({ prefix: 'psend', aadPrefix: 'parasend' });
  const signing = createParaSignStore({});

  await signing.putBlob('victim', Buffer.from('signing secret'), 60_000);
  // psend:blob:<id> where id tries to walk back into psign's keyspace.
  assert.equal(await sending.getBlob('../../psign:blob:victim'), null);
  assert.equal(await sending.getBlob('psign:blob:victim'), null);
});
