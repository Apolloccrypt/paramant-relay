'use strict';
// Audit-chain tamper-evidence (#19): chain_hash binds every field and
// verifyChain actually recomputes it.
const test = require('node:test');
const assert = require('node:assert/strict');
const { auditEntryHash, verifyChain } = require('../lib/audit-chain');

// Build a chain the way auditAppend does (prev_hash links + chain_hash per entry).
function build(events) {
  const chain = [];
  for (const ev of events) {
    const prev_hash = chain.length ? chain[chain.length - 1].chain_hash : '0'.repeat(64);
    const entry = { ts: ev.ts, event: ev.event, prev_hash, ...ev.data };
    entry.chain_hash = auditEntryHash(entry);
    chain.push(entry);
  }
  return chain;
}

const sample = () => build([
  { ts: '2026-06-10T00:00:00.000Z', event: 'inbound',  data: { hash: 'a'.repeat(64), bytes: 10, device: 'dev1', views_left: 1 } },
  { ts: '2026-06-10T00:00:01.000Z', event: 'outbound', data: { hash: 'a'.repeat(64), bytes: 10, device: 'dev1', views_left: 0, sig: 'deadbeef' } },
  { ts: '2026-06-10T00:00:02.000Z', event: 'burned',   data: { hash: 'a'.repeat(64), bytes: 0 } },
]);

test('a well-formed chain verifies', () => {
  assert.equal(verifyChain(sample()), true);
});

test('tampering a hash-covered field (event) is detected', () => {
  const c = sample(); c[1].event = 'inbound';
  assert.equal(verifyChain(c), false);
});

test('tampering a RICH field the old preimage ignored (device/views_left/sig) is now detected', () => {
  for (const mut of [
    (c) => { c[0].device = 'attacker'; },
    (c) => { c[1].views_left = 99; },
    (c) => { c[1].sig = 'forged'; },
  ]) {
    const c = sample(); mut(c);
    assert.equal(verifyChain(c), false);
  }
});

test('breaking the prev_hash linkage is detected', () => {
  const c = sample(); c[2].prev_hash = '0'.repeat(64);
  assert.equal(verifyChain(c), false);
});

test('re-stamping chain_hash after a tamper still fails (linkage breaks downstream)', () => {
  const c = sample();
  c[1].views_left = 99;
  c[1].chain_hash = auditEntryHash(c[1]); // attacker recomputes this entry's hash
  // entry[2].prev_hash still points at the OLD c[1].chain_hash -> linkage breaks
  assert.equal(verifyChain(c), false);
});

test('object key order does not affect the hash (canonical)', () => {
  const e1 = { ts: 't', event: 'x', prev_hash: '0'.repeat(64), a: 1, b: 2 };
  const e2 = { b: 2, prev_hash: '0'.repeat(64), event: 'x', a: 1, ts: 't' };
  assert.equal(auditEntryHash(e1), auditEntryHash(e2));
});

test('a trimmed chain (oldest entries dropped) still verifies on the relative linkage', () => {
  const full = sample();
  const trimmed = full.slice(1); // drop the genesis entry
  assert.equal(verifyChain(trimmed), true);
});
