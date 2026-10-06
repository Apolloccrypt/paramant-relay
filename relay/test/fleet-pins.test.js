'use strict';
// lib/fleet-pins.js: who may speak for which relay name, and when a relay may
// talk to the production fleet at all.
//
// The second half is the one that matters for test stacks. Measured on
// 2026-10-06: production mirrored heads from local acceptance runs
// (relay.telling.test, relay.p10-test.nl, and 15 fresh keys named
// https://health.paramant.app). docker-compose.yml defaults RELAY_SELF_URL_* to
// the paramant.app names, so the sister relays of a local stack registered with
// the local health under production URLs, and that health gossiped its heads to
// the real fleet. mayTalkToParamantFleet is the gate broadcastSTH and
// registerSelf now pass through; a route test cannot cover it without sending
// to production on main, so it is held here, plus a static check that relay.js
// really calls it on both paths.
// Run: node --test relay/test/fleet-pins.test.js

const { test, after } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const { summary } = require('./_requires');
const pins = require('../lib/fleet-pins');

let checks = 0;
const did = () => { checks++; };
after(() => summary('fleet-pins', checks));

const HEALTH = pins.PARAMANT_FLEET['health.paramant.app'];
const OTHER = 'a'.repeat(64);

test('relay_id reduces to one host whether it is a URL or a bare name', () => {
  assert.strictEqual(pins.hostOfRelayId('https://Health.Paramant.App/'), 'health.paramant.app');
  assert.strictEqual(pins.hostOfRelayId('health.paramant.app'), 'health.paramant.app');
  assert.strictEqual(pins.hostOfRelayId('http://127.0.0.1:3001'), '127.0.0.1:3001');
  assert.strictEqual(pins.hostOfRelayId(''), null);
  did();
});

test('classifyPeer: pinned name needs pinned key, pinned key keeps its name', () => {
  const p = pins.buildPins('');
  assert.strictEqual(pins.classifyPeer(p, 'https://health.paramant.app', HEALTH).verdict, 'pinned');
  assert.deepStrictEqual(pins.classifyPeer(p, 'https://health.paramant.app', OTHER).reason, 'relay_id_pinned_to_other_key');
  assert.deepStrictEqual(pins.classifyPeer(p, 'https://relay.telling.test', HEALTH).reason, 'pinned_key_other_relay_id');
  assert.deepStrictEqual(pins.classifyPeer(p, 'https://admin.paramant.app', OTHER).reason, 'unpinned_paramant_host');
  assert.strictEqual(pins.classifyPeer(p, 'https://relay.p10-test.nl', OTHER).verdict, 'unpinned');
  did();
});

test('PEER_STH_PINS adds pins but can never replace a Paramant pin', () => {
  const p = pins.buildPins(`health.paramant.app=${OTHER}, https://relay.example.org=${'b'.repeat(64)}, junk, x=nothex`);
  assert.strictEqual(p.byHost.get('health.paramant.app'), HEALTH);
  assert.strictEqual(p.byHost.get('relay.example.org'), 'b'.repeat(64));
  assert.ok(!p.byHost.has('x'));
  did();
});

test('only a pinned Paramant relay, outside test/dev, may talk to the production fleet', () => {
  const p = pins.buildPins('');
  const prod = { env: { NODE_ENV: 'production' }, selfUrl: 'https://health.paramant.app', selfPkHash: HEALTH, pins: p };
  assert.strictEqual(pins.mayTalkToParamantFleet(prod), true, 'the real health relay keeps gossiping');
  // A local compose stack: production URL by default, but its own fresh key.
  assert.strictEqual(pins.mayTalkToParamantFleet({ ...prod, selfPkHash: OTHER }), false);
  // A test or dev run, even with a copied production identity.
  assert.strictEqual(pins.mayTalkToParamantFleet({ ...prod, env: { NODE_ENV: 'test' } }), false);
  assert.strictEqual(pins.mayTalkToParamantFleet({ ...prod, env: { NODE_ENV: 'development' } }), false);
  // A self-host on its own name.
  assert.strictEqual(pins.mayTalkToParamantFleet({ ...prod, selfUrl: 'https://relay.example.org', selfPkHash: OTHER }), false);
  // Explicit, both ways.
  assert.strictEqual(pins.mayTalkToParamantFleet({ ...prod, selfPkHash: OTHER, env: { PARAMANT_FLEET_GOSSIP: '1' } }), true);
  assert.strictEqual(pins.mayTalkToParamantFleet({ ...prod, env: { PARAMANT_FLEET_GOSSIP: '0' } }), false);
  assert.ok(pins.isParamantUrl('https://relay.paramant.app/v2/sth/ingest'));
  assert.ok(!pins.isParamantUrl('http://relay-health:3000'));
  assert.ok(!pins.isParamantUrl('https://notparamant.app'));
  did();
});

test('relay.js routes both outbound paths to the fleet through the gate', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'relay.js'), 'utf8');
  const fn = (name) => {
    const at = src.indexOf(`function ${name}(`);
    assert.ok(at >= 0, `${name} not found in relay.js`);
    return src.slice(at, at + 2500);
  };
  assert.match(fn('broadcastSTH'), /mayTalkToParamantFleet\(\)/, 'broadcastSTH does not consult the fleet gate');
  assert.match(fn('registerSelf'), /mayTalkToParamantFleet\(\)/, 'registerSelf does not consult the fleet gate');
  did();
});
