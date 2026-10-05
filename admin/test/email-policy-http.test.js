'use strict';
// De e-mailblocklist, door de echte admin heen: /api/user/signup en
// /api/drop/upload weigeren een wegwerpadres met de rustige melding, laten
// proton en tuta door, en het log noemt alleen het domein.
//
// De ontvangerskant (groepsverzending, /ontvang, ophaalcode) zit in de relay
// en in de uitnodigingsroutes; email-policy.test.js legt vast dat die de lijst
// niet eens kennen.
//
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test admin/test/email-policy-http.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll, stubRelay, defaultRelayState, solvePow, summary } = require('./_admin-server');
const policy = require('../lib/email-policy');

let srv = null;
let checks = 0;
const RUN = crypto.randomBytes(4).toString('hex');
const NET = 20 + Math.floor(Math.random() * 200);
let n = 0;
const ip = () => { n++; return `${NET}.77.${n & 255}.9`; };

before(async () => {
  const url = process.env.REDIS_URL || 'redis://127.0.0.1:6399';
  let createClient;
  try { ({ createClient } = require('redis')); }
  catch (e) {
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) {
      console.log('  SKIP [redis] - the "redis" module is not installed (declared via ADMIN_TEST_SKIP)');
      return;
    }
    throw new Error('unmet precondition "redis": the redis module is not installed. Run npm ci in admin/, or declare ADMIN_TEST_SKIP=redis');
  }
  const rc = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  rc.on('error', () => {});
  try { await rc.connect(); await rc.ping(); await rc.disconnect(); }
  catch (e) {
    try { await rc.disconnect(); } catch (_) { /* never connected */ }
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) {
      console.log(`  SKIP [redis] - no reachable redis at ${url} (declared via ADMIN_TEST_SKIP)`);
      return;
    }
    throw new Error(`unmet precondition "redis": no reachable redis at ${url}: ${e.message}`);
  }
  const relay = await stubRelay(defaultRelayState([]));
  // Geen DNS in een test: de MX-helft heeft zijn eigen toetsen met een nep-resolver.
  srv = await boot({ redisUrl: url, relay, env: { EMAIL_MX_CHECK: '0' } });
});

after(async () => {
  await killAll();
  summary('email-policy-http', checks);
});

async function signup(email) {
  const from = ip();
  const ch = await srv.get('/api/captcha/challenge', { headers: { 'X-Real-IP': from } });
  assert.equal(ch.status, 200, `challenge: ${ch.status} ${ch.text}`);
  const nonce = solvePow(ch.json.challenge_id, ch.json.salt, ch.json.difficulty);
  return srv.post('/api/user/signup', {
    headers: { 'X-Real-IP': from },
    body: { email, dpa_accepted: true, challenge_id: ch.json.challenge_id, nonce },
  });
}

test('aanmelden met een wegwerpadres: 422 met de rustige melding in beide talen', async (t) => {
  if (!srv) return t.skip('no redis');
  for (const email of [`geheim_${RUN}@mailinator.com`, `geheim_${RUN}@post.yopmail.com`, `geheim_${RUN}@MAILINATOR.COM`]) {
    const r = await signup(email);
    assert.equal(r.status, 422, `${email}: ${r.status} ${r.text}`);
    assert.equal(r.json.error, 'invalid_email');
    assert.equal(r.json.reason, 'domain_not_allowed');
    assert.equal(r.json.message_nl, policy.MELDING.aanmelden.nl);
    assert.equal(r.json.message_en, policy.MELDING.aanmelden.en);
    checks++;
  }
  // Het log van de admin noemt het domein, niet het adres.
  const log = srv.log();
  assert.match(log, /\[email-policy\] geweigerd doel=aanmelden categorie=wegwerp domein=mailinator\.com/);
  assert.ok(!log.includes(`geheim_${RUN}`), 'het volledige adres staat in het log van de admin');
  checks++;
});

test('aanmelden met proton en tuta gaat door', async (t) => {
  if (!srv) return t.skip('no redis');
  for (const d of ['proton.me', 'tuta.com', 'posteo.de']) {
    const r = await signup(`demo_${RUN}@${d}`);
    assert.equal(r.status, 200, `${d}: ${r.status} ${r.text}`);
    assert.equal(r.json.message, 'verification_email_sent');
    checks++;
  }
});

test('wie zonder account verzendt, wordt als afzender getoetst', async (t) => {
  if (!srv) return t.skip('no redis');
  const weg = await srv.post('/api/drop/upload', { headers: { 'X-Real-IP': ip() }, body: { email: `a_${RUN}@mailinator.com` } });
  assert.equal(weg.status, 422, weg.text);
  assert.equal(weg.json.message_nl, policy.MELDING.verzenden.nl);
  // Een gewoon adres komt langs de lijst; de stub-relay kent anon-inbound niet
  // en antwoordt 404, en dat is hier het bewijs dat de admin doorliep.
  const goed = await srv.post('/api/drop/upload', { headers: { 'X-Real-IP': ip() }, body: { email: `a_${RUN}@proton.me` } });
  assert.notEqual(goed.status, 422, goed.text);
  checks += 2;
});
