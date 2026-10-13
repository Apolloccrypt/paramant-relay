'use strict';
// Aanmeldingen en logins in het beheerlog, tegen een echte admin.
//
// WAAROM. De acceptatie van 3.1.1 vond in het beheerlog alleen ondertekeningen
// en "klantgegevens bekeken". Een eigenaar die wil weten of een klant er ooit
// in kwam, zag niets. Nu schrijft de admin vier dingen weg: account aangemaakt
// (e-mailadres bevestigd), account in gebruik genomen (authenticator-app
// gekoppeld), en een geslaagde login met de app of met een herstelcode.
//
// Wat er NIET in mag staan, en wat dit ook toetst: geen code, geen herstelcode,
// geen sessietoken, geen mailadres en geen IP. Wie het is, leest het paneel uit
// de accountlijst. En een mislukte login schrijft per account niets weg: dan
// zou een adres met een account meer werk doen dan een adres zonder.
//
// Draaien: REDIS_URL=redis://127.0.0.1:6399 node --test admin/test/audit-aanmelding-login.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const { boot, killAll, stubRelay, defaultRelayState, summary } = require('./_admin-server');

const RUN = crypto.randomBytes(5).toString('hex');
const SECRET = '123456';
const BACKUP = 'ABCD-EFGH-IJKL';
let rc = null; let srv = null; let relay = null;
let checks = 0;
const did = () => { checks++; };

// Elk veld dat in een auditregel van deze vier soorten nooit mag staan.
const VERBODEN = ['totp', 'code', 'backup_code', 'token', 'session', 'email', 'ip', 'ua', 'password', 'secret'];

before(async () => {
  const url = process.env.REDIS_URL || 'redis://127.0.0.1:6399';
  let createClient;
  try { ({ createClient } = require('redis')); } catch (e) {
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) return;
    throw new Error(`unmet precondition "redis": ${e.message}`);
  }
  const c = createClient({ url, socket: { connectTimeout: 800, reconnectStrategy: false } });
  c.on('error', () => {});
  try { await c.connect(); await c.ping(); } catch (e) {
    try { await c.disconnect(); } catch (_) { /* never connected */ }
    if (String(process.env.ADMIN_TEST_SKIP || '').split(',').includes('redis')) return;
    throw new Error(`unmet precondition "redis": no reachable redis at ${url}: ${e.message}`);
  }
  rc = c;
  const state = defaultRelayState([], SECRET);
  state.consumeBackup = (body) => ({ valid: body && body.code === BACKUP });
  relay = await stubRelay(state);
  srv = await boot({ redisUrl: url, relay });
});

after(async () => {
  await killAll();
  if (rc) { try { await rc.disconnect(); } catch (_) { /* gone */ } }
  summary('audit-aanmelding-login', checks);
});

async function events(key) {
  const raw = await rc.zRange(`paramant:user:audit:${key}`, 0, -1);
  return raw.map((r) => JSON.parse(r));
}

function schoon(ev) {
  const meta = ev.metadata || {};
  for (const k of VERBODEN) assert.ok(!(k in meta), `${ev.event_type} bevat het veld ${k}: ${JSON.stringify(meta)}`);
  const tekst = JSON.stringify(ev);
  assert.ok(!tekst.includes(SECRET), 'de code staat niet in de regel');
  assert.ok(!tekst.includes(BACKUP), 'de herstelcode staat niet in de regel');
  assert.ok(!/@/.test(tekst), 'geen mailadres in de regel');
}

async function account() {
  const key = `pgp_audit_${RUN}_${crypto.randomBytes(4).toString('hex')}`;
  const email = `audit_${crypto.randomBytes(5).toString('hex')}@example.com`;
  relay.state.accounts.push({ key, email, active: true });
  await rc.set(`paramant:user:totp_active:${key}`, 'true');
  return { key, email };
}

const ip = () => `203.0.113.${1 + Math.floor(Math.random() * 250)}`;

test('een geslaagde login met de app staat in het log, zonder code of adres', async (t) => {
  if (!srv) return t.skip('no redis');
  const { key, email } = await account();
  const r = await srv.login({ email, totp: SECRET, ip: ip() });
  assert.strictEqual(r.status, 200, r.text);
  const evs = (await events(key)).filter((e) => e.event_type === 'user_login');
  assert.strictEqual(evs.length, 1, 'precies één loginregel');
  assert.deepStrictEqual(evs[0].metadata, { via: 'totp' });
  schoon(evs[0]);
  did();
});

test('een mislukte login schrijft per account niets weg', async (t) => {
  if (!srv) return t.skip('no redis');
  const { key, email } = await account();
  const r = await srv.login({ email, totp: '000000', ip: ip() });
  assert.strictEqual(r.status, 401, r.text);
  assert.deepStrictEqual(await events(key), []);
  did();
});

test('een login met een herstelcode staat in het log als herstelcode', async (t) => {
  if (!srv) return t.skip('no redis');
  const { key, email } = await account();
  const r = await srv.post('/api/user/login-with-backup', { headers: { 'X-Real-IP': ip() }, body: { email, backup_code: BACKUP } });
  assert.strictEqual(r.status, 200, r.text);
  const evs = (await events(key)).filter((e) => e.event_type === 'user_login');
  assert.strictEqual(evs.length, 1);
  assert.deepStrictEqual(evs[0].metadata, { via: 'backup_code' });
  schoon(evs[0]);
  did();
});

test('een bevestigde aanmelding en het koppelen van de app staan in het log', async (t) => {
  if (!srv) return t.skip('no redis');
  const email = `nieuw_${crypto.randomBytes(5).toString('hex')}@example.com`;
  const token = crypto.randomBytes(32).toString('hex');
  await rc.set(`paramant:signup:pending:${token}`, JSON.stringify({ email, label: null }), { EX: 600 });
  const r = await srv.get(`/api/user/signup/verify/${token}`);
  assert.strictEqual(r.status, 302, r.text);
  assert.match(String(r.headers.location), /\/signup\/verified$/);
  const key = await rc.get(`paramant:signup:consumed:${token}`);
  assert.ok(key && key.startsWith('pgp_'), 'het nieuwe account is bekend');
  const created = (await events(key)).filter((e) => e.event_type === 'account_created');
  assert.strictEqual(created.length, 1, 'de aanmelding staat erin');
  assert.deepStrictEqual(created[0].metadata, { via: 'signup' });
  schoon(created[0]);
  did();

  // De eerste code uit de app: account in gebruik genomen.
  const setup = crypto.randomBytes(24).toString('hex');
  await rc.set(`paramant:user:setup_token:${setup}`, JSON.stringify({ user_id: key, email }), { EX: 600 });
  const c = await srv.post(`/api/user/setup/${setup}/confirm`, { body: { totp: SECRET } });
  assert.strictEqual(c.status, 200, c.text);
  const act = (await events(key)).filter((e) => e.event_type === 'account_activated');
  assert.strictEqual(act.length, 1);
  assert.deepStrictEqual(act[0].metadata, { via: 'totp' });
  schoon(act[0]);
  did();
});
