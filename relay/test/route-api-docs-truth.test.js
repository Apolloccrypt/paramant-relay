'use strict';
// WHAT THE API DOCS PROMISE, THE RELAY DOES. P10 rest-round (fase-1 matrix,
// cells API-05-A, API-11-A, API-13-B, API-13-C, API-14-L, API-16-N, API-29-N,
// and the IoT help page that sent devices to a POST /v1/upload that never
// existed).
//
// Each case boots the real relay.js and asks it over HTTP:
//   1. /v1 create refuses metadata that is not an object (was 201, stored {}).
//   2. an empty content_base64 is empty_document (was missing_document).
//   3. more signers than the plan allows is too_many_signers with the number
//      (was the catch-all create_failed).
//   4. a signed slot is called 'signed' in the 201 and in GET alike (the 201
//      said 'completed').
//   5. GET /v2/user/parasign-keys says 403 to an account without the ParaSign
//      API and no keys (was 200 with an empty list), and the mint names the
//      key's ParaSign tier (plan_parasign) next to the legacy plan.
//   6. POST /v2/verify-receipt repeats tree_size_at_retrieval.
//   7. a relay without PARASIGN_PUBLIC_ORIGIN builds sign_url and the receipt's
//      relay_pubkey_url from its own RELAY_SELF_URL, not from paramant.app,
//      and says so at boot.
//   8. the Python example on /help/iot-integration (NL and EN), run as printed
//      against this relay, produces a link whose fragment decrypts the file
//      exactly as /get does.
//
// NEEDS: redis and the ML-DSA-65 engine (envelope store, sandbox signer,
// receipts); python3 with the `cryptography` package for case 8.
// Run: REDIS_URL=redis://127.0.0.1:6399 node --test relay/test/route-api-docs-truth.test.js

const { test, before, after } = require('node:test');
const assert = require('assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');
const { boot, killAll } = require('./_relay-server');
const { requireEngine, requireRedis, summary } = require('./_requires');

const ADMIN = 'admin-token-for-the-api-docs-truth-suite';
const INTERNAL = 'internal-token-for-the-api-docs-truth-suite';
const BOTH = { 'X-Admin-Token': ADMIN, 'X-Internal-Auth': INTERNAL };
const DEFAULT_REDIS = 'redis://127.0.0.1:6399';
const RUN = crypto.randomBytes(6).toString('hex');
const FUTURE = new Date(Date.now() + 20 * 86_400_000).toISOString();
const PDF_B64 = Buffer.from('%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n').toString('base64');
const REPO = path.join(__dirname, '..', '..');

let eng = null;
let rc = null;
let checks = 0;
const did = () => { checks++; };
const ready = () => eng !== null && rc !== null;

before(async () => {
  eng = requireEngine();
  rc = await requireRedis(DEFAULT_REDIS);
});

after(async () => {
  await killAll();
  if (rc) { try { await rc.disconnect(); } catch (_) {} }
  summary('route-api-docs-truth', checks);
});

// A relay with two accounts: one that pays for ParaSign (legacy plan community,
// plan_parasign pro, as every self-serve buyer), and one on community with no
// ParaSign at all.
async function relay(tag, env = {}) {
  const payer = `pgp_${tag}p_${RUN}_${crypto.randomBytes(8).toString('hex')}`;
  const free = `pgp_${tag}f_${RUN}_${crypto.randomBytes(8).toString('hex')}`;
  const srv = await boot({
    tag,
    usersFile: true,
    users: { api_keys: [
      { key: payer, plan: 'community', active: true, parasign: true, is_primary: true,
        account_id: `acct_${tag}p_${RUN}`, email: `${tag}p@example.test`,
        plan_parasign: 'pro', paid_until_parasign: FUTURE },
      { key: free, plan: 'community', active: true, is_primary: true,
        account_id: `acct_${tag}f_${RUN}`, email: `${tag}f@example.test` },
    ] },
    env: { ADMIN_TOKEN: ADMIN, INTERNAL_AUTH_TOKEN: INTERNAL, REDIS_URL: process.env.REDIS_URL || DEFAULT_REDIS, ...env },
  });
  return { srv, payer: `acct_${tag}p_${RUN}`, free: `acct_${tag}f_${RUN}`, freeKey: free };
}
const mint = (srv, account, testKey) => srv.post('/v2/user/parasign-keys', {
  headers: BOTH, body: { user_id: account, label: 'docs-truth', test: testKey },
});
const bearer = (psk) => ({ Authorization: `Bearer ${psk}` });
const create = (srv, psk, extra = {}) => srv.post('/v1/envelopes', {
  headers: bearer(psk),
  body: { document: { content_base64: PDF_B64 }, original_filename: 't.pdf',
    signers: [{ name: 'A', email: 'a@example.test' }], ...extra },
});

test('/v1 create: metadata, empty document, too many signers, one signer enum', async () => {
  if (!ready()) return;
  const { srv, payer } = await relay('v1shape');
  const k = await mint(srv, payer, true);
  assert.strictEqual(k.status, 201, k.text);
  const psk = k.json.key;

  const meta = await create(srv, psk, { metadata: 'x' });
  assert.strictEqual(meta.status, 400, `metadata "x": ${meta.text}`);
  assert.strictEqual(meta.json.error, 'invalid_metadata');
  const arr = await create(srv, psk, { metadata: [1, 2] });
  assert.strictEqual(arr.status, 400, `metadata []: ${arr.text}`);
  assert.strictEqual(arr.json.error, 'invalid_metadata');

  const empty = await create(srv, psk, { document: { content_base64: '' } });
  assert.strictEqual(empty.status, 400, empty.text);
  assert.strictEqual(empty.json.error, 'empty_document', 'the spec names empty_document for an empty content_base64');
  const none = await create(srv, psk, { document: {} });
  assert.strictEqual(none.json.error, 'missing_document', 'no document at all stays missing_document');

  const many = Array.from({ length: 30 }, (_, i) => ({ name: 'S' + i, email: `s${i}@example.test` }));
  const tooMany = await create(srv, psk, { signers: many });
  assert.strictEqual(tooMany.status, 400, tooMany.text);
  assert.strictEqual(tooMany.json.error, 'too_many_signers', tooMany.text);
  assert.ok(Number.isInteger(tooMany.json.max_signers) && tooMany.json.max_signers < 30, tooMany.text);

  const ok = await create(srv, psk, { metadata: { quote_id: '8842' },
    signers: [{ name: 'A', email: 'a@example.test' }, { name: 'B', email: 'b@example.test' }] });
  assert.strictEqual(ok.status, 201, ok.text);
  assert.strictEqual(ok.json.status, 'completed', 'precondition: the sandbox signer completed it');
  const g = await srv.get(`/v1/envelopes/${ok.json.id}`, { headers: bearer(psk) });
  assert.strictEqual(g.status, 200, g.text);
  const inCreate = ok.json.signers.map((s) => s.status);
  const inGet = g.json.signers.map((s) => s.status);
  assert.deepStrictEqual(inCreate, inGet, 'the 201 and GET use one word for a signed slot');
  assert.deepStrictEqual(inCreate, ['signed', 'signed']);
  await srv.stop();
  did();
});

test('parasign-keys: GET is gated like POST; the mint names the ParaSign tier', async () => {
  if (!ready()) return;
  const { srv, payer, free } = await relay('keys');
  const g0 = await srv.get(`/v2/user/parasign-keys?user_id=${free}`, { headers: BOTH });
  assert.strictEqual(g0.status, 403, `an account without the ParaSign API: ${g0.text}`);
  assert.strictEqual(g0.json.error, 'parasign_not_entitled');

  const g1 = await srv.get(`/v2/user/parasign-keys?user_id=${payer}`, { headers: BOTH });
  assert.strictEqual(g1.status, 200, g1.text);
  const m = await mint(srv, payer, false);
  assert.strictEqual(m.status, 201, m.text);
  assert.strictEqual(m.json.plan, 'community', 'precondition: the legacy plan stays community');
  assert.strictEqual(m.json.plan_parasign, 'pro', 'the mint names the ParaSign tier the key works under');
  await srv.stop();
  did();
});

test('verify-receipt repeats tree_size_at_retrieval', async () => {
  if (!ready()) return;
  const { srv, freeKey } = await relay('rcpt');
  const blob = crypto.randomBytes(600);
  const hash = crypto.createHash('sha256').update(blob).digest('hex');
  const xk = { 'X-Api-Key': freeKey };
  const up = await srv.post('/v2/inbound', { headers: xk, body: { hash, payload: blob.toString('base64') } });
  assert.strictEqual(up.status, 200, up.text);
  const dl = await srv.get(`/v2/outbound/${hash}`, { headers: xk });
  assert.strictEqual(dl.status, 200, dl.text);
  const url = dl.headers['x-paramant-receipt-url'];
  assert.ok(url, 'precondition: the download names its receipt');
  const rcpt = await srv.get(url, { headers: xk });
  assert.strictEqual(rcpt.status, 200, rcpt.text);
  const inner = JSON.parse(Buffer.from(rcpt.json.receipt, 'base64url').toString());
  assert.strictEqual(typeof inner.retrieved_at, 'number', 'retrieved_at inside the signed receipt is a number (docs/api.md says so)');
  const v = await srv.post('/v2/verify-receipt', { headers: xk, body: { receipt: rcpt.json.receipt } });
  assert.strictEqual(v.status, 200, v.text);
  assert.strictEqual(v.json.valid, true, v.text);
  assert.strictEqual(v.json.tree_size_at_retrieval, inner.tree_size_at_retrieval, v.text);
  assert.ok(Number.isInteger(v.json.tree_size_at_retrieval));
  await srv.stop();
  did();
});

test('without PARASIGN_PUBLIC_ORIGIN a self-host links to its own RELAY_SELF_URL', async () => {
  if (!ready()) return;
  const SELF = 'https://relay.selfhost.example';
  const { srv, payer } = await relay('origin', { RELAY_SELF_URL: SELF, PARASIGN_PUBLIC_ORIGIN: '' });
  const k = await mint(srv, payer, true);
  assert.strictEqual(k.status, 201, k.text);
  const c = await create(srv, k.json.key);
  assert.strictEqual(c.status, 201, c.text);
  for (const s of c.json.signers) assert.ok(s.sign_url.startsWith(SELF + '/co-sign?'), s.sign_url);
  const r = await srv.get(`/v1/envelopes/${c.json.id}/receipt`, { headers: bearer(k.json.key) });
  assert.strictEqual(r.status, 200, r.text);
  assert.strictEqual(r.json.notary.relay_pubkey_url, SELF + '/v2/pubkey');
  // matrix API-16-N: the proof itself names the relay that notarised it.
  assert.strictEqual(r.json.notary.relay_id, SELF, 'the .psign names the self-host, inside the notary signature');
  assert.match(srv.log(), /parasign_public_origin_unset[^\n]*relay\.selfhost\.example/, 'the boot log says which origin it uses');
  await srv.stop();
  did();
});

// The page shows the program with HTML entities; read it back the way a reader
// copies it from the screen.
function codeBlockWith(html, marker) {
  const blocks = [...html.matchAll(/<div class="code-block">([\s\S]*?)<\/div>/g)].map((m) => m[1]);
  const b = blocks.find((x) => x.includes(marker));
  assert.ok(b, `a code block with ${marker}`);
  return b.replace(/<[^>]+>/g, '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&');
}

test('/help/iot-integration: the printed Python example works against a relay', async () => {
  if (!ready()) return;
  try { execFileSync('python3', ['-c', 'import cryptography']); }
  catch (_) { assert.fail('python3 with the cryptography package is a precondition of this case'); }
  const { srv, freeKey } = await relay('iot');
  for (const rel of ['frontend/help/iot-integration.html', 'frontend/en/help/iot-integration.html']) {
    const html = fs.readFileSync(path.join(REPO, rel), 'utf8');
    assert.doesNotMatch(html, /\/v1\/upload/, `${rel}: no route that does not exist`);
    let prog = codeBlockWith(html, 'AESGCM');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'iot-'));
    const file = path.join(dir, 'sensor-log.csv');
    const content = crypto.randomBytes(3000);
    fs.writeFileSync(file, content);
    // The two lines a reader fills in for their own device.
    prog = prog.replace('RELAY   = "https://health.paramant.app"', `RELAY   = "${srv.base}"`)
      .replace('PATH    = "/var/log/sensor-log.csv"', `PATH    = ${JSON.stringify(file)}`);
    assert.ok(prog.includes(srv.base) && prog.includes(file), `${rel}: the example has the RELAY and PATH lines it documents`);
    const link = execFileSync('python3', ['-c', prog], { env: { ...process.env, PARAMANT_API_KEY: freeKey } }).toString().trim();
    const u = new URL(link);
    assert.strictEqual(u.origin + u.pathname, 'https://paramant.app/get', link);
    assert.strictEqual(u.searchParams.get('r'), 'health');
    const t = u.searchParams.get('t');
    assert.match(t, /^[0-9a-f]{48}$/);
    // What get.page.js does: claim, fetch, decrypt with key||iv from the
    // fragment, parse [uint32-LE nameLen][name][bytes], then ack.
    const claim = crypto.randomBytes(16).toString('hex');
    const got = await srv.get(`/v2/dl/${t}/get?claim=${claim}`, { headers: { 'User-Agent': 'Mozilla/5.0' } });
    assert.strictEqual(got.status, 200, got.text);
    const kiv = Buffer.from(u.hash.slice(1), 'base64url');
    assert.strictEqual(kiv.length, 44);
    const d = crypto.createDecipheriv('aes-256-gcm', kiv.subarray(0, 32), kiv.subarray(32, 44));
    d.setAuthTag(got.buf.subarray(got.buf.length - 16));
    const plain = Buffer.concat([d.update(got.buf.subarray(0, got.buf.length - 16)), d.final()]);
    const nameLen = plain.readUInt32LE(0);
    assert.strictEqual(plain.subarray(4, 4 + nameLen).toString(), 'sensor-log.csv');
    assert.ok(plain.subarray(4 + nameLen).equals(content), `${rel}: the bytes come back`);
    const ack = await srv.post(`/v2/dl/${t}/ack`, { headers: { 'User-Agent': 'Mozilla/5.0' }, body: { claim } });
    assert.strictEqual(ack.status, 200, ack.text);
    fs.rmSync(dir, { recursive: true, force: true });
  }
  await srv.stop();
  did();
});
