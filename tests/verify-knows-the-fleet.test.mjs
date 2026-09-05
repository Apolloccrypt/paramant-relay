// /verify has to know the whole fleet, not one relay.
//
// A ParaSend receipt is signed by the relay that handed the file over, and each
// relay generates its own ML-DSA-65 identity on its own volume
// (relay/relay.js:513-548). The app sends transfers through the sector relays
// and prefers health (frontend/js/parashare.page.js:4-10, 418-438), so
// relay.paramant.app signs almost nothing a customer ever holds.
//
// While /verify pinned only relay.paramant.app and used it as the default key
// for every receipt, a genuine receipt from health was checked against the
// wrong key, failed, and was shown to its owner as "Do not trust this receipt".
// That is the one failure a verifier may never produce: calling Paramant's own
// proof a forgery. This suite is the gate on that.
//
// It goes red when a relay is added to docker-compose.yml without pinning its
// key here, which is the way the fleet actually grows.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.join(HERE, '..');
const ROOT = path.join(REPO, 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;

const require = createRequire(import.meta.url);
const { ctTreeHash, ctInclusionProof, blobLeafHash } = require('../relay/lib/ct-hash.js');
const pqc = await import(path.join(ROOT, 'vendor', 'paramant-pqc.js'));
const anchorsMod = await import(path.join(ROOT, 'js', 'relay-trust-anchors.js'));
const { RELAY_TRUST_ANCHORS, anchorForReceipt, anchorByHost, hostOfRelayId } = anchorsMod;

const MIME = {
  '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css',
  '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png',
  '.woff2': 'font/woff2', '.json': 'application/json', '.ico': 'image/x-icon',
};

// Byte-identical to relay.js canonicalJSON.
function canonicalJSON(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonicalJSON).join(',') + ']';
  return '{' + Object.keys(value).sort()
    .map((k) => JSON.stringify(k) + ':' + canonicalJSON(value[k])).join(',') + '}';
}

// ── The roster, read from the thing that actually deploys the relays ────────
// Every relay container publishes itself under RELAY_SELF_URL, and that is the
// exact string relay.js writes into a receipt's relay_id (relay/relay.js:5824).
// Adding a relay means adding one of these lines, so this is the list /verify
// has to keep up with.
function fleetFromCompose() {
  const yml = fs.readFileSync(path.join(REPO, 'docker-compose.yml'), 'utf8');
  const hosts = [];
  for (const m of yml.matchAll(/^\s*RELAY_SELF_URL:\s*["']?([^"'\s]+)["']?\s*$/gm)) {
    hosts.push(hostOfRelayId(m[1]));
  }
  return [...new Set(hosts)];
}

// The status page is the only place the frontend lists all five together.
function fleetFromStatusPage() {
  const js = fs.readFileSync(path.join(ROOT, 'js', 'status.inline1.js'), 'utf8');
  return [...new Set([...js.matchAll(/host:\s*'([a-z0-9.-]+\.paramant\.app)'/g)].map((m) => m[1]))];
}

test('every relay that ships in docker-compose has a key pinned on /verify', () => {
  const fleet = fleetFromCompose();
  assert.ok(fleet.length >= 5, 'expected the five-relay fleet, found ' + JSON.stringify(fleet));

  const pinned = new Set(RELAY_TRUST_ANCHORS.map((a) => a.host.toLowerCase()));
  const missing = fleet.filter((h) => !pinned.has(h));
  assert.deepEqual(missing, [],
    'These relays hand out receipts that /verify cannot check, so their receipts show up as '
    + 'forgeries: ' + missing.join(', ') + '. Read each one’s GET /v2/pubkey and add it to '
    + 'frontend/js/relay-trust-anchors.js in the same commit that adds the relay.');
});

test('the fleet the status page shows is the fleet /verify can check', () => {
  const shown = fleetFromStatusPage();
  const pinned = new Set(RELAY_TRUST_ANCHORS.map((a) => a.host.toLowerCase()));
  const missing = shown.filter((h) => !pinned.has(h));
  assert.deepEqual(missing, [],
    'the status page names relays /verify ships no key for: ' + missing.join(', '));
});

test('every pinned key is a real ML-DSA-65 key and its own fingerprint', () => {
  assert.ok(RELAY_TRUST_ANCHORS.length >= 5);
  const hosts = new Set();
  const fingerprints = new Set();
  for (const a of RELAY_TRUST_ANCHORS) {
    const key = Buffer.from(a.key, 'base64');
    assert.equal(key.length, 1952, a.host + ': an ML-DSA-65 public key is 1952 bytes');
    assert.equal(crypto.createHash('sha3-256').update(key).digest('hex'), a.fingerprint,
      a.host + ': the pinned fingerprint must be the fingerprint of the pinned key');
    assert.ok(a.name && a.host, 'every anchor names itself and its host');
    assert.equal(hosts.has(a.host), false, 'two anchors claim ' + a.host);
    assert.equal(fingerprints.has(a.fingerprint), false,
      'two relays share a key, which cannot happen when each generates its own: ' + a.host);
    hosts.add(a.host);
    fingerprints.add(a.fingerprint);
  }
});

test('a receipt is matched to the relay that signed it, in either relay_id form', () => {
  for (const a of RELAY_TRUST_ANCHORS) {
    // relay.js writes relay_id as RELAY_SELF_URL or as SECTOR + '.paramant.app'
    // (relay/relay.js:5824), so both spellings have to land on the same anchor.
    for (const relayId of ['https://' + a.host, a.host, 'https://' + a.host + '/']) {
      const got = anchorForReceipt({ relay_id: relayId });
      assert.ok(got, 'no anchor found for relay_id ' + relayId);
      assert.equal(got.host, a.host,
        'relay_id ' + relayId + ' was matched to ' + got.host + ' instead of ' + a.host);
      assert.equal(got.fingerprint, a.fingerprint);
    }
  }

  // The bug in one line: the health relay must never be checked with the
  // relay.paramant.app key just because that anchor happens to be first.
  const health = anchorForReceipt({ relay_id: 'https://health.paramant.app' });
  assert.equal(health.host, 'health.paramant.app');
  assert.notEqual(health.fingerprint, anchorByHost('relay.paramant.app').fingerprint);

  // A relay we do not ship is a gap in what we know, reported as null so the
  // caller can say so, never as a fallback guess.
  for (const stranger of ['https://relay.example.com', 'evil.paramant.app.attacker.test', '', null]) {
    assert.equal(anchorForReceipt({ relay_id: stranger }), null,
      'an unknown relay must not be resolved to an anchor: ' + stranger);
  }
});

// ── A receipt from every relay in the fleet, checked through the real page ───
// The five live relays keep their secret keys to themselves, so the suite
// stands up a fleet of its own the same shape as the real one, has each member
// issue a receipt exactly as relay.js does, and makes the shipped verifier
// resolve and check every one. Revert the fix and each of these fails: the
// verifier falls back to the first anchor and reports a forgery.
function buildFleetReceipts() {
  return fleetFromCompose().map((host, i) => {
    const anchor = anchorByHost(host);
    assert.ok(anchor, host + ' ships as a relay but /verify pins no key for it');
    const keys = pqc.ml_dsa65.keygen(new Uint8Array(32).fill(11 + i));
    const sign = (m) => Buffer.from(pqc.ml_dsa65.sign(keys.secretKey, Buffer.from(m, 'utf8'))).toString('base64');
    const sector = anchor.sector || 'relay';
    const ts = '2026-09-04T08:00:0' + i + '.000Z';
    const blobHash = crypto.createHash('sha3-256').update('payload for ' + anchor.host).digest('hex');

    const entries = [];
    for (let k = 0; k < 3; k++) entries.push({ leaf_hash: crypto.createHash('sha3-256').update(anchor.host + k).digest('hex') });
    const leafHash = blobLeafHash(blobHash, sector, ts);
    entries.push({ leaf_hash: leafHash });
    const index = entries.length - 1;
    const root = ctTreeHash(entries);
    const relayId = 'https://' + anchor.host;

    const sthPayload = { relay_id: relayId, sha3_root: root, timestamp: Date.parse(ts), tree_size: entries.length, version: 1 };
    const sth = { ...sthPayload, signature: sign(canonicalJSON(sthPayload)) };
    const payload = {
      blob_hash: blobHash, ts, retrieved_at: Date.parse(ts) + 60000,
      sector, relay_id: relayId, tree_size_at_retrieval: entries.length,
      inclusion_proof: {
        leaf_hash: leafHash, leaf_index: index, tree_size: entries.length,
        audit_path: ctInclusionProof(entries, index), root, sth, sth_signature: sth.signature,
      },
      burn_confirmed: true,
    };
    return {
      host: anchor.host,
      name: anchor.name,
      receipt: { ...payload, signature: sign(canonicalJSON(payload)) },
      key: Buffer.from(keys.publicKey).toString('base64'),
      fingerprint: crypto.createHash('sha3-256').update(Buffer.from(keys.publicKey)).digest('hex'),
    };
  });
}

function startServer() {
  const server = http.createServer((req, res) => {
    let name = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
    if (name === '/verify') name = '/verify.html';
    const file = path.join(ROOT, name);
    if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
    fs.readFile(file, (err, body) => {
      if (err) { res.writeHead(404); return res.end(); }
      res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
      res.end(body);
    });
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
}

const server = await startServer();
const ORIGIN = 'http://127.0.0.1:' + server.address().port;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });

async function openVerify() {
  const context = await browser.newContext();
  const page = await context.newPage();
  await page.goto(ORIGIN + '/verify', { waitUntil: 'load' });
  await page.waitForFunction(() => !!document.getElementById('rv-check'));
  return { context, page };
}

test('a receipt from every relay in the fleet passes every check', async () => {
  const fleet = buildFleetReceipts();
  const { context, page } = await openVerify();

  const results = await page.evaluate(async (cases) => {
    const rv = await import('/js/receipt-verify.js');
    const ta = await import('/js/relay-trust-anchors.js');
    const b64 = (s) => { const bin = atob(s); const u = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; };

    // Same anchor list shape the page ships, but with this suite's keys, so the
    // real resolution and the real verification run over a fleet we can sign for.
    const anchors = cases.map((c) => ({ name: c.name, host: c.host, alg: 'ML-DSA-65', fingerprint: c.fingerprint, key: c.key }));

    return cases.map((c) => {
      const picked = ta.anchorForReceipt(c.receipt, anchors);
      if (!picked) return { host: c.host, picked: null };
      const out = rv.verifyReceipt(c.receipt, b64(picked.key), { source: 'pinned', anchor: picked });
      return {
        host: c.host, picked: picked.host, valid: out.valid,
        signatureHeld: out.signatureHeld, unknownRelay: out.unknownRelay,
        failed: out.checks.filter((k) => k.ok === false).map((k) => k.id),
        skipped: out.checks.filter((k) => k.ok === null).map((k) => k.id),
      };
    });
  }, fleet);

  assert.equal(results.length, fleetFromCompose().length);
  for (const r of results) {
    assert.equal(r.picked, r.host, r.host + ': the verifier reached for ' + r.picked + '’s key');
    assert.deepEqual(r.failed, [], r.host + ': a genuine receipt failed ' + r.failed.join(', '));
    assert.deepEqual(r.skipped, [], r.host + ': a check was skipped on a genuine receipt');
    assert.equal(r.signatureHeld, true, r.host + ': the signature did not hold');
    assert.equal(r.unknownRelay, false, r.host + ': its own relay was reported as unknown');
    assert.equal(r.valid, true, r.host + ': a genuine receipt was not accepted');
  }
  await context.close();
});

test('the page reaches for the signing relay’s own key, not the first one pinned', async () => {
  // Driven through the real page with the key field empty, which is what a
  // customer does. What is under test is which key the page reports having
  // used: before the fix every receipt was checked against 3d9b960c…, the
  // relay.paramant.app pin.
  const fleet = buildFleetReceipts();
  const { context, page } = await openVerify();
  await page.click('#tab-receipt');

  for (const c of fleet) {
    const anchor = anchorByHost(c.host);
    await page.fill('#rv-input', Buffer.from(JSON.stringify(c.receipt)).toString('base64url'));
    await page.click('#rv-check');
    await page.waitForSelector('#rv-result .rv-checks li');
    const text = await page.textContent('#rv-result');
    assert.ok(text.includes(anchor.fingerprint.slice(0, 16)),
      c.host + ': the page checked the receipt against some other relay’s key, expected '
      + anchor.fingerprint.slice(0, 16) + ' in: ' + text.slice(0, 400));
    assert.equal(text.includes('It was signed by the Paramant relay'), false,
      c.host + ': the page named relay.paramant.app as the signer of a receipt it never signed');
  }
  await context.close();
});

test('a receipt from a relay we do not know is unknown, not forged', async () => {
  const [first] = buildFleetReceipts();
  const stranger = JSON.parse(JSON.stringify(first.receipt));
  stranger.relay_id = 'https://relay.someone-else.example';
  stranger.inclusion_proof.sth.relay_id = stranger.relay_id;

  const { context, page } = await openVerify();
  await page.click('#tab-receipt');
  await page.fill('#rv-input', Buffer.from(JSON.stringify(stranger)).toString('base64url'));
  await page.click('#rv-check');
  await page.waitForSelector('#rv-result .ps-banner');
  const text = await page.textContent('#rv-result');

  // The whole point: an unknown sender and a forgery are different findings.
  assert.doesNotMatch(text, /Do not trust this receipt/,
    'a receipt from an unrecognised relay was called a forgery');
  assert.match(text, /This page does not know this relay/);
  assert.match(text, /relay\.someone-else\.example/,
    'the visitor must be told which relay it is that we do not know');
  assert.match(text, /The signature was not checked, because this page does not know this relay/);

  // Nothing that did get checked may be quietly dropped.
  assert.match(text, /The receipt is about this file and no other/);
  assert.match(text, /It really is in the public transparency log/);
  await context.close();
});

test('an unknown relay is still refused when the receipt itself does not add up', async () => {
  const [first] = buildFleetReceipts();
  const bad = JSON.parse(JSON.stringify(first.receipt));
  bad.relay_id = 'https://relay.someone-else.example';
  bad.blob_hash = bad.blob_hash.slice(0, -1) + (bad.blob_hash.endsWith('a') ? 'b' : 'a');

  const { context, page } = await openVerify();
  await page.click('#tab-receipt');
  await page.fill('#rv-input', Buffer.from(JSON.stringify(bad)).toString('base64url'));
  await page.click('#rv-check');
  await page.waitForSelector('#rv-result .ps-banner');
  const text = await page.textContent('#rv-result');
  assert.match(text, /Do not trust this receipt/,
    'not knowing the relay may not soften a receipt that fails its own arithmetic');
  assert.match(text, /The receipt does not match the file it names/);
  await context.close();
});

// Opt-in, because it needs the network: the five pins have to still be what the
// five relays publish. Run with FLEET_LIVE=1 before a release or after a key
// rotation. Everything above stays offline, like /verify itself.
test('the pinned keys are the keys the relays publish', { skip: !process.env.FLEET_LIVE }, async () => {
  for (const a of RELAY_TRUST_ANCHORS) {
    const res = await fetch('https://' + a.host + '/v2/pubkey', { signal: AbortSignal.timeout(15000) });
    assert.equal(res.status, 200, a.host + ' did not answer /v2/pubkey');
    const body = await res.json();
    assert.equal(body.public_key, a.key, a.host + ' publishes a different key than the one pinned here');
    assert.equal(body.pk_hash, a.fingerprint, a.host + ' publishes a different fingerprint');
  }
});

test.after(async () => {
  await browser.close();
  server.close();
  server.closeAllConnections();
});
