// scripts/klant-controle.py: what a customer can check without Paramant.
//
// WHY THIS SUITE EXISTS. The CT research of 2026-10-06 (paramant-bewijs/
// ct-onderzoek-2026-10-06) showed a customer CAN check a transfer receipt
// against the public log, but only with the researcher's own scripts. Those
// are now scripts/klant-controle.py, and this suite holds them to two things:
//
//   * on REAL production data (relay.paramant.app, leaf 777, the signed head at
//     1523, the pin from frontend/js/relay-trust-anchors.js) every step passes;
//   * one byte changed anywhere (the audit path, the root, the signature, the
//     leaf) turns the verdict to "niet aangetoond". A checker that also passes
//     a forgery is worse than none.
//
// The relay is a small http server serving the fixture, so the suite is
// offline. The fixture is five responses, recomputed with relay/lib/ct-tree.js
// over all 1523 real leaves (see its `bron`).
//
// ML-DSA-65 goes through OpenSSL 3.5+. The CI image ships OpenSSL 3.0, so there
// the signature steps report "not checked" (exit 3) and this suite asserts
// exactly that instead of skipping. Locally, with 3.5, they run for real.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawn, spawnSync, execFileSync } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const SCRIPT = path.join(ROOT, 'scripts', 'klant-controle.py');
const FIX = JSON.parse(fs.readFileSync(path.join(ROOT, 'tests/fixtures/klant-controle/relay-777.json'), 'utf8'));
const require = createRequire(import.meta.url);
const { CtMerkle } = require('../relay/lib/ct-tree.js');
const { blobLeafHash } = require('../relay/lib/ct-hash.js');
const pqc = await import(path.join(ROOT, 'frontend', 'vendor', 'paramant-pqc.js'));

let MLDSA = false;
try {
  MLDSA = /ML-DSA-65/i.test(execFileSync('openssl', ['list', '-signature-algorithms'], { encoding: 'utf8' }));
} catch { /* no openssl: the signature steps must say "not checked" */ }

const clone = (o) => JSON.parse(JSON.stringify(o));
const flip = (hex) => hex.slice(0, -1) + (hex.endsWith('0') ? '1' : '0');

// A relay that answers the four routes the tool asks for, from `r`.
async function serve(r) {
  const srv = http.createServer((req, res) => {
    const u = new URL(req.url, 'http://x');
    let body = null;
    if (u.pathname === '/v2/ct/log') body = { ok: true, size: r.sth.tree_size, entries: r.log_entry ? [r.log_entry] : [] };
    else if (u.pathname === `/v2/ct/proof/${r.index}`) body = r.proof || null;
    else if (u.pathname === '/v2/sth') body = { ok: true, sth: r.sth };
    else if (u.pathname === '/v2/sth/consistency') body = r.consistency;
    res.writeHead(body ? 200 : 404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(body || { error: 'not found' }));
  });
  await new Promise((ok) => srv.listen(0, '127.0.0.1', ok));
  return { url: `http://127.0.0.1:${srv.address().port}`, close: () => new Promise((ok) => srv.close(ok)) };
}

// spawnSync would block the event loop the fixture server needs, so the tool
// runs asynchronously.
function runTool(args, stdin) {
  return new Promise((resolve) => {
    const p = spawn('python3', [SCRIPT, '--json', ...args], { stdio: ['pipe', 'pipe', 'pipe'] });
    let out = ''; let err = '';
    p.stdout.on('data', (d) => { out += d; });
    p.stderr.on('data', (d) => { err += d; });
    p.on('close', (code) => {
      let json = null;
      try { json = JSON.parse(out); } catch { /* usage errors print text */ }
      resolve({ code, json, out, err });
    });
    p.stdin.end(stdin || '');
  });
}

async function check(r, extra = []) {
  const s = await serve(r);
  try { return await runTool(['--index', String(r.index), '--relay', s.url, ...extra]); }
  finally { await s.close(); }
}

const sigSteps = (j) => j.stappen.filter((s) => /handtekening/.test(s.controle));

test('python3 is there and the tool parses', () => {
  const r = spawnSync('python3', ['-m', 'py_compile', SCRIPT], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
});

test('real production leaf 777 on relay.paramant.app: every step holds', async () => {
  const r = await check(FIX);
  assert.ok(r.json, r.out + r.err);
  const logSteps = r.json.stappen.filter((s) => !/handtekening/.test(s.controle));
  assert.ok(logSteps.length >= 3);
  for (const s of logSteps) assert.equal(s.ok, true, `${s.controle}: ${s.detail}`);
  if (MLDSA) {
    assert.equal(r.code, 0, r.out);
    assert.deepEqual(sigSteps(r.json).map((s) => s.ok), [true]);
    assert.match(sigSteps(r.json)[0].detail, /gepinde sleutel van relay\.paramant\.app/);
  } else {
    assert.equal(r.code, 3, 'without ML-DSA in OpenSSL the verdict must be "incomplete", never "proven"');
    assert.equal(sigSteps(r.json)[0].ok, null);
  }
});

test('one byte changed in the audit path: not proven', async () => {
  const f = clone(FIX);
  f.proof.proof[0].hash = flip(f.proof.proof[0].hash);
  const r = await check(f);
  assert.equal(r.code, 1, r.out);
});

test('one byte changed in the signed root: not proven', async () => {
  const f = clone(FIX);
  f.sth.sha3_root = flip(f.sth.sha3_root);
  const r = await check(f);
  assert.equal(r.code, 1, r.out);
});

test('a different leaf at that position in the public tree than the proof is about: not proven', async () => {
  const f = clone(FIX);
  f.proof.leaf_hash = flip(f.proof.leaf_hash);
  const r = await check(f);
  assert.equal(r.code, 1, r.out);
});

test('one byte changed in the head signature: refused (or "not checked" without ML-DSA)', async () => {
  const f = clone(FIX);
  const sig = Buffer.from(f.sth.signature, 'base64');
  sig[100] ^= 1;
  f.sth.signature = sig.toString('base64');
  const r = await check(f);
  assert.equal(r.code, MLDSA ? 1 : 3, r.out);
});

test('a head that names a relay with no pin is never "proven"', async () => {
  const f = clone(FIX);
  f.sth.relay_id = 'https://relay.example.org';
  const r = await check(f);
  assert.equal(r.code, 3, r.out);
  assert.match(sigSteps(r.json)[0].detail, /geen sleutel|ML-DSA/);
});

// A receipt as relay.js builds it at GET /v2/outbound/:hash, from a relay with
// a throwaway identity, served by a fixture relay that kept growing after it.
function receiptWorld({ relayId }) {
  const keys = pqc.ml_dsa65.keygen(new Uint8Array(32).fill(9));
  const pkB64 = Buffer.from(keys.publicKey).toString('base64');
  const canon = (o) => JSON.stringify(Object.fromEntries(Object.keys(o).sort().map((k) => [k, o[k]])));
  const signSth = (p) => ({ ...p, signature: Buffer.from(pqc.ml_dsa65.sign(keys.secretKey, Buffer.from(canon(p)))).toString('base64') });
  const t = new CtMerkle();
  for (let i = 0; i < 6; i++) t.append(crypto.createHash('sha3-256').update('other-' + i).digest('hex'));
  const blobHash = crypto.randomBytes(32).toString('hex');
  const ts = '2026-10-06T09:41:12.345Z';
  const leaf = blobLeafHash(blobHash, 'health', ts);
  t.append(leaf);
  const idx = t.size - 1;
  const size = t.size;
  const oldSth = signSth({ relay_id: relayId, sha3_root: t.root(), timestamp: 1791277200000, tree_size: size, version: 1 });
  const receipt = {
    blob_hash: blobHash, ts, sector: 'health', relay_id: relayId, burn_confirmed: true,
    inclusion_proof: { leaf_hash: leaf, leaf_index: idx, tree_size: size, audit_path: t.inclusionProof(idx, size), root: t.root(), sth: oldSth, sth_signature: oldSth.signature },
  };
  for (let i = 0; i < 9; i++) t.append(crypto.createHash('sha3-256').update('later-' + i).digest('hex'));
  const sth = signSth({ relay_id: relayId, sha3_root: t.root(), timestamp: 1791280800000, tree_size: t.size, version: 1 });
  const world = {
    index: idx, sth,
    log_entry: { index: idx, type: 'transfer', leaf_hash: leaf, tree_hash: receipt.inclusion_proof.root, ts: '2026-10-06T09:00:00.000Z' },
    proof: { ok: true, index: idx, leaf_hash: leaf, tree_hash: receipt.inclusion_proof.root, tree_size: size, proof: t.inclusionProof(idx, size) },
    consistency: { ok: true, from: size, to: t.size, proof: t.consistencyProof(size, t.size) },
  };
  return { receipt, world, pkB64 };
}

async function checkReceipt(receipt, world, extra = []) {
  const s = await serve(world);
  try {
    const b64 = Buffer.from(JSON.stringify(receipt)).toString('base64url');
    return await runTool(['-', '--relay', s.url, ...extra], b64);
  } finally { await s.close(); }
}

test('receipt from a self-hosted relay, key given by the customer: proven, and labelled unpinned', async () => {
  const { receipt, world, pkB64 } = receiptWorld({ relayId: 'https://relay.example.org' });
  const r = await checkReceipt(receipt, world, ['--pubkey', pkB64]);
  assert.ok(r.json, r.out + r.err);
  for (const s of r.json.stappen.filter((x) => !/handtekening/.test(x.controle))) {
    assert.equal(s.ok, true, `${s.controle}: ${s.detail}`);
  }
  assert.equal(r.code, MLDSA ? 0 : 3, r.out);
  if (MLDSA) assert.match(sigSteps(r.json)[0].detail, /niet een gepinde Paramant-sleutel/);
});

test('receipt with the blob hash changed: the leaf no longer matches', async () => {
  const { receipt, world, pkB64 } = receiptWorld({ relayId: 'https://relay.example.org' });
  const bad = clone(receipt);
  bad.blob_hash = flip(bad.blob_hash);
  const r = await checkReceipt(bad, world, ['--pubkey', pkB64]);
  assert.equal(r.code, 1, r.out);
  assert.equal(r.json.stappen[0].ok, false);
});

test('receipt claiming relay.paramant.app but signed by another key: refused by the pin', { skip: !MLDSA && 'needs OpenSSL 3.5+ for ML-DSA-65' }, async () => {
  const { receipt, world } = receiptWorld({ relayId: 'https://relay.paramant.app' });
  const r = await checkReceipt(receipt, world);
  assert.equal(r.code, 1, r.out);
  assert.ok(sigSteps(r.json).every((s) => s.ok === false));
});

// Review #576 (LAAG, punt 7): the leaf was looked up in /v2/ct/log, which only
// shows the newest 10.000 entries (CT_MAX). Past that, an old and genuine
// receipt failed with "vertrouw dit niet". /v2/ct/proof works for every leaf.
test('an old receipt whose leaf fell out of the /v2/ct/log window is still proven', async () => {
  const { receipt, world, pkB64 } = receiptWorld({ relayId: 'https://relay.example.org' });
  world.log_entry = null; // the window no longer lists it
  const r = await checkReceipt(receipt, world, ['--pubkey', pkB64]);
  assert.ok(r.json, r.out + r.err);
  for (const s of r.json.stappen.filter((x) => !/handtekening/.test(x.controle))) {
    assert.equal(s.ok, true, `${s.controle}: ${s.detail}`);
  }
  assert.equal(r.code, MLDSA ? 0 : 3, r.out);
});

test('the leaf at that position differs from the receipt: not proven, also through the proof route', async () => {
  const { receipt, world, pkB64 } = receiptWorld({ relayId: 'https://relay.example.org' });
  world.proof.leaf_hash = flip(world.proof.leaf_hash);
  world.log_entry = null;
  const r = await checkReceipt(receipt, world, ['--pubkey', pkB64]);
  assert.equal(r.code, 1, r.out);
});

test('a relay without /v2/ct/proof: the receipt is still checked against /v2/ct/log', async () => {
  const { receipt, world, pkB64 } = receiptWorld({ relayId: 'https://relay.example.org' });
  world.proof = null;
  const r = await checkReceipt(receipt, world, ['--pubkey', pkB64]);
  assert.ok(r.json, r.out + r.err);
  assert.ok(r.json.stappen.some((s) => /openbare log is hetzelfde blad/.test(s.controle) && s.ok === true));
  assert.equal(r.code, MLDSA ? 0 : 3, r.out);
});

test('a ParaSign proof is refused with the honest reason, not checked half', async () => {
  const r = await runTool(['-'], JSON.stringify({ envelope_id: 'abc', ct_index: 12, doc_hash: 'aa'.repeat(32) }));
  assert.equal(r.code, 2, r.out + r.err);
  assert.match(r.err, /ParaSign-bewijs kan deze tool nog niet controleren/);
});

test('the tool reads the pins from relay-trust-anchors.js and does not carry its own', () => {
  const src = fs.readFileSync(SCRIPT, 'utf8');
  assert.match(src, /relay-trust-anchors\.js/);
  assert.doesNotMatch(src, /[A-Za-z0-9+/]{200,}/, 'a key is copied into the tool');
});
