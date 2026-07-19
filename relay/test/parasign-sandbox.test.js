'use strict';
// ParaSign sandbox auto-signer (lib/parasign-open-api.js sandboxAutoSign). Proves
// a psk_test_ envelope is driven to completion by a throwaway ML-DSA-65 signer
// that produces CRYPTOGRAPHICALLY VALID per-slot signatures (the fake envStore
// here verifies each one with the real engine under the correct recipe), and
// that signer.completed + envelope.completed webhooks fire (HMAC-SHA256 signed).
// Needs the ML-DSA-65 engine (@paramant/core); skips if it cannot load.

const assert = require('assert');
const crypto = require('crypto');
const openApi = require('../lib/parasign-open-api');
const { signMessageBytes, partyEmailHash } = require('../envelope');

let passed = 0;
const ok = (n) => { passed++; console.log('  ok -', n); };

function loadEngine() {
  try {
    require('../crypto/bootstrap').bootstrap();
    const registry = require('../crypto/registry');
    const eng = registry.getSig(0x0002);
    if (eng && typeof eng.generateKeyPair === 'function') return eng;
  } catch (_) {}
  return null;
}

async function run(bindingMode, recipe) {
  const eng = loadEngine();
  if (!eng) return { skipped: true };

  const N = 2;
  const docHash = crypto.createHash('sha3-256').update('doc' + bindingMode).digest('hex');
  const id = 'env_' + crypto.randomBytes(8).toString('hex');
  const signers = [
    { name: 'Alice', email: 'alice@example.com' },
    { name: 'Bob', email: 'bob@example.com' },
  ];
  const out = { id, recipe_version: recipe, party_count: N, binding_mode: bindingMode };

  // Fake envStore.sign: VERIFY the sandbox signature with the real engine under
  // the effective recipe -- so a pass proves the sandbox produced a genuine,
  // slot-bound ML-DSA-65 signature, not a rubber stamp.
  let signedCount = 0;
  const signCalls = [];
  const envStore = {
    async sign(sid, pi, pubB64, sigB64, opts) {
      signCalls.push({ pi, opts });
      const emailHash = partyEmailHash(signers[pi].email);
      const eff = bindingMode === 'open' ? 4 : recipe;
      const msg = signMessageBytes(sid, docHash, pi, emailHash, eff, pubB64);
      let verified = false;
      try { verified = eng.verify(Buffer.from(sigB64, 'base64'), msg, Buffer.from(pubB64, 'base64')); } catch { verified = false; }
      if (!verified) return { ok: false, code: 'bad_signature' };
      if (bindingMode === 'email') {
        // sandbox must present the trusted-internal proof for an email slot
        if (!opts || !opts.internalTrusted || opts.verifiedEmailHash !== emailHash) return { ok: false, code: 'email_binding_required' };
      }
      signedCount++;
      const status = signedCount >= N ? 'complete' : 'sent';
      return { ok: true, code: 'new', signed_count: signedCount, party_count: N, status };
    },
  };

  // Capture webhook deliveries; provide the meta via the injected store.
  const secret = crypto.randomBytes(16).toString('hex');
  const deliveries = [];
  const store = { async getMeta() { return { webhook_url: 'https://hooks.example.test/x', webhook_secret: secret, metadata: { q: 1 } }; } };
  const deps = {
    sigEngine: eng,
    envStore,
    store,
    J: JSON.stringify,
    log: () => {},
    async safeHttpsRequest(url, o) {
      deliveries.push({ url, event: o.headers['X-Paramant-Event'], sig: o.headers['X-Paramant-Sig'], body: o.body });
      return { status: 200 };
    },
  };

  const res = await openApi.sandboxAutoSign(deps, out, signers, bindingMode, docHash);
  // let the fire-and-forget emitEvent() promises settle
  await new Promise(r => setTimeout(r, 30));

  assert.deepStrictEqual(res.signedIndices, [0, 1], `[${bindingMode}] both slots signed`);
  assert.strictEqual(res.status, 'complete', `[${bindingMode}] envelope completed`);
  assert.strictEqual(signCalls.length, 2, `[${bindingMode}] engine signed each slot once`);

  const events = deliveries.map(d => d.event).sort();
  assert.deepStrictEqual(events, ['envelope.completed', 'signer.completed', 'signer.completed'],
    `[${bindingMode}] fired 2x signer.completed + 1x envelope.completed`);

  // HMAC-SHA256 over the raw body verifies against the webhook secret.
  for (const d of deliveries) {
    const expect = crypto.createHmac('sha256', secret).update(d.body).digest('hex');
    assert.strictEqual(d.sig, expect, `[${bindingMode}] webhook HMAC verifies`);
  }
  return { skipped: false };
}

async function main() {
  const a = await run('open', 4);
  if (a.skipped) { console.log('  skip - ML-DSA-65 engine unavailable'); }
  else {
    ok('sandbox auto-signs an OPEN test envelope with valid v4 signatures + completion webhooks');
    await run('email', 2);
    ok('sandbox auto-signs an EMAIL-bound test envelope with valid v2 signatures + trusted-internal proof');
  }
}

main()
  .then(() => console.log(`\nparasign-sandbox: ${passed} checks passed`))
  .catch((e) => { console.error('\nFAILED:', e && e.stack || e); process.exit(1); });
