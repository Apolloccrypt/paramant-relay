// Full functional test of the ParaSign signing subsystem, in real Chromium.
//
// Exercises the actual frontend modules (parasign-signer.js + vault.js +
// paramant-pqc.js + totp-prompt.js) with real WebCrypto, real IndexedDB, and a
// real WebAuthn virtual authenticator (CDP). Self-contained: it serves frontend/
// over http and stubs the same-origin /api/* calls, so it needs no backend,
// Redis, or network.
//
// R018 v4 model: signing = "log in again". Passkey-PRF is the only PERSISTED
// unlock; the passphrase wrap is gone; the non-PRF fallback is a TOTP-gated
// EPHEMERAL key (fresh ML-DSA-65, bound via the TOTP enrol route, secret in
// memory only, zeroized after signing).
//
//   Phase 1  pure (buildDocSignMessage) + PRF vault round-trips + resolve
//   Phase 2  WebAuthn flows: ensureSigningKey branching + ephemeral TOTP enrol
//   Phase 3  shared promptTotp against the real ds-/cs- panels
//
// The one path a virtual authenticator can't simulate is live WebAuthn-PRF
// *derivation* (needs PRF-capable hardware); everything our code does with a PRF
// output is covered via the vault layer, and the ephemeral path needs no PRF.
//
// CI: `npx playwright install --with-deps chromium` then `node tests/sign-full.test.mjs`.
// Local: PLAYWRIGHT_CHROMIUM_PATH=<chrome binary> node tests/sign-full.test.mjs
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript','.mjs':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.json':'application/json','.wasm':'application/wasm','.png':'image/png' };

const server = http.createServer((req, res) => {
  const p = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (p === '/__proof') { res.writeHead(200, {'content-type':'text/html'}); return res.end('<!doctype html><meta charset=utf8><title>t</title>'); }
  const file = path.join(ROOT, p);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (e, b) => { if (e) { res.writeHead(404); return res.end(); } res.writeHead(200, {'content-type': MIME[path.extname(file)] || 'application/octet-stream'}); res.end(b); });
});
await new Promise(r => server.listen(0, '127.0.0.1', r));
const ORIGIN = `http://localhost:${server.address().port}`;

let CRED_ID = null, noPasskeyMode = false;
// Response override for the TOTP enrol route (POST /api/user/account/signing-key).
let totpResp = { status: 200, body: { ok: true } };
const CHAL = 'A'.repeat(43);

const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
const ctx = await browser.newContext({ baseURL: ORIGIN });
const page = await ctx.newPage();
const cdp = await ctx.newCDPSession(page);
await cdp.send('WebAuthn.enable');
await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });

await page.route('**/api/**', (route) => {
  const u = new URL(route.request().url());
  const j = (o, s = 200) => route.fulfill({ status: s, contentType: 'application/json', body: JSON.stringify(o) });
  if (u.pathname.endsWith('/signing-key/step-up/options')) {
    if (noPasskeyMode) return j({ error: 'no_passkey' }, 409);
    return j({ flowId: 'f', options: { challenge: CHAL, allowCredentials: CRED_ID ? [{ id: CRED_ID, transports: ['internal'] }] : [], userVerification: 'required', timeout: 20000, rpId: 'localhost' } });
  }
  if (u.pathname.endsWith('/signing-key/step-up/bind')) return j({ ok: true });
  // TOTP-gated ephemeral enrol route — response controlled by totpResp.
  if (u.pathname.endsWith('/account/signing-key')) return j(totpResp.body, totpResp.status);
  return j({ ok: true });
});

await page.goto(`${ORIGIN}/__proof`);
CRED_ID = await page.evaluate(async () => {
  const c = await navigator.credentials.create({ publicKey: { rp: { id: 'localhost', name: 't' }, user: { id: new Uint8Array([1,2,3,4]), name: 'u', displayName: 'u' }, challenge: new Uint8Array(32), pubKeyCredParams: [{ type: 'public-key', alg: -7 }], authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' }, timeout: 20000 } });
  const u = new Uint8Array(c.rawId); let s = ''; for (const x of u) s += String.fromCharCode(x); return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
});

const phase1 = await page.evaluate(async () => {
  const m = await import('/js/parasign-signer.js?v=11');
  const pqc = await import('/vendor/paramant-pqc.js');
  const vault = await import('/vendor/vault.js?v=4');
  const T = []; const ok = (name, cond, detail='') => T.push({ name, pass: !!cond, detail: String(detail) });
  const eqU8 = (a,b) => a.length===b.length && a.every((x,i)=>x===b[i]);
  const hex = (u8) => Array.from(u8).map(b=>b.toString(16).padStart(2,'0')).join('');
  const b64 = (u8) => { let s=''; for (let i=0;i<u8.length;i++) s+=String.fromCharCode(u8[i]); return btoa(s); };
  const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
  const delDB = () => new Promise(r => { const q = indexedDB.deleteDatabase('paramant'); q.onsuccess=q.onerror=q.onblocked=()=>r(); });
  const mk = () => { const s=rnd(32),k=pqc.ml_dsa65.keygen(s); return { k, pk:b64(k.publicKey), ph:hex(pqc.sha3_256(k.publicKey)), sk:k.secretKey.slice() }; };
  const base = { envelopeId:'env_test_000000000001', docHash:'a'.repeat(64), partyIndex:0, emailHash:'b'.repeat(64) };
  try {
    const h0 = hex(m.buildDocSignMessage(base));
    ok('A1 buildDocSignMessage deterministic', h0===hex(m.buildDocSignMessage(base)));
    ok('A2 binds envelopeId', h0!==hex(m.buildDocSignMessage({...base,envelopeId:'env_test_000000000002'})));
    ok('A3 binds docHash', h0!==hex(m.buildDocSignMessage({...base,docHash:'c'.repeat(64)})));
    ok('A4 binds partyIndex', h0!==hex(m.buildDocSignMessage({...base,partyIndex:1})));
    ok('A5 binds emailHash', h0!==hex(m.buildDocSignMessage({...base,emailHash:'d'.repeat(64)})));
    const msg = m.buildDocSignMessage(base);
    // D: PRF vault round-trip (the only persisted unlock).
    await delDB(); const D = mk(); const salt=rnd(16),out=rnd(32),cid='dGVzdGNyZWQ';
    await vault.vaultCreatePrfOnly({ alg:'ML-DSA-65', label:'D', pk_b64:D.pk, pk_hash:D.ph, secretKeyBytes:D.k.secretKey, credentialId:cid, prfSalt:salt, prfOutput:out.slice() });
    const info = await vault.vaultGetPrfWrapInfo(D.ph);
    ok('D1 getPrfWrapInfo returns credentialId+salt', info && info.credentialId===cid && !!info.prfSalt);
    const uD = await vault.vaultUnlockPrf(D.ph, { prfOutput:out.slice(), credentialId:cid });
    ok('D2 PRF unlock returns the key', eqU8(uD.secretKeyBytes, D.sk));
    ok('D3 PRF-unlocked key signs + verifies', pqc.ml_dsa65.verify(D.k.publicKey, msg, pqc.ml_dsa65.sign(uD.secretKeyBytes, msg)));
    let wp=false; try { await vault.vaultUnlockPrf(D.ph,{ prfOutput:rnd(32), credentialId:cid }); } catch(e){ wp=true; } ok('D4 wrong PRF output rejected', wp);
    // E: a SECOND PRF wrap (e.g. a second passkey) unlocks the SAME key.
    await delDB(); const E = mk(); const o1=rnd(32),o2=rnd(32);
    await vault.vaultCreatePrfOnly({ alg:'ML-DSA-65', label:'E', pk_b64:E.pk, pk_hash:E.ph, secretKeyBytes:E.k.secretKey, credentialId:'Y2E=', prfSalt:rnd(16), prfOutput:o1.slice() });
    await vault.vaultAddPrfWrap({ pk_hash:E.ph, secretKeyBytes:E.sk.slice(), credentialId:'Y2I=', prfSalt:rnd(16), prfOutput:o2.slice() });
    const le = (await vault.vaultList()).find(k=>k.pk_hash===E.ph);
    ok('E1 two PRF wraps present', le && le.kekSources.filter(s=>s==='webauthn-prf').length===2);
    const e1 = await vault.vaultUnlockPrf(E.ph,{ prfOutput:o1.slice(), credentialId:'Y2E=' }), e2 = await vault.vaultUnlockPrf(E.ph,{ prfOutput:o2.slice(), credentialId:'Y2I=' });
    ok('E2 both PRF wraps unlock the SAME key', eqU8(e1.secretKeyBytes,E.sk) && eqU8(e2.secretKeyBytes,E.sk));
    // F: resolvePasskeySigningKey.
    await delDB(); let f1=false; try { await m.resolvePasskeySigningKey(); } catch(e){ f1=e.code==='no_signing_passkey'; } ok('F1 empty vault -> no_signing_passkey', f1);
    const Fb=mk(); await vault.vaultCreatePrfOnly({ alg:'ML-DSA-65', label:'prf', pk_b64:Fb.pk, pk_hash:Fb.ph, secretKeyBytes:Fb.k.secretKey, credentialId:'Yg', prfSalt:rnd(16), prfOutput:rnd(32) });
    let rf2 = await m.resolvePasskeySigningKey(); ok('F2 PRF key -> hasPrf + correct fingerprint', rf2.hasPrf===true && rf2.vaultId===Fb.ph && rf2.fingerprint===Fb.ph.slice(0,16));
    ok('F3 resolved key carries pk_b64', (rf2.pk_b64||'').length>1000);
  } catch(e){ ok('PHASE1 FATAL', false, e.message); }
  return T;
});

// Phase 2a: ensureSigningKey branching + ephemeral TOTP enrol (admin stubbed ok).
const phase2a = await page.evaluate(async () => {
  const m = await import('/js/parasign-signer.js?v=11');
  const pqc = await import('/vendor/paramant-pqc.js');
  const vault = await import('/vendor/vault.js?v=4');
  const T = []; const ok = (name, cond, detail='') => T.push({ name, pass: !!cond, detail: String(detail) });
  const delDB = () => new Promise(r => { const q = indexedDB.deleteDatabase('paramant'); q.onsuccess=q.onerror=q.onblocked=()=>r(); });
  const base = { envelopeId:'env_test_000000000001', docHash:'a'.repeat(64), partyIndex:0, emailHash:'' };
  try {
    // I1: virtual authenticator can't produce a PRF result -> prf_unsupported.
    await delDB(); let i1=false; try { await m.ensureSigningKey({ rpId:'localhost' }); } catch(e){ i1=e.code==='prf_unsupported'; } ok('I1 no-PRF authenticator -> prf_unsupported', i1);
    // G: ephemeral TOTP enrol returns an in-memory signer (admin stub -> ok).
    const r = await m.enrolEphemeralSigningKeyWithTotp({ label:'g', totp:'123456' });
    ok('G1 ephemeral enrol returns signer + ephemeral signKey', !!r.signer && r.signKey.ephemeral===true && r.signKey.hasPrf===false && (r.signKey.pk_b64||'').length>1000);
    const msg = m.buildDocSignMessage(base); const sig = await r.signer.sign(msg);
    const pub = Uint8Array.from(atob(r.signKey.pk_b64), c=>c.charCodeAt(0));
    ok('G2 ephemeral signer signs + verifies (ML-DSA-65)', pqc.ml_dsa65.verify(pub, msg, sig));
    ok('G3 signer.publicKey matches signKey pk', r.signer.publicKey===r.signKey.pk_b64);
    r.signer.dispose(); let dp=false; try { await r.signer.sign(msg); } catch(e){ dp=/disposed/.test(e.message); } ok('G4 sign after dispose throws', dp);
    ok('G5 ephemeral key NOT persisted to vault', (await vault.vaultList()).length===0);
    let g6=false; try { await m.enrolEphemeralSigningKeyWithTotp({ totp:'abc' }); } catch(e){ g6=e.code==='totp_required'; } ok('G6 malformed code rejected', g6);
  } catch(e){ ok('PHASE2a FATAL', false, e.message); }
  return T;
});

// Phase 2b: TOTP enrol error mapping (admin stub returns relay 403s).
totpResp = { status: 403, body: { error: 'invalid_totp' } };
const phase2b1 = await page.evaluate(async () => {
  const m = await import('/js/parasign-signer.js?v=11');
  const T = []; const ok = (name, cond, detail='') => T.push({ name, pass: !!cond, detail: String(detail) });
  let c=''; try { await m.enrolEphemeralSigningKeyWithTotp({ totp:'654321' }); } catch(e){ c=e.code; } ok('J1 relay 403 invalid_totp -> totp_invalid', c==='totp_invalid', c);
  return T;
});
totpResp = { status: 403, body: { error: 'no_totp_setup' } };
const phase2b2 = await page.evaluate(async () => {
  const m = await import('/js/parasign-signer.js?v=11');
  const T = []; const ok = (name, cond, detail='') => T.push({ name, pass: !!cond, detail: String(detail) });
  let c=''; try { await m.enrolEphemeralSigningKeyWithTotp({ totp:'654321' }); } catch(e){ c=e.code; } ok('J2 relay 403 no_totp_setup -> totp_unavailable', c==='totp_unavailable', c);
  return T;
});
totpResp = { status: 200, body: { ok: true } };

// Phase 2c: server 409 no_passkey path.
noPasskeyMode = true;
const phase2c = await page.evaluate(async () => {
  const m = await import('/js/parasign-signer.js?v=11');
  const T = []; const ok = (name, cond, detail='') => T.push({ name, pass: !!cond, detail: String(detail) });
  const delDB = () => new Promise(r => { const q = indexedDB.deleteDatabase('paramant'); q.onsuccess=q.onerror=q.onblocked=()=>r(); });
  await delDB();
  let c=''; try { await m.ensureSigningKey({ rpId:'localhost' }); } catch(e){ c=e.code; } ok('I3 server 409 no_passkey -> code no_passkey', c==='no_passkey', c);
  return T;
});
noPasskeyMode = false;

// Phase 3: the shared promptTotp against each real panel (ds-/cs-).
const PANELS = [{ page: 'sign.html', prefix: 'ds-pass' }, { page: 'co-sign.html', prefix: 'cs-pass' }];
const phase3 = [];
for (const { page: pg, prefix } of PANELS) {
  await page.goto(`${ORIGIN}/${pg}`, { waitUntil: 'domcontentloaded' });
  const r = await page.evaluate(async (prefix) => {
    const out = {};
    const { promptTotp } = await import('/js/totp-prompt.js?v=1');
    const $ = (s) => document.getElementById(s);
    out.panelExists = !!$(prefix + '-panel') && !!$(prefix + '-input') && !!$(prefix + '-confirm');
    const tick = () => new Promise(r => setTimeout(r, 15));
    // valid 6-digit code, confirm -> resolves with it; panel hidden again
    const p1 = promptTotp(prefix); await tick();
    $(prefix + '-input').value = '123456'; $(prefix + '-confirm').click();
    out.ok = (await p1) === '123456';
    out.hiddenAfter = $(prefix + '-panel').hidden === true;
    // invalid code -> error shown, promise still pending; cancel to clean up
    const p2 = promptTotp(prefix); await tick();
    $(prefix + '-input').value = '12ab'; $(prefix + '-confirm').click(); await tick();
    out.invalidErr = $(prefix + '-err').hidden === false;
    $(prefix + '-cancel').click(); out.cancelNull = (await p2) === null;
    return out;
  }, prefix);
  phase3.push({ name: `P3 ${prefix} panel (${pg}): exists=${r.panelExists} ok=${r.ok} hidden=${r.hiddenAfter} invalidErr=${r.invalidErr} cancel=${r.cancelNull}`,
    pass: r.panelExists && r.ok && r.hiddenAfter && r.invalidErr && r.cancelNull, detail: '' });
}

await browser.close();
await new Promise(r => server.close(r));

const all = [...phase1, ...phase2a, ...phase2b1, ...phase2b2, ...phase2c, ...phase3];
let passed = 0;
console.log('\n================ ParaSign signing — FULL functional test ================');
for (const t of all) { console.log(`  ${t.pass ? 'PASS' : 'FAIL'}  ${t.name}${t.detail ? '   (' + t.detail + ')' : ''}`); if (t.pass) passed++; }
console.log(`\n  ${passed}/${all.length} passed`);
console.log('  (live WebAuthn-PRF derivation needs PRF-capable hardware; vault layer covers our PRF code)');
console.log('==========================================================================');
process.exit(passed === all.length ? 0 : 1);
