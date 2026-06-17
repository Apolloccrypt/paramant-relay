// Full functional test of the ParaSign signing subsystem, in real Chromium.
//
// Exercises the actual frontend modules (parasign-signer.js + vault.js +
// paramant-pqc.js + passphrase-prompt.js) with real WebCrypto, real IndexedDB,
// and a real WebAuthn virtual authenticator (CDP). Self-contained: it serves
// frontend/ over http and stubs the same-origin /api/* calls, so it needs no
// backend, Redis, or network.
//
//   Phase 1  pure + vault round-trips (passphrase + PRF + dual-wrap)
//   Phase 2  WebAuthn flows: enrol-with-passphrase, ensureSigningKey branching
//   Phase 3  shared promptPassphrase against the real ds-/cs-/en- panels
//
// The one path a virtual authenticator can't simulate is live WebAuthn-PRF
// *derivation* (needs PRF-capable hardware); everything our code does with a PRF
// output is covered via the vault layer.
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
  return j({ ok: true });
});

await page.goto(`${ORIGIN}/__proof`);
CRED_ID = await page.evaluate(async () => {
  const c = await navigator.credentials.create({ publicKey: { rp: { id: 'localhost', name: 't' }, user: { id: new Uint8Array([1,2,3,4]), name: 'u', displayName: 'u' }, challenge: new Uint8Array(32), pubKeyCredParams: [{ type: 'public-key', alg: -7 }], authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' }, timeout: 20000 } });
  const u = new Uint8Array(c.rawId); let s = ''; for (const x of u) s += String.fromCharCode(x); return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
});

const phase1 = await page.evaluate(async () => {
  const m = await import('/js/parasign-signer.js?v=10');
  const pqc = await import('/vendor/paramant-pqc.js');
  const vault = await import('/vendor/vault.js?v=3');
  const T = []; const ok = (name, cond, detail='') => T.push({ name, pass: !!cond, detail: String(detail) });
  const eqU8 = (a,b) => a.length===b.length && a.every((x,i)=>x===b[i]);
  const hex = (u8) => Array.from(u8).map(b=>b.toString(16).padStart(2,'0')).join('');
  const b64 = (u8) => { let s=''; for (let i=0;i<u8.length;i++) s+=String.fromCharCode(u8[i]); return btoa(s); };
  const rnd = (n) => crypto.getRandomValues(new Uint8Array(n));
  const delDB = () => new Promise(r => { const q = indexedDB.deleteDatabase('paramant'); q.onsuccess=q.onerror=q.onblocked=()=>r(); });
  const mk = () => { const s=rnd(32),k=pqc.ml_dsa65.keygen(s); return { k, pk:b64(k.publicKey), ph:hex(pqc.sha3_256(k.publicKey)), sk:k.secretKey.slice() }; };
  const PASS = 'correct-horse-battery-staple-42';
  const base = { envelopeId:'env_test_000000000001', docHash:'a'.repeat(64), partyIndex:0, emailHash:'b'.repeat(64) };
  try {
    const h0 = hex(m.buildDocSignMessage(base));
    ok('A1 buildDocSignMessage deterministic', h0===hex(m.buildDocSignMessage(base)));
    ok('A2 binds envelopeId', h0!==hex(m.buildDocSignMessage({...base,envelopeId:'env_test_000000000002'})));
    ok('A3 binds docHash', h0!==hex(m.buildDocSignMessage({...base,docHash:'c'.repeat(64)})));
    ok('A4 binds partyIndex', h0!==hex(m.buildDocSignMessage({...base,partyIndex:1})));
    ok('A5 binds emailHash', h0!==hex(m.buildDocSignMessage({...base,emailHash:'d'.repeat(64)})));
    const rej = (p) => { try { vault.assertStrongPassphrase(p); return false; } catch { return true; } };
    const acc = (p) => { try { vault.assertStrongPassphrase(p); return true; } catch { return false; } };
    ok('B1 reject empty', rej(''));
    ok('B2 reject short', rej('short1'));
    ok('B3 reject all-same-char', rej('aaaaaaaaaaaaaaaa'));
    ok('B4 reject common-word', rej('mypasswordhere12'));
    ok('B5 reject 12 lc-only', rej('abcdefghijkl'));
    ok('B6 accept long passphrase', acc(PASS));
    ok('B7 accept 16 mixed-classes', acc('Tr0ub4dour&3xtra'));
    await delDB(); const C = mk();
    await vault.vaultStore({ alg:'ML-DSA-65', label:'C', pk_b64:C.pk, pk_hash:C.ph, secretKeyBytes:C.k.secretKey, passphrase:PASS });
    const uC = await vault.vaultUnlock(C.ph, PASS);
    ok('C1 passphrase unlock returns the key', eqU8(uC.secretKeyBytes, C.sk));
    const msg = m.buildDocSignMessage(base);
    ok('C2 unlocked key signs + verifies', pqc.ml_dsa65.verify(C.k.publicKey, msg, pqc.ml_dsa65.sign(uC.secretKeyBytes, msg)));
    let w=false; try { await vault.vaultUnlock(C.ph,'wrong-pass-wrong-1'); } catch(e){ w=/wrong passphrase/.test(e.message); } ok('C3 wrong passphrase rejected', w);
    let n=false; try { await vault.vaultUnlock('deadbeefdeadbeef','x'); } catch(e){ n=/no such key/.test(e.message); } ok('C4 unknown id rejected', n);
    await delDB(); const D = mk(); const salt=rnd(16),out=rnd(32),cid='dGVzdGNyZWQ';
    await vault.vaultCreatePrfOnly({ alg:'ML-DSA-65', label:'D', pk_b64:D.pk, pk_hash:D.ph, secretKeyBytes:D.k.secretKey, credentialId:cid, prfSalt:salt, prfOutput:out.slice() });
    const info = await vault.vaultGetPrfWrapInfo(D.ph);
    ok('D1 getPrfWrapInfo returns credentialId+salt', info && info.credentialId===cid && !!info.prfSalt);
    const uD = await vault.vaultUnlockPrf(D.ph, { prfOutput:out.slice(), credentialId:cid });
    ok('D2 PRF unlock returns the key', eqU8(uD.secretKeyBytes, D.sk));
    ok('D3 PRF-unlocked key signs + verifies', pqc.ml_dsa65.verify(D.k.publicKey, msg, pqc.ml_dsa65.sign(uD.secretKeyBytes, msg)));
    let wp=false; try { await vault.vaultUnlockPrf(D.ph,{ prfOutput:rnd(32), credentialId:cid }); } catch(e){ wp=true; } ok('D4 wrong PRF output rejected', wp);
    await delDB(); const E = mk(); const sE=rnd(16),oE=rnd(32);
    await vault.vaultStore({ alg:'ML-DSA-65', label:'E', pk_b64:E.pk, pk_hash:E.ph, secretKeyBytes:E.k.secretKey, passphrase:PASS });
    await vault.vaultAddPrfWrap({ pk_hash:E.ph, secretKeyBytes:E.sk.slice(), credentialId:'ZHVhbA', prfSalt:sE, prfOutput:oE.slice() });
    const le = (await vault.vaultList()).find(k=>k.pk_hash===E.ph);
    ok('E1 both kekSources present', le && le.kekSources.includes('passphrase') && le.kekSources.includes('webauthn-prf'));
    const ep = await vault.vaultUnlock(E.ph, PASS), epr = await vault.vaultUnlockPrf(E.ph,{ prfOutput:oE.slice(), credentialId:'ZHVhbA' });
    ok('E2 passphrase + PRF unlock the SAME key', eqU8(ep.secretKeyBytes,E.sk) && eqU8(epr.secretKeyBytes,E.sk));
    await delDB(); let f1=false; try { await m.resolvePasskeySigningKey(); } catch(e){ f1=e.code==='no_signing_passkey'; } ok('F1 empty vault -> no_signing_passkey', f1);
    await delDB(); const Fa=mk(); await vault.vaultStore({ alg:'ML-DSA-65', label:'pp', pk_b64:Fa.pk, pk_hash:Fa.ph, secretKeyBytes:Fa.k.secretKey, passphrase:PASS });
    let rf = await m.resolvePasskeySigningKey(); ok('F2 passphrase-only -> hasPassphrase', rf.hasPassphrase===true && rf.hasPrf===false);
    await delDB(); const Fb=mk(); await vault.vaultCreatePrfOnly({ alg:'ML-DSA-65', label:'prf', pk_b64:Fb.pk, pk_hash:Fb.ph, secretKeyBytes:Fb.k.secretKey, credentialId:'Yg', prfSalt:rnd(16), prfOutput:rnd(32) });
    let rf2 = await m.resolvePasskeySigningKey(); ok('F3 PRF-only -> hasPrf', rf2.hasPrf===true && rf2.hasPassphrase===false);
    const Fc=mk(); await vault.vaultStore({ alg:'ML-DSA-65', label:'pp2', pk_b64:Fc.pk, pk_hash:Fc.ph, secretKeyBytes:Fc.k.secretKey, passphrase:PASS });
    let rf3 = await m.resolvePasskeySigningKey(); ok('F4 both present -> prefers PRF key', rf3.hasPrf===true && rf3.fingerprint===Fb.ph.slice(0,16));
    await delDB(); const H=mk(); await vault.vaultStore({ alg:'ML-DSA-65', label:'h', pk_b64:H.pk, pk_hash:H.ph, secretKeyBytes:H.k.secretKey, passphrase:PASS });
    let np=false; try { await new m.LocalVaultSigner().activate({ vaultId:H.ph, rpId:'localhost' }); } catch(e){ np=e.code==='need_passphrase'; } ok('H1 passphrase key w/o passphrase -> need_passphrase', np);
    const sg = await new m.LocalVaultSigner().activate({ vaultId:H.ph, rpId:'localhost', passphrase:PASS });
    ok('H2 activate(passphrase) signs + verifies', pqc.ml_dsa65.verify(H.k.publicKey, msg, await sg.sign(msg)));
    ok('H3 signer.publicKey matches enrolled pk', sg.publicKey===H.pk);
    sg.dispose(); let dp=false; try { await sg.sign(msg); } catch(e){ dp=/disposed/.test(e.message); } ok('H4 sign after dispose throws', dp);
  } catch(e){ ok('PHASE1 FATAL', false, e.message); }
  return T;
});

const phase2a = await page.evaluate(async () => {
  const m = await import('/js/parasign-signer.js?v=10');
  const pqc = await import('/vendor/paramant-pqc.js');
  const T = []; const ok = (name, cond, detail='') => T.push({ name, pass: !!cond, detail: String(detail) });
  const delDB = () => new Promise(r => { const q = indexedDB.deleteDatabase('paramant'); q.onsuccess=q.onerror=q.onblocked=()=>r(); });
  const base = { envelopeId:'env_test_000000000001', docHash:'a'.repeat(64), partyIndex:0, emailHash:'' };
  try {
    await delDB(); let i1=false; try { await m.ensureSigningKey({ rpId:'localhost' }); } catch(e){ i1=e.code==='prf_unsupported'; } ok('I1 no-PRF authenticator -> prf_unsupported', i1);
    const PASS = 'correct-horse-battery-staple-42';
    const key = await m.enrolSigningKeyWithPassphrase({ rpId:'localhost', label:'g', passphrase:PASS });
    ok('G1a enrol returns passphrase key', key.hasPassphrase===true && key.hasPrf===false && (key.pk_b64||'').length>1000);
    const signer = await new m.LocalVaultSigner().activate({ vaultId:key.vaultId, rpId:'localhost', passphrase:PASS });
    const msg = m.buildDocSignMessage(base); const sig = await signer.sign(msg); const pub = Uint8Array.from(atob(key.pk_b64), c=>c.charCodeAt(0)); signer.dispose();
    ok('G1b enrolled key signs + verifies (ML-DSA-65)', pqc.ml_dsa65.verify(pub, msg, sig));
    let g2=false; try { await m.enrolSigningKeyWithPassphrase({ rpId:'localhost', passphrase:'weak' }); } catch(e){ g2=/too weak/.test(e.message); } ok('G2 weak passphrase rejected', g2);
    const fp = await m.ensureSigningKey({ rpId:'localhost' }); ok('I2 fast-path returns existing key', fp && fp.hasPassphrase===true && fp.vaultId===key.vaultId);
  } catch(e){ ok('PHASE2a FATAL', false, e.message); }
  return T;
});

noPasskeyMode = true;
const phase2b = await page.evaluate(async () => {
  const m = await import('/js/parasign-signer.js?v=10');
  const T = []; const ok = (name, cond, detail='') => T.push({ name, pass: !!cond, detail: String(detail) });
  const delDB = () => new Promise(r => { const q = indexedDB.deleteDatabase('paramant'); q.onsuccess=q.onerror=q.onblocked=()=>r(); });
  await delDB();
  let c=''; try { await m.ensureSigningKey({ rpId:'localhost' }); } catch(e){ c=e.code; } ok('I3 server 409 no_passkey -> code no_passkey', c==='no_passkey', c);
  return T;
});
noPasskeyMode = false;

// Phase 3: the shared promptPassphrase against each real panel (ds-/cs-/en-).
const PANELS = [{ page: 'sign.html', prefix: 'ds-pass' }, { page: 'co-sign.html', prefix: 'cs-pass' }, { page: 'account.html', prefix: 'en-pass' }];
const phase3 = [];
for (const { page: pg, prefix } of PANELS) {
  await page.goto(`${ORIGIN}/${pg}`, { waitUntil: 'domcontentloaded' });
  const r = await page.evaluate(async (prefix) => {
    const out = {};
    const { promptPassphrase } = await import('/js/passphrase-prompt.js?v=1');
    const $ = (s) => document.getElementById(s);
    out.panelExists = !!$(prefix + '-panel') && !!$(prefix + '-input') && !!$(prefix + '-confirm');
    const tick = () => new Promise(r => setTimeout(r, 15));
    // unlock: enter a value, confirm -> resolves with it
    const p1 = promptPassphrase(prefix, 'unlock'); await tick();
    $(prefix + '-input').value = 'enter-me'; $(prefix + '-confirm').click();
    out.unlock = (await p1) === 'enter-me';
    // set: matching strong values -> resolves; panel hidden again
    const p2 = promptPassphrase(prefix, 'set'); await tick();
    $(prefix + '-input').value = 'correct-horse-battery-staple-42'; $(prefix + '-input2').value = 'correct-horse-battery-staple-42'; $(prefix + '-confirm').click();
    out.set = (await p2) === 'correct-horse-battery-staple-42';
    out.hiddenAfter = $(prefix + '-panel').hidden === true;
    // set mismatch -> error shown, promise still pending; cancel to clean up
    const p3 = promptPassphrase(prefix, 'set'); await tick();
    $(prefix + '-input').value = 'correct-horse-battery-staple-42'; $(prefix + '-input2').value = 'different-but-also-strong-99'; $(prefix + '-confirm').click(); await tick();
    out.mismatchErr = $(prefix + '-err').hidden === false;
    $(prefix + '-cancel').click(); out.cancelNull = (await p3) === null;
    return out;
  }, prefix);
  phase3.push({ name: `P3 ${prefix} panel (${pg}): exists=${r.panelExists} unlock=${r.unlock} set=${r.set} hidden=${r.hiddenAfter} mismatchErr=${r.mismatchErr} cancel=${r.cancelNull}`,
    pass: r.panelExists && r.unlock && r.set && r.hiddenAfter && r.mismatchErr && r.cancelNull, detail: '' });
}

await browser.close();
await new Promise(r => server.close(r));

const all = [...phase1, ...phase2a, ...phase2b, ...phase3];
let passed = 0;
console.log('\n================ ParaSign signing — FULL functional test ================');
for (const t of all) { console.log(`  ${t.pass ? 'PASS' : 'FAIL'}  ${t.name}${t.detail ? '   (' + t.detail + ')' : ''}`); if (t.pass) passed++; }
console.log(`\n  ${passed}/${all.length} passed`);
console.log('  (live WebAuthn-PRF derivation needs PRF-capable hardware; vault layer covers our PRF code)');
console.log('==========================================================================');
process.exit(passed === all.length ? 0 : 1);
