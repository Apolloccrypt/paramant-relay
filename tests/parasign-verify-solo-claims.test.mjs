// /verify may only state as fact what a solo .psign actually signs.
//
// A v3 solo proof (parasign-doc-3) signs the document hash, the envelope id,
// the party index, the email hash, the signer key and the appearance
// (buildDocSignMessage). signer_name, signer_pk_fingerprint and signed_at sit
// next to the signature, free to edit. Test round 3 (2026-10-04, finding 2 and
// 3) made a proof with its own key, the name "Mick (Paramant)", someone else's
// fingerprint and the date 2020-01-01, and /verify showed all three as facts
// under a green banner; offline even the one hedge ("not linked to an account")
// disappeared, and with a revoked key the page told the reader to trust the
// signature if it was made before the revocation, judged by that same free date.
//
// This suite pins the honest version: the key fingerprint shown is computed
// from the key, the name and date are labelled as stated and not checked, the
// "not tied to a person" sentence is there with the network cut, a forged
// fingerprint is called out, a proof from a multi-party envelope says it covers
// one signer, and a revoked key takes the green away.
import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript', '.css':'text/css', '.html':'text/html', '.svg':'image/svg+xml', '.wasm':'application/wasm', '.png':'image/png' };
const server = http.createServer((req, res) => {
  let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (pathname === '/') pathname = '/index.html';
  const file = path.join(ROOT, pathname);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (error, body) => {
    if (error) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(body);
  });
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const origin = `http://127.0.0.1:${server.address().port}`;
const browser = await chromium.launch({ headless: true, ...(EXE ? { executablePath: EXE } : {}) });
const page = await browser.newPage({ viewport:{ width:390, height:844 } });
await page.goto(origin + '/', { waitUntil:'domcontentloaded' });

const forged = await page.evaluate(async () => {
  const pqc = await import('/vendor/paramant-pqc.js');
  const signer = await import('/js/parasign-signer.js?v=20');
  const enc = new TextEncoder();
  const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  const b64 = (bytes) => { let value = ''; for (const byte of bytes) value += String.fromCharCode(byte); return btoa(value); };
  const source = enc.encode('a contract nobody at Paramant ever signed');
  const documentHash = hex(pqc.sha3_256(source));
  const keys = pqc.ml_dsa65.keygen(crypto.getRandomValues(new Uint8Array(32)));
  const signerPublicKey = b64(keys.publicKey);
  const emailHash = hex(pqc.sha3_256(enc.encode('forger@example.invalid')));
  const appearance = signer.normaliseSigningAppearance({ version:1, fields:[] });
  const envelopeId = 'env_forged_solo_claims';
  const message = signer.buildDocSignMessage({ envelopeId, docHash:documentHash, partyIndex:0, emailHash, recipeVersion:5, signerPublicKey, appearance });
  return {
    source:Array.from(source),
    realFp:hex(pqc.sha3_256(keys.publicKey)).slice(0, 16),
    psign:{
      version:'parasign-doc-3', recipe_version:5, sign_domain:'paramant/parasign/doc/v1',
      algorithm:'ML-DSA-65', hash_algorithm:'SHA3-256', original_filename:'contract.txt',
      document_hash:documentHash,
      signer_name:'Mick (Paramant)',
      signer_pk_fingerprint:'deadbeefcafe0001',
      signer_public_key:signerPublicKey, party_email_hash:emailHash,
      appearance, appearance_hash:hex(signer.signingAppearanceHash(appearance)),
      signature:b64(pqc.ml_dsa65.sign(keys.secretKey, message)),
      signed_at:'2020-01-01T00:00:00Z',
      multiparty:{ envelope_id:envelopeId, party_index:0, party_count:2, signed_count:1 },
    },
  };
});

async function runOnce({ url, verdict, lookup }) {
  await page.unroute('https://relay.paramant.app/**');
  // Offline: every request to the relay fails, as on a plane or behind a
  // firewall. Revoked: the public lookup answers that the key was revoked.
  await page.route('https://relay.paramant.app/**', (route) => (lookup
    ? route.fulfill({ status:200, contentType:'application/json', body:JSON.stringify(lookup) })
    : route.abort('internetdisconnected')));
  await page.goto(origin + url, { waitUntil:'domcontentloaded' });
  await page.locator('#vf-document').setInputFiles({ name:'contract.txt', mimeType:'text/plain', buffer:Buffer.from(forged.source) });
  await page.locator('#vf-envelope').setInputFiles({ name:'contract.psign', mimeType:'application/json', buffer:Buffer.from(JSON.stringify(forged.psign)) });
  const info = await page.locator('#vf-envelope-info').innerText();
  const lookups = [];
  const onReq = (req) => { if (/lookup-signer/.test(req.url())) lookups.push(req.url()); };
  page.on('request', onReq);
  await page.locator('#vf-verify').click();
  await page.waitForFunction((src) => new RegExp(src).test(document.querySelector('#vf-result')?.textContent || ''), verdict.source);
  // The account lookup is a question the reader asks, never one the page asks
  // by itself (retest T3-10).
  await page.waitForTimeout(300);
  const lookupsBeforeClick = lookups.length;
  if (lookup) {
    await page.locator('#vf-lookup').click();
    await page.waitForFunction(() => /ingetrokken|revoked/i.test(document.querySelector('#vf-result')?.textContent || ''));
  }
  page.off('request', onReq);
  return { info, lookupsBeforeClick, result: await page.locator('#vf-result').innerText(), banner: await page.locator('#vf-result .ps-banner').first().getAttribute('class') };
}

const nl = { url:'/verify.html', verdict:/Handtekening geldig|Handtekening ONGELDIG|Sleutel ingetrokken|bestand is aangepast|handtekening klopt met dit document/ };
const en = { url:'/en/verify.html', verdict:/Signature valid|Signature INVALID|Key revoked|has been altered|signature matches this document/ };
const offlineNl = await runOnce(nl);
const offlineEn = await runOnce(en);
const revokedNl = await runOnce({ ...nl, lookup:{ found:true, label:'Someone', email:'someone@example.invalid', alg:'ML-DSA-65', revoked_at:'2026-06-01T00:00:00Z' } });

await browser.close();
server.close();

const fail = (what, got) => { throw new Error(what + '\n--- got ---\n' + got); };

// The file line above the button names no signer, and shows the key the
// signature really belongs to.
for (const [lang, o] of [['nl', offlineNl], ['en', offlineEn]]) {
  if (/Mick/.test(o.info)) fail(lang + ': the free signer_name is shown as the signer in the file line', o.info);
  if (/deadbeef/.test(o.info)) fail(lang + ': the free fingerprint is shown in the file line', o.info);
  if (!o.info.includes(forged.realFp)) fail(lang + ': the computed key fingerprint is missing from the file line', o.info);
  if (!o.result.includes(forged.realFp)) fail(lang + ': the computed key fingerprint is missing from the result', o.result);
}

// The mathematics is sound (it is a real signature by some key), but the file
// writes a fingerprint that belongs to another key: someone altered it. The
// banner says so in orange instead of a reassuring green (retest T3-2), and
// everything the key does not prove is labelled.
const r = offlineNl.result;
if (!/De handtekening klopt, maar dit bestand is aangepast/.test(r)) fail('nl: the banner should say the signature holds but the file was altered', r);
if (!/\bwarn\b/.test(offlineNl.banner) || /\bok\b/.test(offlineNl.banner)) fail('nl: an altered file must not get the green banner: ' + offlineNl.banner, r);
if (!/has been altered/.test(offlineEn.result)) fail('en: the banner should say the file was altered', offlineEn.result);
for (const [lang, o] of [['nl', offlineNl], ['en', offlineEn], ['nl revoked', revokedNl]]) {
  if (o.lookupsBeforeClick !== 0) fail(lang + ': the page asked the relay about the key without being asked', String(o.lookupsBeforeClick));
}
if (!/koppelt deze sleutel niet aan een persoon of account/.test(r)) fail('nl offline: "not tied to a person" sentence missing with the network cut', r);
if (!/Naam: Mick \(Paramant\) \(opgegeven door de ondertekenaar, niet gecontroleerd\)/.test(r)) fail('nl: name not labelled as unchecked', r);
if (!/Datum: 2020-01-01T00:00:00Z \(opgegeven door de ondertekenaar, niet gecontroleerd\)/.test(r)) fail('nl: date not labelled as unchecked', r);
if (!/deadbeefcafe0001[\s\S]*hoort niet bij de sleutel die tekende/.test(r)) fail('nl: forged fingerprint not called out', r);
if (!/partij 1 van 2/.test(r)) fail('nl: multi-party scope caveat missing', r);
if (/Ondertekenaar: Mick|ondertekenaar: Mick/.test(r)) fail('nl: name presented as fact', r);

const e = offlineEn.result;
if (!/does not tie this key to a person or account/.test(e)) fail('en offline: "not tied to a person" sentence missing', e);
if (!/Name: Mick \(Paramant\) \(stated by the signer, not checked\)/.test(e)) fail('en: name not labelled as unchecked', e);
if (!/party 1 of 2/.test(e)) fail('en: multi-party scope caveat missing', e);

// Revoked key: no green, and no "valid if signed before" judged by a date the
// forger chose.
const v = revokedNl;
if (!/\bwarn\b/.test(v.banner) || /\bok\b/.test(v.banner)) fail('nl revoked: banner still green: ' + v.banner, v.result);
if (/Beschouw hem als geldig/.test(v.result)) fail('nl revoked: reassuring "valid if signed before" sentence still shown', v.result);
if (!/geen ondertekend tijdstip/.test(v.result)) fail('nl revoked: missing the explanation that the proof has no signed time', v.result);

console.log('parasign-verify-solo-claims: a self-made solo proof shows its name, date and fingerprint as unchecked claims, offline too; a revoked key loses the green');
