import { chromium } from 'playwright';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const pqc = await import(path.join(ROOT, 'vendor', 'paramant-pqc.js'));
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

const fixture = await page.evaluate(async () => {
  const pqc = await import('/vendor/paramant-pqc.js');
  const signer = await import('/js/parasign-signer.js?v=20');
  const enc = new TextEncoder();
  const hex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  const b64 = (bytes) => { let value = ''; for (const byte of bytes) value += String.fromCharCode(byte); return btoa(value); };
  const canonical = (value) => {
    if (value === null || typeof value !== 'object') return JSON.stringify(value);
    if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
    return '{' + Object.keys(value).sort().map((key) => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  };
  const source = enc.encode('generic source document for multi signer verification');
  const documentHash = hex(pqc.sha3_256(source));
  const signerKeys = pqc.ml_dsa65.keygen(crypto.getRandomValues(new Uint8Array(32)));
  const relayKeys = pqc.ml_dsa65.keygen(crypto.getRandomValues(new Uint8Array(32)));
  const signerPublicKey = b64(signerKeys.publicKey);
  const emailHash = hex(pqc.sha3_256(enc.encode('generic recipient binding')));
  const appearance = signer.normaliseSigningAppearance({ version:1, fields:[
    { type:'seal', page_index:0, x:.4, y:.7, w:.36, h:.105 },
  ] });
  const envelopeId = 'env_demo_multi_verify';
  const message = signer.buildDocSignMessage({ envelopeId, docHash:documentHash, partyIndex:0, emailHash, recipeVersion:5, signerPublicKey, appearance });
  const receipt = {
    type:'parasign-envelope-receipt', version:'2', algorithm:'ML-DSA-65',
    envelope_id:envelopeId, document_hash:documentHash, document_hash_algo:'sha3-256',
    binding_mode:'email', recipe_version:5, sign_recipe:5, status:'completed',
    created_at:'2026-07-21T11:00:00.000Z', completed_at:'2026-07-21T12:00:00.000Z', expires_at:'2026-08-20T12:00:00.000Z',
    parties:[{
      index:0, label:'Signer Demo', email_hash:emailHash, status:'signed', signed_at:'2026-07-21T12:00:00.000Z',
      public_key:signerPublicKey, signature:b64(pqc.ml_dsa65.sign(signerKeys.secretKey, message)),
      signer_pk_hash:hex(pqc.sha3_256(signerKeys.publicKey)), appearance,
      appearance_hash:hex(signer.signingAppearanceHash(appearance)),
    }],
    notary:{ relay_pk_hash:hex(pqc.sha3_256(relayKeys.publicKey)), relay_public_key:b64(relayKeys.publicKey), relay_pubkey_url:'https://paramant.app/v2/pubkey' },
  };
  const notarise = (body) => ({ ...body, notary_signature:b64(pqc.ml_dsa65.sign(relayKeys.secretKey, enc.encode(canonical(body)))) });
  receipt.notary_signature = b64(pqc.ml_dsa65.sign(relayKeys.secretKey, enc.encode(canonical(receipt))));
  // A sandbox receipt carries mode/sandbox INSIDE the notary signature, as
  // relay/lib/parasign-open-api.js buildEnvelopePsign writes it.
  const { notary_signature: _drop, ...plain } = receipt;
  const sandboxReceipt = notarise({ ...plain, mode:'test', sandbox:true });
  return { source:Array.from(source), receipt, sandboxReceipt, relayPublicKey:b64(relayKeys.publicKey) };
});


// The relay key of this fixture is made up on the spot, exactly like the one a
// forger would make up. The page may only call such a receipt genuine when that
// key is one of the pins in js/relay-trust-anchors.js, so the "real" runs below
// serve the anchors module with this key added, the way a pinned relay would
// be, and the forged runs serve the module as it ships.
const relayKeyBytes = Buffer.from(fixture.relayPublicKey, 'base64');
const relayFp = Buffer.from(pqc.sha3_256(new Uint8Array(relayKeyBytes))).toString('hex');
const anchorsSource = fs.readFileSync(path.join(ROOT, 'js', 'relay-trust-anchors.js'), 'utf8');
const anchorsWithTestRelay = anchorsSource + `
RELAY_TRUST_ANCHORS.push({ name:'the test relay', name_nl:'de testrelay', host:'test-relay.invalid', sector:'test', alg:'ML-DSA-65', fingerprint:'${relayFp}', key:'${fixture.relayPublicKey}' });
`;

async function runOnce({ url, verdict, receipt, doc, trustRelay }) {
  await page.unroute('**/js/relay-trust-anchors.js*');
  if (trustRelay) {
    await page.route('**/js/relay-trust-anchors.js*', (route) => route.fulfill({ status:200, contentType:'text/javascript', body:anchorsWithTestRelay }));
  }
  await page.goto(origin + url, { waitUntil:'domcontentloaded' });
  await page.locator('#vf-document').setInputFiles({ name:'source-demo.pdf', mimeType:'application/pdf', buffer:Buffer.from(doc || fixture.source) });
  await page.locator('#vf-envelope').setInputFiles({ name:'source-demo.psign', mimeType:'application/json', buffer:Buffer.from(JSON.stringify(receipt)) });
  await page.locator('#vf-verify').click();
  await page.waitForFunction((src) => new RegExp(src).test(document.querySelector('#vf-result')?.textContent || ''), verdict.source);
  return {
    result: await page.locator('#vf-result').innerText(),
    banner: await page.locator('#vf-result .ps-banner').first().getAttribute('class'),
    mark: await page.locator('#vf-result .ps-banner .ps-mark').first().textContent().catch(() => ''),
    keyHidden: await page.locator('#vf-key-block').isHidden(),
    overflow: await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth),
  };
}

// The same receipt through both copies of the page: the English words on
// /en/verify, the Dutch words on /verify. One parasign-verify.js serves both.
const runs = [
  { url:'/en/verify.html', verdict:/Signature valid|Signature INVALID|Test proof|This is not the signed file/, valid:/Signature valid/, invalid:/Signature INVALID/, offline:/verified offline/,
    unknownRelay:/is not a Paramant key/, pinned:/Counter-signed by the test relay/, test:/Test proof, not a real signature/, stampedHint:/reading copy/, stampedHead:/This is not the signed file[\s\S]*check with the original/, stampedMark:/Paramant ParaSign · PQ/ },
  { url:'/verify.html', verdict:/Handtekening geldig|Handtekening ONGELDIG|Testbewijs|Dit is niet het ondertekende bestand/, valid:/Handtekening geldig/, invalid:/Handtekening ONGELDIG/, offline:/offline gecontroleerd/,
    unknownRelay:/is geen sleutel van Paramant/, pinned:/Bekrachtigd door de testrelay/, test:/Testbewijs, geen echte ondertekening/, stampedHint:/leesbare kopie/, stampedHead:/Dit is niet het ondertekende bestand[\s\S]*Controleer dan met het origineel/, stampedMark:/Paramant ParaSign · PQ/ },
];
const outcomes = [];
for (const run of runs) {
  outcomes.push({ run, kind:'pinned', ...(await runOnce({ ...run, receipt:fixture.receipt, trustRelay:true })) });
  outcomes.push({ run, kind:'forged', ...(await runOnce({ ...run, receipt:fixture.receipt, trustRelay:false })) });
  outcomes.push({ run, kind:'sandbox', ...(await runOnce({ ...run, receipt:fixture.sandboxReceipt, trustRelay:true })) });
  // The reading copy co-sign.js writes carries a marker with THIS envelope
  // and THIS original. Only that file gets the orange "check with the
  // original"; any other wrong file is INVALID (hertest r2 R1: M7/M8 were orange).
  const docHash = fixture.receipt.document_hash;
  const mark = (env, doc) => Buffer.from('\n%stamped copy\n<< /ParamantStampedCopy (env=' + env + ';doc=' + doc + ') >>\n');
  const stamped = [...fixture.source, ...mark(fixture.receipt.envelope_id, docHash)];
  outcomes.push({ run, kind:'stamped', ...(await runOnce({ ...run, receipt:fixture.receipt, doc:stamped, trustRelay:true })) });
  const oneByte = fixture.source.slice(); oneByte[3] ^= 1;
  outcomes.push({ run, kind:'wrongdoc', ...(await runOnce({ ...run, receipt:fixture.receipt, doc:oneByte, trustRelay:true })) });
  const otherEnv = [...fixture.source, ...mark('env_some_other_envelope', docHash)];
  outcomes.push({ run, kind:'wrongdoc', ...(await runOnce({ ...run, receipt:fixture.receipt, doc:otherEnv, trustRelay:true })) });
  const otherDoc = [...fixture.source, ...mark(fixture.receipt.envelope_id, 'ab'.repeat(32))];
  outcomes.push({ run, kind:'wrongdoc', ...(await runOnce({ ...run, receipt:fixture.receipt, doc:otherDoc, trustRelay:true })) });
  const unmarked = [...fixture.source, ...Buffer.from('\n%stamped copy without the marker')];
  outcomes.push({ run, kind:'wrongdoc', ...(await runOnce({ ...run, receipt:fixture.receipt, doc:unmarked, trustRelay:true })) });
}

await browser.close();
server.close();
for (const o of outcomes) {
  const { run, kind, result, banner, mark, keyHidden, overflow } = o;
  const where = run.url + ' [' + kind + ']: ';
  if (!keyHidden) throw new Error(where + 'API key field visible for self-contained proof');
  if (overflow > 1) throw new Error(where + 'phone overflow: ' + overflow);
  if (kind === 'pinned') {
    if (!run.valid.test(result)) throw new Error(where + result);
    if (!run.offline.test(result)) throw new Error(where + 'offline result missing');
    if (!run.pinned.test(result)) throw new Error(where + 'pinned relay not named: ' + result);
    if (!/\bok\b/.test(banner) || mark !== '✓') throw new Error(where + 'valid verdict lacks the green check: ' + banner + ' ' + mark);
  }
  if (kind === 'forged') {
    // Finding 1 of test round 3: a receipt whose notary key is not one of ours
    // was "Handtekening geldig" because the page checked it against the key
    // printed inside the file. It must be red, and say why.
    if (run.valid.test(result) || !run.invalid.test(result)) throw new Error(where + 'self-signed receipt not refused: ' + result);
    if (!run.unknownRelay.test(result)) throw new Error(where + 'unknown relay key not explained: ' + result);
    if (!/\berr\b/.test(banner) || mark !== '✕') throw new Error(where + 'invalid verdict lacks the red cross: ' + banner + ' ' + mark);
  }
  if (kind === 'sandbox') {
    if (!run.test.test(result)) throw new Error(where + 'sandbox receipt not marked as a test: ' + result);
    if (run.valid.test(result)) throw new Error(where + 'sandbox receipt shown as a real valid signature: ' + result);
  }
  if (kind === 'wrongdoc') {
    if (!run.invalid.test(result) || run.stampedHead.test(result)) throw new Error(where + 'a wrong document must be INVALID, not "the stamped copy": ' + result);
    if (!/\berr\b/.test(banner) || mark !== '✕') throw new Error(where + 'wrong document lacks the red cross: ' + banner + ' ' + mark);
  }
  if (kind === 'stamped') {
    // Every signature holds and only the file differs: an orange "check with
    // the original", not a red INVALID, naming the mark the copy really carries
    // (retest A8/T5-7: the old text named a footer the co-sign copy does not have).
    if (run.invalid.test(result)) throw new Error(where + 'stamped copy still called INVALID: ' + result);
    if (!run.stampedHead.test(result) || !run.stampedHint.test(result) || !run.stampedMark.test(result)) throw new Error(where + 'stamped copy not explained: ' + result);
    if (!/\bwarn\b/.test(banner) || /\b(ok|err)\b/.test(banner)) throw new Error(where + 'stamped copy banner should be orange: ' + banner);
  }
}
console.log('parasign-multi-verify: recipe 5 receipt verifies offline against a pinned relay key; a self-signed relay key, a sandbox receipt and a stamped copy are each called what they are, in Chromium');
