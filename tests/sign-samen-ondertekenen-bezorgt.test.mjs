// Matrix COSIGN-02 (fase 1, 2026-10-04): de modus "Samen ondertekenen" maakte
// een verzoek zonder versleuteld document en zonder sleutelhelft, er ging geen
// mail uit, en het eindscherm zei toch "De sleutel zit in de link". Wie werd
// uitgenodigd kon het document niet openen.
//
// Nu gaat het zoals bij "Handtekeningen vragen": na de handtekening van de
// afzender gaat het document zoals de anderen het tekenen (met zijn stempel)
// versleuteld mee, de helft van de sleutel naar de relay, de andere helft in
// de uitnodiging per mail, en de links op het eindscherm openen het document.
// Met "paraaf op elke pagina" krijgt elke medeondertekenaar ook die paraaf als
// verzoek mee. En de tekst onder de links zegt wat er echt gebeurde.
// Draait in Chromium; in WebKit via ~/bin/pw-webkit.sh.
// Run: node --test tests/sign-samen-ondertekenen-bezorgt.test.mjs
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { startServer, launch, newPage, makePdf, pickBytes, waitPlaced, clickPage } from './helpers/sign-flow-harness.mjs';

const { server, origin } = await startServer();
const browser = await launch();
after(async () => { await browser.close(); server.close(); });
const ENV_ID = 'env_demo_abcdefghijklmnop';

async function runCosign({ failUpload = false } = {}) {
  const page = await newPage(browser);
  const seen = { creates: [], uploads: [], invites: [] };
  await page.route('**/api/user/envelopes', async (route) => {
    const b = route.request().postDataJSON();
    seen.creates.push(b);
    const n = (b.recipients || []).length + 1;
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, envelope: { id: ENV_ID, party_count: n, binding_mode: 'email', expires_at: '2026-10-20T12:00:00.000Z',
      party_links: Array.from({ length: n }, (_, i) => ({ party_index: i, sign_path: `/co-sign?env=${ENV_ID}&p=${i}&t=${String(i).repeat(43)}`, invite_token: String(i).repeat(43) })) } }) });
  });
  await page.route(`**/api/user/sign/submit`, (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, signed_count: 1, party_count: 3, status: 'sent', appearance_hash: null }) }));
  await page.route(`**/api/user/envelopes/${ENV_ID}/document`, async (route) => {
    seen.uploads.push({ headers: route.request().headers(), body: Array.from(await route.request().postDataBuffer()) });
    if (failUpload) return route.fulfill({ status: 413, contentType: 'application/json', body: '{"error":"payload_too_large"}' });
    return route.fulfill({ status: 200, contentType: 'application/json', body: '{"ok":true}' });
  });
  await page.route(`**/api/user/envelopes/${ENV_ID}/invitations`, async (route) => {
    const b = route.request().postDataJSON();
    seen.invites.push(b);
    await route.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ok: true, failed_party_indexes: [], results: b.invitations.map((i) => ({ party_index: i.party_index, ok: true })) }) });
  });
  await page.goto(`${origin}/sign?mode=cosign`, { waitUntil: 'domcontentloaded' });
  await page.locator('#ds-doc-input').waitFor({ state: 'attached', timeout: 20000 });
  const pdf = await makePdf(page, { pages: [{ lines: true }, { lines: true }, { lines: true }, { lines: true }] });
  await pickBytes(page, pdf, 'huurcontract.pdf');
  await waitPlaced(page, 4);
  await clickPage(page, 3, 0.3, 0.9);
  await page.waitForTimeout(400);
  const all = page.locator('#ds-allpages');
  if (await all.isVisible() && !(await all.isChecked())) await all.check();
  await page.locator('#ds-place-continue').click();
  await page.locator('#step-recipients:not([hidden])').waitFor({ timeout: 20000 });
  const deliveryVisible = await page.locator('#ds-invite-delivery').isVisible();
  if ((await page.locator('.ds-recipient-row').count()) < 1) await page.locator('#ds-add-recipient').click();
  await page.locator('.ds-recipient-row').nth(0).locator('[data-field=label]').fill('Ayşe Yılmaz');
  await page.locator('.ds-recipient-row').nth(0).locator('[data-field=email]').fill('ayse@example.com');
  await page.locator('#ds-add-recipient').click();
  await page.locator('.ds-recipient-row').nth(1).locator('[data-field=label]').fill('Derde Partij');
  await page.locator('.ds-recipient-row').nth(1).locator('[data-field=email]').fill('derde@example.com');
  await page.locator('#ds-recipients-continue').click();
  await page.locator('#step-identity:not([hidden])').waitFor({ timeout: 20000 });
  await page.locator('#ds-signer-name').fill('Sandeep Panday');
  await page.locator('#ds-signer-name').dispatchEvent('input');
  await page.locator('#ds-identity-continue').click();
  await page.locator('#step-sign:not([hidden])').waitFor({ timeout: 20000 });
  await page.locator('#ds-sign-now').click();
  await page.locator('#ds-pass-panel:not([hidden])').waitFor({ timeout: 60000 });
  await page.locator('#ds-pass-input').fill('123456');
  await page.locator('#ds-pass-confirm').click();
  await page.locator('#step-done:not([hidden])').waitFor({ timeout: 120000 });
  await page.waitForTimeout(300);
  const ui = await page.evaluate(() => ({
    links: [...document.querySelectorAll('#ds-party-links .ds-pl-url')].map((e) => e.textContent),
    copy: (document.getElementById('ds-party-links-copy') || {}).textContent || '',
    result: (document.getElementById('ds-invite-delivery-result') || {}).textContent || '',
    resultHidden: !!(document.getElementById('ds-invite-delivery-result') || {}).hidden,
  }));
  // The capsule must open with the key in the sender's link and hash to the
  // document the envelope names: the one with the sender's stamp on it.
  let opened = null;
  if (seen.uploads.length && ui.links[0] && ui.links[0].includes('#doc=')) {
    opened = await page.evaluate(async ({ capsule, link, envId, docHash }) => {
      const m = await import('/js/parasign-document-capsule.js?v=2');
      const pqc = await import('/vendor/paramant-pqc.js');
      const out = await m.decryptDocumentCapsule({ capsule: new Uint8Array(capsule), fragment: link.slice(link.indexOf('#')), envelopeId: envId, docHash });
      const h = Array.from(pqc.sha3_256(out.bytes)).map((b) => b.toString(16).padStart(2, '0')).join('');
      return { hash: h, size: out.bytes.length };
    }, { capsule: seen.uploads[0].body, link: ui.links[0], envId: ENV_ID, docHash: seen.creates[0].doc_hash }).catch((e) => ({ error: String(e) }));
  }
  const errors = page._errors.slice();
  await page.context().close();
  return { seen, ui, opened, deliveryVisible, errors };
}

test('Samen ondertekenen: document gaat versleuteld mee, mail per medeondertekenaar, links openen het', async () => {
  const r = await runCosign();
  assert.equal(r.deliveryVisible, true, 'de keuze mail of zelf delen staat ook in deze modus');
  assert.equal(r.seen.uploads.length, 1, 'het versleutelde document is geüpload');
  assert.ok(/^[A-Za-z0-9_-]{43}$/.test(r.seen.uploads[0].headers['x-document-key-share'] || ''), 'met de helft van de sleutel voor de relay');
  assert.ok(r.opened && !r.opened.error && r.opened.hash === r.seen.creates[0].doc_hash, 'de link opent precies het document van het verzoek: ' + JSON.stringify(r.opened));
  assert.equal(r.seen.invites.length, 1, 'er gaat een uitnodiging per mail uit');
  const inv = r.seen.invites[0].invitations;
  assert.deepEqual(inv.map((i) => [i.party_index, i.email]), [[1, 'ayse@example.com'], [2, 'derde@example.com']], 'partij 1 en 2, niet de afzender');
  for (const i of inv) assert.match(new URL(i.invite_url).hash, /^#ks=v1\.[A-Za-z0-9_-]{43}$/, 'de mail draagt alleen een sleutelhelft');
  assert.equal(r.ui.links.length, 2);
  for (const l of r.ui.links) assert.ok(l.includes('#doc='), 'de link op het scherm opent het document: ' + l);
  assert.doesNotMatch(r.ui.copy, /De sleutel zit in de link\.$/);
  assert.match(r.ui.copy, /opent het document na inloggen/);
  const recips = r.seen.creates[0].recipients;
  assert.ok(recips.every((x) => x.requested_appearance && x.requested_appearance.fields.some((f) => f.all_pages)), 'elke medeondertekenaar krijgt de paraaf op elke pagina als verzoek');
  assert.deepEqual(r.errors, []);
});

test('Samen ondertekenen: lukt het meesturen niet, dan zegt het eindscherm dat eerlijk', async () => {
  const r = await runCosign({ failUpload: true });
  assert.equal(r.seen.invites.length, 0, 'zonder document geen mail die niets opent');
  assert.equal(r.ui.resultHidden, false);
  assert.match(r.ui.result, /Uw handtekening staat/);
  assert.match(r.ui.result, /te groot/);
  assert.match(r.ui.copy, /niet het document/);
  assert.deepEqual(r.errors, []);
});

// PDF-sweep B4: een scan van meer dan 5 MB maakte eerst het verzoek aan en
// faalde daarna bij het uploaden met "probeer het zo nog eens". Nu wordt de
// grens getoetst voordat er iets wordt aangemaakt, met de grens in de melding.
test('Handtekeningen vragen: te groot document stopt voor het aanmaken, met de grens erbij', async () => {
  const page = await newPage(browser);
  let creates = 0;
  await page.route('**/api/user/envelopes', (r) => { creates++; return r.fulfill({ status: 500, body: '{}' }); });
  await page.goto(`${origin}/sign?mode=invite`, { waitUntil: 'domcontentloaded' });
  await page.locator('#ds-doc-input').waitFor({ state: 'attached', timeout: 20000 });
  const base = await makePdf(page, { pages: [{ lines: true }] });
  const big = await page.evaluate(async (b64) => {
    const { PDFDocument } = window.PDFLib;
    const doc = await PDFDocument.load(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
    const junk = new Uint8Array(5.6 * 1024 * 1024);
    for (let i = 0; i < junk.length; i += 65536) crypto.getRandomValues(junk.subarray(i, Math.min(junk.length, i + 65536)));
    await doc.attach(junk, 'scan.bin', { mimeType: 'application/octet-stream' });
    const out = await doc.save({ useObjectStreams: false });
    let s = ''; for (let i = 0; i < out.length; i += 8192) s += String.fromCharCode.apply(null, out.subarray(i, i + 8192));
    return btoa(s);
  }, base.toString('base64'));
  await pickBytes(page, Buffer.from(big, 'base64'), 'scan-groot.pdf');
  await waitPlaced(page, 1);
  await clickPage(page, 0, 0.3, 0.9);
  await page.locator('#ds-place-continue').click();
  await page.locator('#step-recipients:not([hidden])').waitFor({ timeout: 20000 });
  if ((await page.locator('.ds-recipient-row').count()) < 1) await page.locator('#ds-add-recipient').click();
  await page.locator('.ds-recipient-row').nth(0).locator('[data-field=label]').fill('Ayşe Yılmaz');
  await page.locator('.ds-recipient-row').nth(0).locator('[data-field=email]').fill('ayse@example.com');
  await page.locator('#ds-recipients-continue').click();
  await page.locator('#ds-recipients-hint.err').waitFor({ timeout: 30000 });
  const hint = await page.locator('#ds-recipients-hint').innerText();
  await page.context().close();
  assert.equal(creates, 0, 'er is geen verzoek aangemaakt');
  assert.match(hint, /5 MB/);
  assert.doesNotMatch(hint, /Probeer het zo nog eens/);
});
