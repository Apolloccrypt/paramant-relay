// /sign: what goes wrong must be said as what it is, and the common cases must
// simply work. From the test reports of 2026-10-04:
//   - a name with ş, ı, Ł, Ĳ, ễ or Chinese made the bake throw (WinAnsi) and the
//     signer was told his passkey failed (tester 1, point 3);
//   - a PDF locked with an owner password went through the whole flow and then
//     failed with the passkey text; one with an opening password was called
//     "corrupt" (points 4 and 7);
//   - a PNG named .jpg failed in the bake, again as a passkey error (point 8);
//   - every bake failure read as a passkey failure (point 9);
//   - 403 signer_not_enrolled read as "authorization already used" and starting
//     over picked the same unlinked key forever (tester 3, point 4);
//   - after dragging the seal with a finger the next tap was eaten (point 5);
//   - the seal vanished after Back (point 6);
//   - a saved template switched "every page" on, unseen, for the next document
//     (point 11);
//   - a paying customer read "Free forever · 2 signatures a month" (tester 5, point 8).
// Run: node --test tests/sign-errors.test.mjs
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { startServer, launch, newPage, openSign, makePdf, pickBytes, waitPlaced, clickPage, uiBoxes, signAndDownload, signNow, measurePdf, savePngs } from './helpers/sign-flow-harness.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SHOTS = process.env.PARAMANT_SIGN_SHOT_DIR || '';
const PASSKEY_TEXT = /passkey kon het ondertekenen|passkey could not complete/i;

const { server, origin } = await startServer();
const browser = await launch();
after(async () => { await browser.close(); server.close(); });

const A4 = [595.28, 841.89];

async function readyOnePage(page, spec = { pages: [{ size: A4 }] }) {
  await openSign(page, origin);
  const pdf = await makePdf(page, spec);
  await pickBytes(page, pdf, 'contract.pdf');
  await waitPlaced(page, spec.pages.length);
  return pdf;
}

// ── 3. every name can sign ─────────────────────────────────────────────────
const NAMES = [
  ['Ayşe Yılmaz', 'text'],
  ['Łukasz Żółć', 'text'],
  ['Ĳsbrand van Dijk', 'text'],
  ['Nguyễn Văn An', 'text'],
  ['José van Dijk-Ünal', 'text'],
  ['王小明', 'image'],
];
for (const [name, how] of NAMES) {
  test(`the name "${name}" signs, and is in the PDF as ${how}`, async () => {
    const page = await newPage(browser);
    await readyOnePage(page, { pages: [{ size: A4 }, { size: A4 }] });
    await page.locator('#ds-allpages').check();
    await clickPage(page, 0, 0.5, 0.8);
    const res = await signAndDownload(page, { name });
    assert.equal(res.error, undefined, `signing as ${name} failed: ${res.error}`);
    const m = await measurePdf(page, res.pdf, SHOTS ? 1 : 0);
    savePngs(SHOTS, 'naam-' + name.replace(/[^\p{L}]+/gu, '-'), m);
    const text = m[0].texts.map((t) => t.str).join(' ');
    if (how === 'text') {
      assert.ok(text.includes(name), `the seal carries "${name}" as text (got: ${text.slice(0, 200)})`);
      // Embedded whole: pdf-lib's subsetter mangled this font ("Ayşe Yılmaz"
      // drew as "Ayse" while the text layer still read right, seen in a render).
      if (/[ışłŁżŻĲễăć]/.test(name)) {
        // The size of every embedded TrueType program: the whole Noto Sans is
        // about 100 KB even compressed, a subset of a few letters a few KB.
        const programs = await page.evaluate(async (b64) => {
          const { PDFDocument, PDFName, PDFDict } = window.PDFLib;
          const doc = await PDFDocument.load(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
          const out = [];
          for (const [, obj] of doc.context.enumerateIndirectObjects()) {
            if (!(obj instanceof PDFDict) || String(obj.get(PDFName.of('Type'))) !== '/FontDescriptor') continue;
            const ref = obj.get(PDFName.of('FontFile2'));
            const st = ref && doc.context.lookup(ref);
            if (st) out.push({ name: String(obj.get(PDFName.of('FontName'))), bytes: st.getContents().length });
          }
          return out;
        }, res.pdf.toString('base64'));
        const noto = programs.find((f) => /NotoSans/.test(f.name));
        assert.ok(noto, `Noto Sans is embedded (${JSON.stringify(programs)})`);
        assert.ok(noto.bytes > 50000, `Noto Sans must be embedded whole, not subset (${noto.bytes} bytes)`);
      }
    } else {
      assert.ok(!text.includes(name), 'drawn as an image, not as text');
      assert.ok(m[0].navy, 'the seal is there');
    }
    assert.ok(m[1].navy, 'the paraaf on page 2 is there');
    await page.context().close();
  });
}

test('typed text with ş and Ł in the edit layer is baked as text', async () => {
  const page = await newPage(browser);
  await readyOnePage(page);
  await clickPage(page, 0, 0.5, 0.8);
  await page.click('#ds-add-text');
  await clickPage(page, 0, 0.2, 0.3);
  await page.keyboard.press('Control+A');
  await page.keyboard.type('Şükrü Łoś');
  await page.keyboard.press('Enter');
  const res = await signAndDownload(page);
  assert.equal(res.error, undefined, res.error);
  const m = await measurePdf(page, res.pdf);
  assert.ok(m[0].texts.some((t) => t.str.includes('Şükrü Łoś')), 'the typed text is in the PDF');
  await page.context().close();
});

// ── 4/7. locked PDFs are said to be locked, at the door ────────────────────
for (const [file, re] of [
  ['encrypted-owneronly.pdf', /beveiligd: de maker heeft wijzigen geblokkeerd/],
  ['encrypted-userpw.pdf', /beveiligd met een wachtwoord/],
]) {
  test(`${file}: told at once, honestly, and signable by hash`, async () => {
    const page = await newPage(browser);
    await openSign(page, origin);
    await page.setInputFiles('#ds-doc-input', path.join(HERE, 'fixtures', 'sign', file));
    await page.locator('#step-hash-only:not([hidden])').waitFor({ timeout: 30000 });
    const note = await page.locator('#ds-hash-only-note').textContent();
    assert.match(note, re);
    assert.doesNotMatch(note, /beschadigd|corrupt/i);
    assert.equal(await page.locator('#ds-hash-only-continue').isDisabled(), false, 'the hash route stays open');
    await page.context().close();
  });
}

// ── 5. a bake failure is not a passkey failure ─────────────────────────────
function tmpFile(name, bytes) {
  const f = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'sig-')), name);
  fs.writeFileSync(f, bytes);
  return f;
}
// A real 1x1 PNG.
const PNG_1PX = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==', 'base64');

async function toIdentityWithImage(page, file) {
  await page.locator('#ds-place-continue').click();
  await page.locator('#step-identity:not([hidden])').waitFor({ timeout: 20000 });
  await page.locator('#ds-signer-name').fill('Sandeep Test');
  await page.locator('#ds-signer-name').dispatchEvent('input');
  await page.click('#ds-tab-image');
  await page.setInputFiles('#ds-sig-image-input', file);
  await page.waitForTimeout(300);
  await page.locator('#ds-identity-continue').click();
  await page.locator('#step-sign:not([hidden])').waitFor({ timeout: 20000 });
}

test('a PNG named .jpg is read by its bytes and signs', async () => {
  const page = await newPage(browser);
  await readyOnePage(page);
  await clickPage(page, 0, 0.5, 0.8);
  await toIdentityWithImage(page, { name: 'handtekening.jpg', mimeType: 'image/jpeg', buffer: PNG_1PX });
  const res = await signNow(page);
  assert.equal(res.error, undefined, res.error);
  await page.context().close();
});

test('a broken signature image gets its own message, not the passkey one', async () => {
  const page = await newPage(browser);
  await readyOnePage(page);
  await clickPage(page, 0, 0.5, 0.8);
  // PNG magic, then garbage: passes the upload check, cannot be embedded.
  const broken = Buffer.concat([PNG_1PX.subarray(0, 16), Buffer.alloc(64, 7)]);
  await toIdentityWithImage(page, { name: 'kapot.png', mimeType: 'image/png', buffer: broken });
  const res = await signNow(page);
  assert.ok(res.error, 'signing must fail on a broken image');
  assert.match(res.error, /handtekeningafbeelding kon niet in de pdf/);
  assert.match(res.error, /Er is niets ondertekend/);
  assert.doesNotMatch(res.error, PASSKEY_TEXT);
  await page.context().close();
});

test('a file that is not an image is refused at upload', async () => {
  const page = await newPage(browser);
  await readyOnePage(page);
  await clickPage(page, 0, 0.5, 0.8);
  await page.locator('#ds-place-continue').click();
  await page.locator('#step-identity:not([hidden])').waitFor({ timeout: 20000 });
  await page.click('#ds-tab-image');
  const dialog = new Promise((r) => page.once('dialog', async (d) => { const m = d.message(); await d.dismiss(); r(m); }));
  await page.setInputFiles('#ds-sig-image-input', { name: 'sig.png', mimeType: 'image/png', buffer: Buffer.from('GIF89a not really an image') });
  assert.match(await dialog, /geen PNG- of JPG-afbeelding/);
  await page.context().close();
});

test('403 signer_not_enrolled: said as it is, and one button links a key and signs', async () => {
  let calls = 0;
  const page = await newPage(browser, { overrides: {
    activation: (r, j) => (++calls === 1)
      ? j(r, { error: 'signer_not_enrolled' }, 403)
      : j(r, { activation_id: 'act_demo_0002', email_hash: 'b'.repeat(64), recipe_version: 4 }),
  } });
  await readyOnePage(page);
  await clickPage(page, 0, 0.5, 0.8);
  const res = await signAndDownload(page);
  assert.ok(res.error, 'the first attempt is refused');
  assert.match(res.error, /niet aan uw account gekoppeld/);
  assert.doesNotMatch(res.error, /al gebruikt of verlopen/);
  assert.doesNotMatch(res.error, PASSKEY_TEXT);
  await page.click('#ds-relink-key');
  await page.locator('#ds-pass-panel:not([hidden]), #step-done:not([hidden])').first().waitFor({ timeout: 60000 });
  if (await page.locator('#ds-pass-panel:not([hidden])').count()) {
    await page.locator('#ds-pass-input').fill('123456');
    await page.locator('#ds-pass-confirm').click();
  }
  await page.locator('#step-done:not([hidden])').waitFor({ timeout: 60000 });
  assert.equal(calls, 2);
  await page.context().close();
});

test('429: a plain sentence with the wait the server gave, never http_429', async () => {
  const page = await newPage(browser, { overrides: {
    activation: (r, j) => j(r, { error: 'rate_limited', retry_after_s: 120 }, 429),
  } });
  await readyOnePage(page);
  await clickPage(page, 0, 0.5, 0.8);
  const res = await signAndDownload(page);
  assert.ok(res.error);
  assert.match(res.error, /Even te veel tegelijk\. Probeer het over 2 minuten opnieuw\./);
  assert.doesNotMatch(res.error, /http_|429|passkey/i);
  await page.context().close();
});

test('429 from a proxy without a body: try again in a minute', async () => {
  const page = await newPage(browser, { overrides: {
    activation: (r) => r.fulfill({ status: 429, contentType: 'text/html', body: '<html>429 Too Many Requests</html>' }),
  } });
  await readyOnePage(page);
  await clickPage(page, 0, 0.5, 0.8);
  const res = await signAndDownload(page);
  assert.match(res.error, /Probeer het over een minuut opnieuw/);
  assert.doesNotMatch(res.error, /http_/);
  await page.context().close();
});

test("402 sender_sign_quota_reached: the sender's allowance, no upgrade pitch", async () => {
  const page = await newPage(browser, { overrides: {
    activation: (r, j) => j(r, { error: 'sender_sign_quota_reached', billed_to: 'sender', dimension: 'signs_month', plan: 'free', limit: 2 }, 402),
  } });
  await readyOnePage(page);
  await clickPage(page, 0, 0.5, 0.8);
  const res = await signAndDownload(page);
  assert.match(res.error, /Het tegoed van de afzender voor deze maand is op; de afzender is op de hoogte\./);
  assert.equal(await page.locator('#ds-sign-status a').count(), 0, 'no upgrade link');
  await page.context().close();
});

test('an unexpected error is not blamed on the passkey', async () => {
  const page = await newPage(browser, { overrides: {
    // A response the page cannot read: a script error after the code, not a WebAuthn one.
    activation: (r) => r.fulfill({ status: 200, contentType: 'application/json', body: 'null' }),
  } });
  await readyOnePage(page);
  await clickPage(page, 0, 0.5, 0.8);
  const res = await signAndDownload(page);
  assert.ok(res.error);
  assert.doesNotMatch(res.error, PASSKEY_TEXT);
  assert.match(res.error, /Er is niets ondertekend/);
  await page.context().close();
});

// ── 6. phone: the first tap after a finger drag counts ─────────────────────
test('phone: after dragging the seal with a finger, the next tap moves it', async () => {
  const page = await newPage(browser, { mobile: true });
  await readyOnePage(page);
  const cdp = await page.context().newCDPSession(page);
  const touch = (type, x, y) => cdp.send('Input.dispatchTouchEvent', { type, touchPoints: type === 'touchEnd' ? [] : [{ x, y }] });
  const canvas = page.locator('.ds-page-wrap[data-page-index="0"] canvas');
  await canvas.scrollIntoViewIfNeeded();
  let c = await canvas.boundingBox();
  await page.touchscreen.tap(c.x + c.width * 0.5, c.y + c.height * 0.3);
  await page.waitForTimeout(300);
  const mb = await page.locator('.ds-stamp-marker').boundingBox();
  const sx = mb.x + mb.width * 0.4, sy = mb.y + mb.height * 0.5;
  await touch('touchStart', sx, sy);
  for (let i = 1; i <= 10; i++) { await touch('touchMove', sx + i * 5, sy + i * 5); await page.waitForTimeout(16); }
  await touch('touchEnd', 0, 0);
  await page.waitForTimeout(300);
  const afterDrag = (await uiBoxes(page)).find((b) => b.kind === 'seal');
  c = await canvas.boundingBox();
  await page.touchscreen.tap(c.x + c.width * 0.5, c.y + c.height * 0.12);
  await page.waitForTimeout(300);
  const afterTap = (await uiBoxes(page)).find((b) => b.kind === 'seal');
  assert.ok(Math.abs(afterTap.y - afterDrag.y) > 0.05, `the first tap after the drag was eaten (y ${afterDrag.y.toFixed(3)} -> ${afterTap.y.toFixed(3)})`);
  await page.context().close();
});

test('desktop: the click that ends a mouse drag still does not re-place the seal', async () => {
  const page = await newPage(browser);
  await readyOnePage(page);
  await clickPage(page, 0, 0.5, 0.3);
  const mb = await page.locator('.ds-stamp-marker').boundingBox();
  const sx = mb.x + mb.width * 0.4, sy = mb.y + mb.height * 0.5;
  await page.mouse.move(sx, sy);
  await page.mouse.down();
  for (let i = 1; i <= 10; i++) await page.mouse.move(sx + i * 6, sy + i * 6);
  await page.mouse.up();
  await page.waitForTimeout(200);
  const after = await page.locator('.ds-stamp-marker').boundingBox();
  // The marker followed the drag (about 60px), it did not jump to centre on the cursor.
  assert.ok(Math.abs(after.x - (mb.x + 60)) < 6 && Math.abs(after.y - (mb.y + 60)) < 6, `seal at ${after.x},${after.y}, expected ${mb.x + 60},${mb.y + 60}`);
  await page.context().close();
});

// ── 7. Back keeps the seal; a template does not switch "every page" on ─────
test('Back from the identity step: the seal is still where it was', async () => {
  const page = await newPage(browser, { mobile: true });
  await readyOnePage(page);
  await page.locator('.ds-page-wrap[data-page-index="0"] canvas').scrollIntoViewIfNeeded();
  const c = await page.locator('.ds-page-wrap[data-page-index="0"] canvas').boundingBox();
  await page.touchscreen.tap(c.x + c.width * 0.5, c.y + c.height * 0.4);
  await page.waitForTimeout(300);
  const before = (await uiBoxes(page)).find((b) => b.kind === 'seal');
  await page.locator('#ds-place-continue').click();
  await page.locator('#step-identity:not([hidden])').waitFor();
  await page.locator('#ds-signer-name').fill('Sandeep Test');
  await page.locator('#ds-signer-name').dispatchEvent('input');
  await page.click('#ds-tab-drawn');
  await page.click('#ds-tab-typed');
  await page.locator('#ds-identity-back').click();
  await page.locator('#step-place:not([hidden])').waitFor();
  await page.waitForTimeout(300);
  const back = (await uiBoxes(page)).find((b) => b.kind === 'seal');
  assert.ok(back && back.w > 0.1, 'the seal is visible again');
  for (const k of ['x', 'y', 'w', 'h']) assert.ok(Math.abs(back[k] - before[k]) < 0.005, `seal ${k} ${before[k].toFixed(3)} -> ${back[k].toFixed(3)}`);
  await page.context().close();
});

test('a saved template does not switch "every page" on for the next document', async () => {
  const page = await newPage(browser);
  // Save a template the way a signer does: tick "every page", place the seal.
  await readyOnePage(page, { pages: [{ size: A4 }, { size: A4 }] });
  await page.locator('#ds-allpages').check();
  await clickPage(page, 0, 0.5, 0.5);
  assert.ok(await page.evaluate(() => Object.keys(localStorage).length > 0), 'the template was saved');
  // A new visit, a new document: "every page" stays off until asked for.
  await page.reload();
  await readyOnePage(page, { pages: [{ size: A4 }, { size: A4 }] });
  assert.equal(await page.locator('#ds-allpages').isChecked(), false, '"every page" stays off until the signer asks for it');
  // Using the saved position applies the position only (retest T1-11: it used
  // to switch "every page" back on, on a document that was never asked for it).
  await page.click('#ds-apply-tpl');
  await page.waitForTimeout(300);
  assert.equal(await page.locator('#ds-allpages').isChecked(), false, 'the saved position does not switch "every page" on');
  assert.equal(await page.locator('.ds-paraaf').count(), 0, 'and puts no paraaf anywhere');
  assert.doesNotMatch(await page.locator('#ds-place-hint').textContent(), /paraaf/);
  // And placing by hand on a fresh visit puts no paraaf anywhere.
  await page.reload();
  await readyOnePage(page, { pages: [{ size: A4 }, { size: A4 }] });
  await clickPage(page, 0, 0.5, 0.5);
  await page.waitForTimeout(300);
  assert.equal(await page.locator('.ds-paraaf').count(), 0, 'no paraaf appears unasked');
  await page.context().close();
});

// ── 8. a paying customer sees his plan ─────────────────────────────────────
for (const [label, me, re] of [
  ['Firm (pro)', { plan: 'community', plan_parasign: 'pro', paid_until_parasign: '2099-01-01T00:00:00Z' }, /Uw plan: Firm/],
  ['expired pro', { plan: 'community', plan_parasign: 'pro', paid_until_parasign: '2001-01-01T00:00:00Z' }, /Altijd gratis/],
  ['community', { plan: 'community', plan_parasign: null }, /Altijd gratis/],
]) {
  test(`the plan line for a ${label} account`, async () => {
    const page = await newPage(browser, { overrides: { me: (r, j) => j(r, { email: 'demo@example.com', ...me }) } });
    await openSign(page, origin);
    await page.waitForTimeout(800);
    const t = await page.locator('#ds-plan-fact').textContent();
    assert.match(t, re);
    if (/Firm/.test(t)) assert.doesNotMatch(t, /gratis|2 handtekeningen/);
    await page.context().close();
  });
}
