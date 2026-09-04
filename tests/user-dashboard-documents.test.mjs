// Real Chromium coverage for the document-focused user dashboard.

import { chromium } from 'playwright';
import { stableScreenshot } from '../scripts/stable-screenshot.mjs';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const MIME = { '.js':'text/javascript','.css':'text/css','.html':'text/html','.svg':'image/svg+xml','.png':'image/png','.woff2':'font/woff2' };
const server = http.createServer((req, res) => {
  let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  if (pathname === '/dashboard') pathname = '/dashboard.html';
  if (pathname === '/account') pathname = '/account.html';
  const file = path.join(ROOT, pathname);
  if (!file.startsWith(ROOT)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (error, body) => {
    if (error) { res.writeHead(404); return res.end(); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' });
    res.end(body);
  });
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const ORIGIN = `http://localhost:${server.address().port}`;
const browser = await chromium.launch({ headless:true, ...(EXE ? { executablePath:EXE } : {}) });
const page = await browser.newPage({ viewport:{ width:390, height:844 } });

let overviewRequests = 0;
let documentRequests = 0;
let cancelRequests = 0;
let inboxRequests = 0;
let resendRequests = 0;
await page.route('**/api/user/session/verify', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
await page.route('**/api/user/me', (route) => route.fulfill({ status:200, contentType:'application/json', body:JSON.stringify({
  email:'demo@example.com', label:'Demo', plan:'pro', created_at:'2026-06-01T10:00:00.000Z',
  backup_codes_remaining:8, session_expires_at:'2026-07-21T16:00:00.000Z', usage_purpose:'organisation'
}) }));
await page.route('**/api/user/dashboard/overview', (route) => { overviewRequests++; return route.fulfill({ status:500, body:'' }); });
await page.route('**/api/user/account/signing-key', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"keys":[{"label":"Signing key"}]}' }));
await page.route('**/api/user/account/webauthn/credentials', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"passkeys":[{"label":"Passkey"}]}' }));
await page.route('**/api/user/documents', (route) => {
  documentRequests++;
  return route.fulfill({ status:200, contentType:'application/json', body:JSON.stringify({ documents:[
    { id:'env_waiting_abcdefghijklmnop', original_filename:'Lease agreement.pdf', status:'sent', created_at:'2026-07-21T10:00:00.000Z', party_count:2, signed_count:0 },
    { id:'env_progress_abcdefghijklmnop', original_filename:'Service order.pdf', status:'sent', created_at:'2026-07-20T10:00:00.000Z', party_count:3, signed_count:1 },
    { id:'env_complete_abcdefghijklmnop', original_filename:'Completed contract.pdf', status:'complete', created_at:'2026-07-19T10:00:00.000Z', party_count:2, signed_count:2 },
    { id:'env_void_abcdefghijklmnop', original_filename:'<img src=x onerror=window.dashboardInjected=1>', status:'void', created_at:'2026-07-18T10:00:00.000Z', party_count:1, signed_count:0 }
  ] }) });
});
await page.route('**/api/user/documents/env_waiting_abcdefghijklmnop/cancel', (route) => {
  cancelRequests++;
  return route.fulfill({ status:200, contentType:'application/json', body:'{"ok":true,"status":"void"}' });
});
// The other side of the worklist: what somebody else sent to this reader. The
// resend stub is registered LAST, because Playwright tries handlers newest
// first and the inbox pattern would otherwise swallow it.
await page.route('**/api/user/parasign/inbox', (route) => {
  inboxRequests++;
  return route.fulfill({ status:200, contentType:'application/json', body:JSON.stringify({ ok:true, count:2, documents:[
    { id:'AbCdEfGhIjKlMnOpQrStUvWx', document:'Shareholder agreement.pdf', sender:'notary@example.com',
      sent_at:'2026-07-20T10:00:00.000Z', signing_closes_at:'2026-07-27T10:00:00.000Z', status:'sent', party_count:2, signed_count:1 },
    // Somebody else chose this file name. It has to reach the screen as text.
    { id:'ZyXwVuTsRqPoNmLkJiHgFeDc', document:'<img src=x onerror=window.inboxInjected=1>', sender:'purchasing@example.com',
      sent_at:'2026-07-19T10:00:00.000Z', signing_closes_at:'2026-07-26T10:00:00.000Z', status:'sent', party_count:3, signed_count:0 }
  ] }) });
});
await page.route('**/api/user/parasign/inbox/*/resend', (route) => {
  resendRequests++;
  return route.fulfill({ status:200, contentType:'application/json', body:'{"ok":true,"sent_to":"demo@example.com"}' });
});

const checks = [];
function ok(name, condition, detail='') { checks.push({ name, pass:!!condition, detail:String(detail) }); }

await page.goto(ORIGIN + '/dashboard', { waitUntil:'networkidle' });
await page.locator('#dh-root:not([hidden])').waitFor();
await page.waitForFunction(() => document.querySelectorAll('.dh-document').length === 2);
const mainText = await page.locator('main').innerText();
// The mission line used to read "Send, sign and prove important documents.
// Private by design." It now names the two products we actually sell, in the
// same words the homepage uses, because a customer who has just signed up
// should be able to map what is on screen onto what he read before signing up.
// "burns on read" left here because the dashboard sends through the web app,
// which does burn on the first read; but the sentence names the PRODUCT, and
// through the API a paid link reads up to ten times. Block 37 of
// site-claims.test.mjs now sweeps this screen too.
ok('mission is the first dashboard promise', /Important documents, under control/.test(mainText) && /ParaSign gets a document signed/.test(mainText) && /ParaSend sends a file that deletes itself after reading/.test(mainText), mainText.slice(0, 220));
ok('dashboard leads with three plain-language actions', await page.locator('.dh-start-card').count() === 3, await page.locator('.dh-start').innerText());
// The order changed on purpose: the two PRODUCTS lead, so ParaSend is second
// and signing alone is third. On a 390px screen the old order put both
// ParaSign modes above the fold and pushed ParaSend out of sight, which made
// the dashboard disagree with a homepage that sells two things.
ok('signing actions enter the intended workflow', await page.locator('.dh-start-card').nth(0).getAttribute('href') === '/sign?mode=invite' && await page.locator('.dh-start-card').nth(1).getAttribute('href') === '/parashare' && await page.locator('.dh-start-card').nth(2).getAttribute('href') === '/sign?mode=alone', await page.locator('.dh-start').innerText());
ok('open filter shows waiting and in-progress documents', await page.locator('.dh-document').count() === 2 && /Waiting for signatures/.test(await page.locator('#dh-documents').innerText()) && /In progress/.test(await page.locator('#dh-documents').innerText()), await page.locator('#dh-documents').innerText());
ok('relay document counts fill every filter', await page.locator('[data-doc-count="open"]').innerText() === '2' && await page.locator('[data-doc-count="completed"]').innerText() === '1' && await page.locator('[data-doc-count="cancelled"]').innerText() === '1' && await page.locator('[data-doc-count="all"]').innerText() === '4', await page.locator('.dh-filters').innerText());
ok('normal dashboard no longer loads developer operations', overviewRequests === 0 && !/API keys|More tools|Operations/.test(mainText), overviewRequests);
await page.locator('.dh-document').first().click();
ok('open document has actionable owner controls', await page.locator('#dh-document-dialog').isVisible() && await page.locator('[data-pa-action="document-cancel"]').isVisible() && /not recoverable from the relay dashboard/i.test(await page.locator('#dh-document-dialog-body').innerText()), await page.locator('#dh-document-dialog-body').innerText());
page.once('dialog', (dialog) => dialog.accept());
await page.locator('[data-pa-action="document-cancel"]').click();
await page.waitForFunction(() => document.querySelector('#dh-document-dialog-body')?.textContent.includes('closed'));
ok('cancel is owner action and updates measured status', cancelRequests === 1 && /Cancelled/.test(await page.locator('#dh-document-dialog-body').innerText()), await page.locator('#dh-document-dialog-body').innerText());
await page.locator('[data-pa-action="document-close"]').click();
if (process.env.PARAMANT_DASHBOARD_SCREENSHOT_PATH) await stableScreenshot(page, { path:process.env.PARAMANT_DASHBOARD_SCREENSHOT_PATH, fullPage:true });

await page.locator('[data-doc-filter="completed"]').click();
ok('completed filter shows only completed work', await page.locator('.dh-document').count() === 1 && /Completed contract/.test(await page.locator('#dh-documents').innerText()), await page.locator('#dh-documents').innerText());
await page.locator('.dh-document').click();
const completedDialogMetrics = await page.locator('#dh-document-dialog').evaluate((node) => {
  const box = node.getBoundingClientRect();
  const style = getComputedStyle(node);
  const panel = node.querySelector('.dh-doc-dialog-panel');
  const panelStyle = panel ? getComputedStyle(panel) : null;
  return { hidden:node.hidden, display:style.display, position:style.position, zIndex:style.zIndex, background:style.backgroundColor, panelDisplay:panelStyle && panelStyle.display, panelBackground:panelStyle && panelStyle.backgroundColor, top:box.top, left:box.left, bottom:box.bottom, right:box.right, width:box.width, height:box.height, innerWidth, innerHeight };
});
const completedDialogInViewport = !completedDialogMetrics.hidden && completedDialogMetrics.top >= -5 && completedDialogMetrics.left >= -5 && completedDialogMetrics.bottom <= completedDialogMetrics.innerHeight + 5 && completedDialogMetrics.right <= completedDialogMetrics.innerWidth + 5;
ok('completed document exposes proof export with honest storage guidance', completedDialogInViewport && await page.locator('a[download]').getAttribute('href') === '/api/user/documents/env_complete_abcdefghijklmnop/receipt' && /not a plaintext copy/i.test(await page.locator('#dh-document-dialog-body').innerText()), JSON.stringify(completedDialogMetrics));
if (process.env.PARAMANT_DASHBOARD_DETAIL_SCREENSHOT_PATH) {
  await page.waitForTimeout(100);
  await stableScreenshot(page.locator('#dh-document-dialog'), { path:process.env.PARAMANT_DASHBOARD_DETAIL_SCREENSHOT_PATH });
}
await page.locator('[data-pa-action="document-close"]').click();
await page.locator('[data-doc-filter="cancelled"]').click();
ok('filenames are rendered as text', await page.locator('.dh-document img').count() === 0 && await page.evaluate(() => !window.dashboardInjected), await page.locator('#dh-documents').innerText());
ok('phone viewport has no horizontal overflow', await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth) <= 1, await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth));
ok('document status is fetched once on load', documentRequests === 1, documentRequests);

// ── What the phone screen actually hands the customer ────────────────────────
// A koper review of the signed-in journey measured this screen at 390px. Three
// findings are pinned here, because all three were invisible to every existing
// assertion: they are geometry and attributes, not text.
// The All filter, because the case above cancelled the first request: Open
// now holds one row and All still holds the four the relay stub returned.
await page.locator('[data-doc-filter="all"]').click();
await page.waitForFunction(() => document.querySelectorAll('.dh-document').length === 4);

// 1. The reference. It used to be sliced to ten characters in dashboard.js, so
// env_waiting_abcdefghijklmnop rendered as "env_waitin": a fragment with
// nothing to say it was one, which is worthless when a customer reads it out
// to support. The full value is in the DOM and in the title; when it does not
// fit, CSS shortens it with an ellipsis rather than a silent cut.
const reference = await page.locator('.dh-doc-ref').first().evaluate((node) => ({
  text: node.textContent.trim(),
  title: node.getAttribute('title'),
  textOverflow: getComputedStyle(node).textOverflow,
  clipped: node.scrollWidth > node.clientWidth + 1,
}));
ok('the document reference is never cut without an ellipsis',
  reference.text.endsWith('Ref env_waiting_abcdefghijklmnop') &&
  reference.title === 'env_waiting_abcdefghijklmnop' &&
  reference.textOverflow === 'ellipsis', JSON.stringify(reference));

// 2. Tap targets. Measured at 390px before this change: filter chips and
// Refresh 36px, the four quiet links 36px, the two text links in a running
// line 19px. The house minimum is 44, and it is reached with padding: the
// type keeps its size.
const taps = await page.evaluate(() => {
  const h = (sel) => { const el = document.querySelector(sel); return el ? Math.round(el.getBoundingClientRect().height) : 0; };
  return {
    filter: h('.dh-filter'),
    refresh: h('#dh-documents-refresh'),
    quiet: h('.dh-quiet-links a'),
    help: h('.dh-ask-foot a'),
    footer: h('footer .footer-links a'),
    // Every link inside an answer, not just the first: "See the plans" sat at
    // the end of its line and measured 19px while its neighbours measured 41.
    faq: Math.min(...[...document.querySelectorAll('.dh-ask-list a')].map((el) => Math.round(el.getBoundingClientRect().height))),
    resend: h('.dh-inbox-act'),
  };
});
ok('every control on the phone screen is at least a 44px tap target',
  Object.values(taps).every((height) => height >= 44), JSON.stringify(taps));

// 2b. Waiting for your signature. The section above "Open documents", and the
// only list on this page about work the reader owes rather than work the reader
// is owed. It was impossible before the party index: the dashboard could show an
// account its outbox and nothing else, and the page said so in the box at the
// bottom of the workspace, which told a reader to go and look in his email.
const inbox = await page.evaluate(() => {
  const rows = [...document.querySelectorAll('.dh-inbox-row')];
  return {
    shown: !document.getElementById('dh-inbox').hidden,
    rows: rows.map((r) => r.innerText.replace(/\s+/g, ' ').trim()),
    acts: rows.map((r) => (r.querySelector('.dh-inbox-act') || {}).textContent),
    // A row is not a button here: this page holds no way to open somebody
    // else's document, and a row that looked clickable would say it does.
    openers: rows.filter((r) => r.matches('button') || r.querySelector('a')).length,
    injected: !window.inboxInjected,
    // The inbox is above the outbox in the document, not merely styled that way.
    beforeOutbox: !!(document.getElementById('dh-inbox').compareDocumentPosition(document.getElementById('dh-documents')) & Node.DOCUMENT_POSITION_FOLLOWING),
  };
});
ok('the inbox is fetched once and drawn above the account own requests',
  inboxRequests === 1 && inbox.shown && inbox.beforeOutbox, `${inboxRequests} requests, ${JSON.stringify([inbox.shown, inbox.beforeOutbox])}`);
ok('each waiting document names its sender and both of its dates',
  inbox.rows.length === 2
  && inbox.rows[0].includes('Shareholder agreement.pdf')
  && inbox.rows[0].includes('From notary@example.com')
  && inbox.rows[0].includes('sent 20 July 2026')
  && inbox.rows[0].includes('signing closes 27 July 2026'), JSON.stringify(inbox.rows));
ok('a file name chosen by somebody else reaches the screen as text, never as markup',
  inbox.injected && inbox.rows[1].includes('<img src=x'), JSON.stringify(inbox.rows[1]));
ok('the inbox offers the one thing it can do and pretends no way in',
  inbox.openers === 0 && inbox.acts.every((t) => t === 'Send me the link again'), JSON.stringify(inbox.acts));

await page.locator('.dh-inbox-act').first().click();
await page.waitForFunction(() => /Sent/.test(document.querySelector('.dh-inbox-act').textContent));
ok('send me the link again asks once and says which address it went to',
  resendRequests === 1 && (await page.locator('.dh-inbox-act').first().textContent()).trim() === 'Sent to demo@example.com',
  `${resendRequests} requests :: ${await page.locator('.dh-inbox-act').first().textContent()}`);

await page.setViewportSize({ width:1280, height:900 });
ok('desktop uses a three-action row without overflow', await page.evaluate(() => getComputedStyle(document.querySelector('.dh-start')).gridTemplateColumns.split(' ').length === 3 && document.documentElement.scrollWidth - document.documentElement.clientWidth <= 1), await page.evaluate(() => getComputedStyle(document.querySelector('.dh-start')).gridTemplateColumns));

// ── The plan badge and the Community band, driven end to end ────────────────
// admin/test/user-plan-fields.test.js proves the FIELDS are on the wire. It is
// a source-inspection test, so it cannot see whether the browser does anything
// with them: paidProductTier() and the #dh-community toggle in dashboard.js
// could both be deleted and every suite stayed green. This drives the real page
// in Chromium with /api/user/me stubbed, one account state at a time.
//
// Why each case matters:
//   community            the give-back band is the whole point of the page
//   parasign pro, valid  a paying customer must never be told he is free
//   parasign pro, lapsed the same rule effectiveProductTier() applies on the
//                        server: above the floor is paid only while the period
//                        runs, so an expired one falls back
//   licensed             normalisePlan folds it to enterprise; before this it
//                        rendered as a raw machine string
const planPage = await browser.newPage({ viewport:{ width:390, height:844 } });
await planPage.route('**/api/user/session/verify', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
await planPage.route('**/api/user/documents**', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"documents":[]}' }));
await planPage.route('**/api/user/dashboard/overview', (route) => route.fulfill({ status:500, body:'' }));
await planPage.route('**/api/user/account/**', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{}' }));

const future = new Date(Date.now() + 30 * 86400000).toISOString();
const past = new Date(Date.now() - 86400000).toISOString();
let planState = {};
await planPage.route('**/api/user/me', (route) => route.fulfill({ status:200, contentType:'application/json', body:JSON.stringify({
  email:'demo@example.com', label:'Demo', created_at:'2026-06-01T10:00:00.000Z',
  backup_codes_remaining:8, session_expires_at:'2026-07-21T16:00:00.000Z', usage_purpose:'organisation',
  plan_parasign:null, plan_parasend:null, paid_until_parasign:null, paid_until_parasend:null,
  ...planState,
}) }));

async function planCase(state) {
  planState = state;
  await planPage.goto(ORIGIN + '/dashboard', { waitUntil:'domcontentloaded' });
  await planPage.locator('#dh-root:not([hidden])').waitFor();
  return {
    // textContent, not innerText: the chip is uppercased in CSS, and what is
    // under test is the word dashboard.js writes, not how it is painted.
    badge: (await planPage.locator('[data-dh="plan-strong"]').textContent()).trim(),
    band: await planPage.locator('#dh-community').isVisible(),
  };
}

const freePlan = await planCase({ plan:'community' });
ok('a Community account sees the give-back band', freePlan.badge === 'Community' && freePlan.band === true, JSON.stringify(freePlan));

// 3. The empty state. This page's document list is stubbed empty, so it is the
// screen a new customer meets. It used to be two sentences and no way out: the
// one action that fills the list now sits in it as a real button.
const emptyCta = await planPage.locator('.dh-empty a').first();
const emptyCtaBox = await emptyCta.boundingBox();
ok('the empty document list offers the action that fills it',
  await planPage.locator('.dh-empty strong').innerText() === 'No open requests' &&
  (await emptyCta.getAttribute('href')).startsWith('/sign') &&
  emptyCtaBox.height >= 44, JSON.stringify({ href: await emptyCta.getAttribute('href'), height: emptyCtaBox && Math.round(emptyCtaBox.height) }));

// The stored tier is 'pro' and the badge says Firm. Those are two different
// things and both are right: 'pro' is the entitlement tier the relay writes
// (relay/lib/entitlements.js PARASIGN_TIERS, unchanged), Firm is the plan that
// grants it since 6 September 2026. What is under test here is the GATE, not
// the word: the decision that this account is paid runs off PRODUCT_LADDER,
// the tier keys, so renaming what is printed cannot move it. band === false is
// the half that would go red if it ever did.
const paidPlan = await planCase({ plan:'community', plan_parasign:'pro', paid_until_parasign:future });
ok('a paid ParaSign tier is never called free', paidPlan.badge === 'Firm' && paidPlan.band === false, JSON.stringify(paidPlan));

const lapsedPlan = await planCase({ plan:'community', plan_parasign:'pro', paid_until_parasign:past });
ok('an expired paid period falls back to Community', lapsedPlan.badge === 'Community' && lapsedPlan.band === true, JSON.stringify(lapsedPlan));

const sendPlan = await planCase({ plan:'community', plan_parasend:'pro', paid_until_parasend:future });
ok('a paid ParaSend tier counts too', sendPlan.badge === 'Firm' && sendPlan.band === false, JSON.stringify(sendPlan));

const licensedPlan = await planCase({ plan:'licensed' });
ok('a licensed account reads as Enterprise, not as a machine string', licensedPlan.badge === 'Enterprise' && licensedPlan.band === false, JSON.stringify(licensedPlan));

// ── /account tells the same story, and gates the same way ────────────────────
// This is the page a customer opens to find out what he pays, so the answer has
// to match the dashboard's. It also carries two affordances the dashboard does
// not: the Active badge and the Cancel button. Those used to be decided by
// `current_plan !== 'community'`, one string, which got it wrong in BOTH
// directions: a free ParaSign account sits on the tier called 'free', so it was
// offered a cancel button for a subscription it does not have, and a self-serve
// customer keeps the unified plan 'community' while only his product tier
// moves, so the person actually paying never saw the badge.
//
// Tested through the rendered page rather than by reading the source for a
// forbidden string, because the next wrong gate will not be spelled the same.
const acctPage = await browser.newPage({ viewport:{ width:390, height:844 } });
let acctState = {};
const acctBody = () => JSON.stringify({
  email:'demo@example.com', api_key_masked:'pgp_****', label:'Demo',
  created_at:'2026-06-01T10:00:00.000Z', backup_codes_remaining:8, sessions:[],
  plan_parasign:null, plan_parasend:null, paid_until_parasign:null, paid_until_parasend:null,
  ...acctState,
});
// Playwright tries handlers newest-first, so the catch-all is registered FIRST
// and the specific stubs land on top of it. The other way round it answers {}
// to everything and every case renders as a signed-out, planless page, which
// makes three of the four assertions below pass for the wrong reason.
await acctPage.route('**/api/user/**', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{}' }));
await acctPage.route('**/api/user/session/verify', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
await acctPage.route('**/api/user/billing/history', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"history":[]}' }));
await acctPage.route('**/api/user/billing/status', (route) => route.fulfill({ status:200, contentType:'application/json', body:JSON.stringify({ current_plan: acctState.plan || 'community', ...JSON.parse(acctBody()) }) }));
await acctPage.route('**/api/user/account', (route) => route.fulfill({ status:200, contentType:'application/json', body:acctBody() }));

async function acctCase(state) {
  acctState = state;
  await acctPage.goto(ORIGIN + '/account', { waitUntil:'domcontentloaded' });
  await acctPage.locator('#billing-content:not(.hidden)').waitFor();
  return {
    chip: (await acctPage.locator('#plan-chip').textContent()).trim(),
    current: (await acctPage.locator('#billing-plan').textContent()).trim(),
    active: await acctPage.locator('#billing-active-badge').isVisible(),
    cancel: await acctPage.locator('#billing-cancel-btn').isVisible(),
    giveBack: await acctPage.locator('#billing-community').isVisible(),
    bought: await acctPage.locator('#billing-paid').isVisible(),
  };
}

const acctFree = await acctCase({ plan:'community' });
ok('a Community account is not offered a cancel button',
  acctFree.chip === 'Community' && acctFree.current === 'Community' &&
  acctFree.active === false && acctFree.cancel === false &&
  acctFree.giveBack === true && acctFree.bought === false, JSON.stringify(acctFree));

// ParaSign's floor tier is the word 'free', not 'community'
// (relay/lib/entitlements.js PARASIGN_TIERS). The old gate read that as paid.
const acctFloor = await acctCase({ plan:'community', plan_parasign:'free' });
ok('the ParaSign floor tier is still free of charge',
  acctFloor.current === 'Community' && acctFloor.cancel === false && acctFloor.giveBack === true, JSON.stringify(acctFloor));

// ParaSend's floor is the word 'community', ParaSign's is 'free', and a tier
// nobody recognises must not be luckier than either. paidProductTier() reads
// the paid rungs rather than listing the floors, so all three come out unpaid.
const acctSendFloor = await acctCase({ plan:'community', plan_parasend:'community' });
ok('the ParaSend floor tier is free of charge as well',
  acctSendFloor.current === 'Community' && acctSendFloor.cancel === false, JSON.stringify(acctSendFloor));

const acctUnknown = await acctCase({ plan:'community', plan_parasign:'platinum', paid_until_parasign:future });
ok('an unrecognised tier fails closed rather than unlocking a subscription',
  acctUnknown.current === 'Community' && acctUnknown.active === false && acctUnknown.cancel === false, JSON.stringify(acctUnknown));

const acctPaid = await acctCase({ plan:'community', plan_parasign:'pro', paid_until_parasign:future });
// Same split as on the dashboard above: the tier on file is 'pro', the plan it
// is sold as is Firm. The four booleans are the point of this check and none of
// them reads a name: active, cancel, giveBack and bought all come off
// paidProductTier(), which walks the tier keys and fails closed on anything it
// does not recognise. A give-back band decided by the plan NAME is exactly the
// bug this line was written for, and it would show up here as giveBack true.
ok('a self-serve customer gets the badge and the cancel button he pays for',
  acctPaid.chip === 'Firm' && acctPaid.current === 'Firm' &&
  acctPaid.active === true && acctPaid.cancel === true &&
  acctPaid.giveBack === false && acctPaid.bought === true, JSON.stringify(acctPaid));

const acctLapsed = await acctCase({ plan:'community', plan_parasign:'pro', paid_until_parasign:past });
ok('an expired paid period falls back to Community on /account too',
  acctLapsed.chip === 'Community' && acctLapsed.current === 'Community' &&
  acctLapsed.active === false && acctLapsed.cancel === false &&
  acctLapsed.giveBack === true, JSON.stringify(acctLapsed));

for (const check of checks) console.log(`${check.pass ? 'PASS' : 'FAIL'} ${check.name}${check.detail ? ' :: ' + check.detail : ''}`);
await browser.close();
server.close();
if (checks.some((check) => !check.pass)) process.exit(1);
console.log(`\nuser-dashboard-documents: ${checks.length} checks passed`);
