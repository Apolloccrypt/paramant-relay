// Real Chromium coverage for "Je documenten", the one signed-in screen
// (/dashboard), and for /account, which tells the same plan story.

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
  if (pathname === '/en/dashboard') pathname = '/en/dashboard.html';
  if (pathname === '/en/account') pathname = '/en/account.html';
  if (pathname === '/api/user/sends' || pathname === '/api/user/opvragen') { res.writeHead(404); return res.end(); }
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

// /dashboard and /account are Dutch since 23 September 2026. The English copies
// under /en/ load the same scripts, so this suite walks the whole flow there,
// and the Dutch page is checked at the end.
await page.route('**/api/user/sends', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"ok":true,"sends":[]}' }));
await page.route('**/api/user/opvragen', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"requests":[]}' }));
await page.goto(ORIGIN + '/en/dashboard', { waitUntil:'networkidle' });
await page.locator('#dh-root:not([hidden])').waitFor();
await page.waitForFunction(() => document.querySelectorAll('#pa-open .dh-document').length === 2);
const mainText = await page.locator('main').innerText();
// The screen leads with what it is, and the two tabs that sort the work. The
// three ways to start something sit behind one button (Nieuw) on a computer
// and in the bar at the bottom on a phone.
ok('the screen leads with its name and the two tabs', /Your documents\./.test(mainText) && await page.locator('#pa-seg').isVisible(), mainText.slice(0, 220));
const starts = await page.locator('#pa-menu a').evaluateAll((as) => as.map((a) => a.getAttribute('href')));
ok('Nieuw holds the three ways to start, into the intended workflow', JSON.stringify(starts) === JSON.stringify(['/en/sign?mode=invite', '/en/parashare', '/en/opvragen']), JSON.stringify(starts));
const bar = await page.locator('.pa-tabbar a').evaluateAll((as) => as.map((a) => a.getAttribute('href')));
ok('the phone bar is Documents, Send, Sign, Requests', JSON.stringify(bar) === JSON.stringify(['/en/dashboard', '/en/parashare', '/en/sign', '/en/opvragen']) && await page.locator('.pa-tabbar').isVisible(), JSON.stringify(bar));
const openText = await page.locator('#pa-open').innerText();
ok('Open shows the waiting and in-progress documents, each with how far it is', await page.locator('#pa-open .dh-document').count() === 2 && /Lease agreement\.pdf/.test(openText) && /0 of 2/.test(openText) && /Service order\.pdf/.test(openText) && /1 of 3/.test(openText), openText);
// Two waiting on the reader (the inbox) and two of the account's own: Open is 4.
ok('one count: the tabs say the number of cards under them', await page.locator('[data-doc-count="open"]').innerText() === '4' && await page.locator('[data-doc-count="klaar"]').innerText() === '2' && await page.locator('#pa-open .pa-card').count() === 4, await page.locator('#pa-seg').innerText());
// One read of the overview per page load is the 80% usage band every account
// gets (eindmatrix DASH-27-N); what must not come back is the five-second
// polling operations panel (DASH-27-A), so more than one request fails.
ok('normal dashboard no longer loads developer operations', overviewRequests <= 1 && !/API keys|More tools|Operations/.test(mainText), overviewRequests);
await page.locator('#pa-open .dh-document [data-pa-action="document-open"]').first().click();
ok('open document has actionable owner controls', await page.locator('#dh-document-dialog').isVisible() && await page.locator('[data-pa-action="document-cancel"]').isVisible() && /not recoverable from the relay dashboard/i.test(await page.locator('#dh-document-dialog-body').innerText()), await page.locator('#dh-document-dialog-body').innerText());
// 1. The reference: the full value, never sliced, so a customer can read it out to support.
const reference = await page.locator('#dh-document-dialog-body').evaluate((node) => {
  const dd = [...node.querySelectorAll('dt')].find((dt) => /Reference/.test(dt.textContent));
  const v = dd && dd.nextElementSibling;
  return v ? { text: v.textContent.trim(), clipped: v.scrollWidth > v.clientWidth + 1 } : null;
});
ok('the document reference is shown whole', reference && reference.text === 'env_waiting_abcdefghijklmnop' && !reference.clipped, JSON.stringify(reference));
page.once('dialog', (dialog) => dialog.accept());
await page.locator('[data-pa-action="document-cancel"]').click();
await page.waitForFunction(() => document.querySelector('#dh-document-dialog-body')?.textContent.includes('closed'));
ok('cancel is owner action and updates measured status', cancelRequests === 1 && /Cancelled/.test(await page.locator('#dh-document-dialog-body').innerText()), await page.locator('#dh-document-dialog-body').innerText());
ok('a withdrawn request leaves Open for Klaar, and the count follows', await page.locator('[data-doc-count="open"]').innerText() === '3' && await page.locator('[data-doc-count="klaar"]').innerText() === '3', await page.locator('#pa-seg').innerText());
await page.locator('[data-pa-action="document-close"]').click();
if (process.env.PARAMANT_DASHBOARD_SCREENSHOT_PATH) await stableScreenshot(page, { path:process.env.PARAMANT_DASHBOARD_SCREENSHOT_PATH, fullPage:true });

await page.locator('#pa-tab-klaar').click();
const klaarText = await page.locator('#pa-klaar').innerText();
ok('Klaar shows the finished work and not the open work', /Completed contract\.pdf/.test(klaarText) && !/Service order/.test(klaarText), klaarText);
ok('a finished document offers its proof straight from the list', await page.locator('#pa-klaar a.pa-dl[download]').first().getAttribute('href') === '/api/user/documents/env_complete_abcdefghijklmnop/receipt', '');
await page.locator('#pa-klaar .dh-document[data-document-id="env_complete_abcdefghijklmnop"] .pa-open').click();
const completedDialogMetrics = await page.locator('#dh-document-dialog').evaluate((node) => {
  const card = node.querySelector('.pa-dialog-card');
  const box = card.getBoundingClientRect();
  return { hidden:node.hidden, top:box.top, left:box.left, bottom:box.bottom, right:box.right, innerWidth, innerHeight };
});
const completedDialogInViewport = !completedDialogMetrics.hidden && completedDialogMetrics.top >= -5 && completedDialogMetrics.left >= -5 && completedDialogMetrics.bottom <= completedDialogMetrics.innerHeight + 5 && completedDialogMetrics.right <= completedDialogMetrics.innerWidth + 5;
ok('completed document exposes proof export with honest storage guidance', completedDialogInViewport && await page.locator('#dh-document-dialog a[download]').getAttribute('href') === '/api/user/documents/env_complete_abcdefghijklmnop/receipt' && /not a plaintext copy/i.test(await page.locator('#dh-document-dialog-body').innerText()), JSON.stringify(completedDialogMetrics));
if (process.env.PARAMANT_DASHBOARD_DETAIL_SCREENSHOT_PATH) {
  await page.waitForTimeout(100);
  await stableScreenshot(page.locator('#dh-document-dialog'), { path:process.env.PARAMANT_DASHBOARD_DETAIL_SCREENSHOT_PATH });
}
await page.locator('[data-pa-action="document-close"]').click();
ok('filenames are rendered as text', await page.locator('#pa-klaar img').count() === 0 && await page.evaluate(() => !window.dashboardInjected) && /<img src=x/.test(await page.locator('#pa-klaar').innerText()), await page.locator('#pa-klaar').innerText());
ok('phone viewport has no horizontal overflow', await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth) <= 1, await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth));
ok('document status is fetched once on load', documentRequests === 1, documentRequests);

// 2. Tap targets. The house minimum is 44, reached with padding: the type
// keeps its size (koper review at 390px).
await page.locator('#pa-tab-open').click();
const taps = await page.evaluate(() => {
  const all = (sel) => [...document.querySelectorAll(sel)].filter((el) => el.offsetParent !== null).map((el) => Math.round(el.getBoundingClientRect().height));
  return {
    tabs: Math.min(...all('#pa-seg button')),
    cardButtons: Math.min(...all('#pa-open .pa-btn')),
    cardLinks: Math.min(...all('#pa-open .pa-links button')),
    bar: Math.min(...all('.pa-tabbar a')),
    resend: Math.min(...all('.dh-inbox-act')),
  };
});
ok('every control on the phone screen is at least a 44px tap target', Object.values(taps).every((height) => height >= 44), JSON.stringify(taps));

// 2b. Waiting for your signature: work the reader owes, first on the list.
const inbox = await page.evaluate(() => {
  const rows = [...document.querySelectorAll('.dh-inbox-row')];
  const firstOwn = document.querySelector('#pa-open .dh-document');
  return {
    rows: rows.map((r) => r.innerText.replace(/\s+/g, ' ').trim()),
    acts: rows.map((r) => (r.querySelector('.dh-inbox-act') || {}).textContent.trim()),
    // A card here is not a way in: this page holds no way to open somebody
    // else's document, and a link would say it does.
    openers: rows.filter((r) => r.querySelector('a, button.pa-ch')).length,
    injected: !window.inboxInjected,
    beforeOwn: rows.length > 0 && !!(rows[rows.length - 1].compareDocumentPosition(firstOwn) & Node.DOCUMENT_POSITION_FOLLOWING),
  };
});
ok('the inbox is fetched once and drawn above the account own requests', inboxRequests === 1 && inbox.beforeOwn, `${inboxRequests} requests, ${inbox.beforeOwn}`);
ok('each waiting document names its sender and both of its dates',
  inbox.rows.length === 2
  && inbox.rows.some((r) => r.includes('Shareholder agreement.pdf') && r.includes('From notary@example.com') && r.includes('sent 20 July 2026') && r.includes('signing closes 27 July 2026')), JSON.stringify(inbox.rows));
ok('a file name chosen by somebody else reaches the screen as text, never as markup',
  inbox.injected && inbox.rows.some((r) => r.includes('<img src=x')), JSON.stringify(inbox.rows));
ok('the inbox offers the one thing it can do and pretends no way in',
  inbox.openers === 0 && inbox.acts.every((t) => t === 'Send me the link again'), JSON.stringify(inbox.acts));

await page.locator('.dh-inbox-act').first().click();
await page.waitForFunction(() => /Asked the sender/.test(document.querySelector('.dh-inbox-act').textContent));
// COSIGN-46-A (2026-10-05): only the sender's browser holds the link that
// opens the document, so the sender is asked to send the invitation again.
ok('send me the link again asks once and says the sender was asked',
  resendRequests === 1 && (await page.locator('.dh-inbox-act').first().textContent()).trim() === 'Asked the sender'
  && /We have asked the sender to send you the invitation again/.test(await page.locator('.dh-inbox-note').first().textContent()),
  `${resendRequests} requests :: ${await page.locator('.dh-inbox-act').first().textContent()}`);

await page.setViewportSize({ width:1280, height:900 });
ok('desktop: one button Nieuw, no bottom bar, no overflow', await page.locator('#pa-new').isVisible() && !(await page.locator('.pa-tabbar').isVisible())
  && await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth <= 1), '');
await page.locator('#pa-new').click();
ok('Nieuw opens its menu and says so', await page.locator('#pa-menu').isVisible() && await page.locator('#pa-new').getAttribute('aria-expanded') === 'true', '');

// ── The plan, driven end to end ──────────────────────────────────────────────
// admin/test/user-plan-fields.test.js proves the FIELDS are on the wire; this
// drives the real page with /api/user/me stubbed, one account state at a time.
// The screen no longer carries a plan badge or a Community band: a free
// account with nothing yet reads "You are on Community." under its first step,
// a paying one reads what it bought one fold down ("Your plan: Firm").
//   parasign pro, valid  a paying customer must never be told he is free
//   parasign pro, lapsed above the floor is paid only while the period runs
//   licensed             normalisePlan folds it to enterprise
const planPage = await browser.newPage({ viewport:{ width:390, height:844 } });
await planPage.route('**/api/user/**', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{}' }));
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
  await planPage.goto(ORIGIN + '/en/dashboard', { waitUntil:'domcontentloaded' });
  await planPage.locator('#dh-root:not([hidden])').waitFor();
  await planPage.locator('#pa-empty:not([hidden])').waitFor();
  const paid = await planPage.locator('#dh-plan-paid').isVisible();
  return {
    badge: paid ? (await planPage.locator('#dh-plan-paid [data-dh="paid-name"]').textContent()).trim()
      : (/You are on Community\./.test(await planPage.locator('#pa-plan').textContent()) ? 'Community' : '?'),
    band: await planPage.locator('#pa-plan').isVisible(),
  };
}

const freePlan = await planCase({ plan:'community' });
ok('a Community account is told its plan', freePlan.badge === 'Community' && freePlan.band === true, JSON.stringify(freePlan));

// 3. The empty state: one card, and the action that fills the list.
const emptyCta = planPage.locator('#pa-empty a.pa-btn').first();
const emptyCtaBox = await emptyCta.boundingBox();
ok('the empty screen offers the action that fills it',
  /Your documents will show up here/.test(await planPage.locator('#pa-empty h2').innerText()) &&
  (await emptyCta.getAttribute('href')).startsWith('/en/sign') &&
  emptyCtaBox.height >= 44, JSON.stringify({ href: await emptyCta.getAttribute('href'), height: emptyCtaBox && Math.round(emptyCtaBox.height) }));

// The stored tier is 'pro' and the name is Firm; what is under test is the
// GATE (PRODUCT_LADDER, the tier keys), and band === false is the half that
// would go red if a paying account were ever told it is free.
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
  await acctPage.goto(ORIGIN + '/en/account', { waitUntil:'domcontentloaded' });
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
// A one-off payment is not a subscription (besluit 05-10-2026): the badge,
// and no cancel button, because nothing would be collected again.
ok('a self-serve customer on a one-off payment gets the badge and no cancel button',
  acctPaid.chip === 'Firm' && acctPaid.current === 'Firm' &&
  acctPaid.active === true && acctPaid.cancel === false &&
  acctPaid.giveBack === false && acctPaid.bought === true, JSON.stringify(acctPaid));
const acctRenews = await acctCase({ plan:'community', plan_parasign:'pro', paid_until_parasign:future, auto_renews:true });
ok('a plan with a collection behind it keeps the cancel button',
  acctRenews.active === true && acctRenews.cancel === true, JSON.stringify(acctRenews));

const acctLapsed = await acctCase({ plan:'community', plan_parasign:'pro', paid_until_parasign:past });
ok('an expired paid period falls back to Community on /account too',
  acctLapsed.chip === 'Community' && acctLapsed.current === 'Community' &&
  acctLapsed.active === false && acctLapsed.cancel === false &&
  acctLapsed.giveBack === true, JSON.stringify(acctLapsed));

// ── The Dutch page, on the same script ───────────────────────────────────────
{
  const nl = await browser.newPage({ viewport:{ width:390, height:844 } });
  await nl.route('**/api/**', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{}' }));
  await nl.route('**/api/user/session/verify', (route) => route.fulfill({ status:200, contentType:'application/json', body:'{"authenticated":true,"email":"demo@example.com"}' }));
  await nl.route('**/api/user/me', (route) => route.fulfill({ status:200, contentType:'application/json', body:JSON.stringify({
    email:'demo@example.com', label:'Demo', plan:'pro', created_at:'2026-06-01T10:00:00.000Z',
    backup_codes_remaining:8, session_expires_at:'2026-07-21T16:00:00.000Z', usage_purpose:'organisation' }) }));
  await nl.route('**/api/user/documents', (route) => route.fulfill({ status:200, contentType:'application/json', body:JSON.stringify({ documents:[
    { id:'env_waiting_abcdefghijklmnop', original_filename:'Lease agreement.pdf', status:'sent', created_at:'2026-07-21T10:00:00.000Z', party_count:2, signed_count:0 },
    { id:'env_progress_abcdefghijklmnop', original_filename:'Service order.pdf', status:'sent', created_at:'2026-07-20T10:00:00.000Z', party_count:3, signed_count:1 },
    { id:'env_void_abcdefghijklmnop', original_filename:'<img src=x onerror=window.dashboardInjected=1>', status:'void', created_at:'2026-07-18T10:00:00.000Z', party_count:1, signed_count:0 },
  ] }) }));
  await nl.goto(ORIGIN + '/dashboard', { waitUntil:'networkidle' });
  await nl.locator('#dh-root:not([hidden])').waitFor();
  await nl.waitForFunction(() => document.querySelectorAll('#pa-open .dh-document').length === 2);
  const nlMain = await nl.locator('main').innerText();
  const nlDocs = await nl.locator('#pa-open').innerText();
  ok('nl: the screen is Dutch', /Je documenten\./.test(nlMain) && /Open \(2\)/.test(nlMain) && /Klaar \(1\)/.test(nlMain), nlMain.slice(0, 200));
  ok('nl: Nieuw leads to the same three starts', JSON.stringify(await nl.locator('#pa-menu a').evaluateAll((as) => as.map((a) => a.getAttribute('href')))) === JSON.stringify(['/sign?mode=invite', '/parashare', '/opvragen']), '');
  ok('nl: the cards say in Dutch where each document stands',
    /0 van 2/.test(nlDocs) && /1 van 3/.test(nlDocs) && /Herinnering sturen/.test(nlDocs) && !/of 2|Send a reminder/.test(nlDocs), nlDocs);
  await nl.locator('#pa-tab-klaar').click();
  ok('nl: filenames are rendered as text here too', await nl.locator('#pa-klaar img').count() === 0
    && await nl.evaluate(() => !window.dashboardInjected) && /Geannuleerd/.test(await nl.locator('#pa-klaar').innerText()), await nl.locator('#pa-klaar').innerText());
  await nl.close();
}

for (const check of checks) console.log(`${check.pass ? 'PASS' : 'FAIL'} ${check.name}${check.detail ? ' :: ' + check.detail : ''}`);
await browser.close();
server.close();
if (checks.some((check) => !check.pass)) process.exit(1);
console.log(`\nuser-dashboard-documents: ${checks.length} checks passed`);
