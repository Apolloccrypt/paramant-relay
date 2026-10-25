// The signed-in overview has to be a workbench, not a menu.
//
// WHAT WENT WRONG
//
// Mick opened paramant.app on his iPhone on 4 September 2026, signed in, and
// got: the band, "Your documents, mickbr.", one paragraph, three buttons, and
// then an empty screen down to the footer. "I see ONLY 3 buttons, as if it
// were a test page." The workbench that followed lived on the homepage, next
// to /dashboard, and the two counted the same request differently.
//
// Since 25 October 2026 there is one screen, "Je documenten" on /dashboard,
// and the homepage sends a signed-in visitor there. This file holds that
// screen to the same three rules the homepage workbench was held to:
//
//   1. THE NUMBERS ARE REAL. The count on each tab is the number of cards
//      under it, from the mocked API, in every state.
//   2. NO STATE IS A HOLE. A new account gets one card with its first step,
//      and a server that is down gets a sentence and a way to try again.
//   3. THE WORDS ARE THE READER'S. No hashes, no envelopes, no endpoints, no
//      plan IDs.
//
// The API is mocked with route interception over a static file server, no
// relay, no Redis. The shapes are copied from the real ones (relay/envelope.js
// listAccountEnvelopes and listPartyEnvelopes, admin/server.js overview).
//
// PARAMANT_HOME_IN_SCREENSHOT_DIR=<dir> writes one screenshot per state into
// that directory. Off by default; the assertions do not need it.
import { chromium } from 'playwright';
import { stableScreenshot } from '../scripts/stable-screenshot.mjs';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'frontend');
const EXE = process.env.PLAYWRIGHT_CHROMIUM_PATH || undefined;
const SHOTS = process.env.PARAMANT_HOME_IN_SCREENSHOT_DIR || '';
const MIME = { '.js':'text/javascript', '.css':'text/css', '.html':'text/html', '.svg':'image/svg+xml', '.png':'image/png', '.woff2':'font/woff2', '.json':'application/json', '.ico':'image/x-icon' };
const aliases = { '/':'/index.html', '/en':'/en/index.html', '/en/':'/en/index.html', '/dashboard':'/dashboard.html', '/en/dashboard':'/en/dashboard.html', '/sign':'/sign.html', '/parashare':'/parashare.html', '/pricing':'/pricing.html' };

const server = http.createServer((req, res) => {
  let pathname = decodeURIComponent(new URL(req.url, 'http://localhost').pathname);
  pathname = aliases[pathname] || pathname;
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

const checks = [];
function okAll(name, condition, detail='') { checks.push({ name, pass:!!condition, detail:String(detail) }); }

// The one notation the site shows a reader, rebuilt here rather than imported,
// so a bug in js/format-date.js cannot make this test agree with it.
// Dutch on / and English on /en, each in its own month names.
const MONTHS_EN = ['January','February','March','April','May','June','July','August','September','October','November','December'];
const MONTHS_NL = ['januari','februari','maart','april','mei','juni','juli','augustus','september','oktober','november','december'];
// Dutch time, like js/format-date.js since acceptatie 3.1.1 ronde 2.
const dayIn = (months) => (v) => {
  const p = Object.fromEntries(new Intl.DateTimeFormat('en-GB', { timeZone: 'Europe/Amsterdam', year: 'numeric', month: 'numeric', day: 'numeric' }).formatToParts(new Date(v)).map((x) => [x.type, x.value]));
  return `${Number(p.day)} ${months[Number(p.month) - 1]} ${p.year}`;
};
const inDays = (n) => new Date(Date.now() + n * 86400000).toISOString();
const agoDays = (n) => new Date(Date.now() - n * 86400000).toISOString();

const OPEN_OLDEST = agoDays(9);
const documentsOpen = { ok:true, count:3, documents:[
  { id:'env_open_one', original_filename:'Engagement letter Bakker.pdf', status:'pending', created_at:OPEN_OLDEST, expires_at:inDays(21), party_count:2, signed_count:0,
    parties:[{ index:0, label:'Anna Bakker', status:'pending' }, { index:1, label:'Joris de Wit', status:'pending' }] },
  { id:'env_open_two', original_filename:'Payroll August 2026.pdf', status:'pending', created_at:agoDays(3), expires_at:inDays(27), party_count:2, signed_count:1,
    parties:[{ index:0, label:'Anna Bakker', status:'signed' }, { index:1, label:'Joris de Wit', status:'pending' }] },
  { id:'env_done_one', original_filename:'Annual accounts 2025.pdf', status:'complete', created_at:agoDays(20), completed_at:agoDays(19), party_count:2, signed_count:2,
    parties:[{ index:0, label:'Anna Bakker', status:'signed' }, { index:1, label:'Joris de Wit', status:'signed' }] },
]};
const documentsDone = { ok:true, count:3, documents:[
  { id:'env_done_a', original_filename:'Annual accounts 2025.pdf', status:'complete', created_at:agoDays(6), completed_at:agoDays(5), party_count:2, signed_count:2,
    parties:[{ index:0, label:'Anna Bakker', status:'signed' }, { index:1, label:'Joris de Wit', status:'signed' }] },
  { id:'env_done_b', original_filename:'Lease Harderwijk.pdf', status:'complete', created_at:agoDays(12), completed_at:agoDays(11), party_count:1, signed_count:1,
    parties:[{ index:0, label:'Anna Bakker', status:'signed' }] },
  { id:'env_void_a', original_filename:'Old quote.pdf', status:'void', created_at:agoDays(30), voided_at:agoDays(29), party_count:2, signed_count:0,
    parties:[{ index:0, label:'Anna Bakker', status:'pending' }, { index:1, label:'Joris de Wit', status:'pending' }] },
]};
const documentsNone = { ok:true, count:0, documents:[] };

// The other side of the worklist: documents somebody else sent to this reader.
// Shape copied from relay/envelope.js listPartyEnvelopes, which deliberately
// carries no invite token and no document hash, so neither appears here either.
const INBOX_FIRST = agoDays(4);
const inboxWaiting = { ok:true, count:2, documents:[
  { id:'AbCdEfGhIjKlMnOpQrStUvWx', document:'Shareholder agreement.pdf', sender:'notary@example.com',
    sent_at:INBOX_FIRST, signing_closes_at:inDays(3), status:'sent', party_count:2, signed_count:1 },
  { id:'ZyXwVuTsRqPoNmLkJiHgFeDc', document:'Supplier terms 2026.pdf', sender:'purchasing@example.com',
    sent_at:agoDays(1), signing_closes_at:inDays(6), status:'sent', party_count:3, signed_count:0 },
]};
const inboxNone = { ok:true, count:0, documents:[] };

// The overview names a tier per product, not one plan word: the caps come from
// the relay's entitlement layer, where ParaSign Pro and ParaSend Community can
// sit on the same account. That is why overviewPro pairs 100 signatures with
// the community transfer ceiling the ParaSign grant leaves alone.
const overviewCommunity = { tiers:{ parasend:'community', parasign:'free' }, quota:{ transfers:1, signs:0, caps:{ transfers:10, signs:2 } }, audit:[] };
const overviewPro       = { tiers:{ parasend:'community', parasign:'pro' }, quota:{ transfers:12, signs:3, caps:{ transfers:10, signs:100 } }, audit:[] };

const PRO_ENDS = inDays(29);
const billingCommunity = { current_plan:'community', plan_parasign:'free', plan_parasend:'community', paid_until_parasign:null, paid_until_parasend:null, auto_renews:false, access_until:null };
const billingPro       = { current_plan:'community', plan_parasign:'pro', plan_parasend:'community', paid_until_parasign:PRO_ENDS, paid_until_parasend:null, auto_renews:false, access_until:PRO_ENDS };

let resendCalls = 0;

async function openDash(at, { documents, overview, billing, inbox = inboxNone, down = false, resend = null }) {
  const page = await browser.newPage({ viewport:{ width:390, height:844 } });
  const json = (payload, status = 200) => (r) => r.fulfill({ status, contentType:'application/json', body:JSON.stringify(payload) });
  await page.route('**/api/user/session/verify', json({ authenticated:true, email:'mickbr@example.com' }));
  await page.route('**/api/user/me', json({ email:'mickbr@example.com', label:'', plan:'community', plan_parasign:billing.plan_parasign, paid_until_parasign:billing.paid_until_parasign,
    created_at:'2026-06-01T10:00:00.000Z', usage_purpose:'organisation' }));
  await page.route('**/api/user/account/signing-key', json({ keys:[{ label:'Signing key' }] }));
  await page.route('**/api/user/account/webauthn/credentials', json({ passkeys:[{ label:'Passkey' }] }));
  const answer = (payload) => (down ? json({ error:'unavailable' }, 500) : json(payload));
  if (resend) {
    await page.route('**/api/user/parasign/inbox/*/resend', (r) => {
      resendCalls++;
      return r.fulfill({ status:resend.status, contentType:'application/json', body:JSON.stringify(resend.body) });
    });
  }
  await page.route('**/api/user/parasign/inbox', answer(inbox));
  await page.route('**/api/user/documents', answer(documents));
  await page.route('**/api/user/sends', answer({ ok:true, sends:[] }));
  await page.route('**/api/user/opvragen', answer({ requests:[] }));
  await page.route('**/api/user/dashboard/overview', json(overview));
  await page.route('**/api/user/billing/status', json(billing));
  await page.goto(ORIGIN + at, { waitUntil:'domcontentloaded' });
  await page.locator('#dh-root:not([hidden])').waitFor();
  await page.waitForFunction(() => {
    const o = document.getElementById('pa-open'), e = document.getElementById('pa-empty');
    return (o && o.innerHTML.trim()) || (e && !e.hidden);
  });
  await page.waitForTimeout(150);
  return page;
}

async function measure(page) {
  return page.evaluate(() => {
    const vis = (el) => el && !el.hidden && getComputedStyle(el).display !== 'none';
    const tx = (el) => (el ? el.innerText.replace(/\s+/g, ' ').trim() : '');
    return {
      open: (document.querySelector('[data-doc-count="open"]') || {}).textContent,
      klaar: (document.querySelector('[data-doc-count="klaar"]') || {}).textContent,
      openCards: Array.from(document.querySelectorAll('#pa-open .pa-card')).map(tx),
      klaarRows: Array.from(document.querySelectorAll('#pa-klaar .pa-mini')).map(tx),
      inboxActs: Array.from(document.querySelectorAll('#pa-open [data-pa-action="inbox-resend"]')).map((b) => b.textContent.trim()),
      actHeight: (() => { const b = document.querySelector('[data-pa-action="inbox-resend"]'); return b ? Math.round(b.getBoundingClientRect().height) : 0; })(),
      empty: vis(document.getElementById('pa-empty')),
      emptyLink: (document.querySelector('#pa-empty a.pa-btn') || {}).getAttribute ? document.querySelector('#pa-empty a.pa-btn').getAttribute('href') : '',
      plan: vis(document.getElementById('pa-plan')) ? tx(document.getElementById('pa-plan')) : '',
      seg: vis(document.getElementById('pa-seg')),
      text: document.querySelector('main').innerText,
    };
  });
}

const JARGON = /\benvelope|env_|pgp_|pst_|sha3|ml-dsa|ml-kem|merkle|recipe_version|api key|endpoint|payload|http \d|\bjson\b|redis|quota\b|caps\b|parasign_|paid_until|current_plan/i;

const states = [
  { key:'open',   title:'open requests',        args:{ documents:documentsOpen, overview:overviewCommunity, billing:billingCommunity } },
  { key:'recent', title:'finished documents only', args:{ documents:documentsDone, overview:overviewPro, billing:billingPro } },
  { key:'empty',  title:'a new account',        args:{ documents:documentsNone, overview:overviewCommunity, billing:billingCommunity } },
  { key:'down',   title:'every list down',      args:{ documents:documentsOpen, overview:overviewCommunity, billing:billingCommunity, down:true } },
  { key:'inbox',  title:'documents waiting for you', args:{ documents:documentsOpen, overview:overviewCommunity, billing:billingCommunity, inbox:inboxWaiting } },
];

const LANGS = [
  { key:'en', at:'/en/dashboard', day:dayIn(MONTHS_EN), zeroOf2:'0 of 2', oneOf2:'1 of 2', stillSign:'still has to sign',
    signedOn:'Signed on ', cancelled:'Cancelled', nothingYet:/Your documents will show up here/, firstStep:'/en/sign?mode=invite',
    planFree:'You are on Community. 2 signatures and 10 transfers a month. Need more?', notLoading:/could not load .* just now\. Nothing has changed/,
    from:'From notary@example.com', closes:'signing closes ', resendLabel:'Send me the link again', waitingYou:'Waiting for you',
    inviteNote:/personal link in the invitation/, asked:/Asked the sender/, capped:/again in an hour/ },
  { key:'nl', at:'/dashboard', day:dayIn(MONTHS_NL), zeroOf2:'0 van 2', oneOf2:'1 van 2', stillSign:'moet nog tekenen',
    signedOn:'Getekend op ', cancelled:'Geannuleerd', nothingYet:/Hier komen je documenten/, firstStep:'/sign?mode=invite',
    planFree:'Je zit op Community. 2 handtekeningen en 10 verzendingen per maand. Meer nodig?', notLoading:/konden .* nu niet laden\. Er is niets veranderd/,
    from:'Van notary@example.com', closes:'tekenen kan tot ', resendLabel:'Stuur mij de link opnieuw', waitingYou:'Wacht op jou',
    inviteNote:/persoonlijke link in de uitnodiging/, asked:/Gevraagd aan de afzender/, capped:/over een uur opnieuw/ },
];

for (const L of LANGS) {
const day = L.day;
const ok = (name, condition, detail='') => okAll(`[${L.key}] ${name}`, condition, detail);
const seen = {};
for (const state of states) {
  const page = await openDash(L.at, state.args);
  // Klaar is read from the tab itself; the open cards stay in the DOM.
  if (state.key === 'open' || state.key === 'recent') await page.locator('#pa-tab-klaar').click();
  const m = await measure(page);
  seen[state.key] = m;
  if (SHOTS) {
    fs.mkdirSync(SHOTS, { recursive:true });
    await stableScreenshot(page, { path:path.join(SHOTS, `documenten-${L.key}-${state.key}-390.png`), fullPage:true });
  }
  ok(`${state.title}: the words are the reader's, not the relay's`, !JARGON.test(m.text), (m.text.match(JARGON) || [''])[0]);
  ok(`${state.title}: the screen is never a hole`, m.openCards.length + m.klaarRows.length > 0 || m.empty || L.notLoading.test(m.text), JSON.stringify(m));
  await page.close();
}

// 1. Open requests: two open, one done; the tab says the number of cards.
ok('open requests: Open counts the open requests in the API, one card each', seen.open.open === '2' && seen.open.openCards.length === 2, `${seen.open.open} ${seen.open.openCards.length}`);
ok('open requests: each card says how far it is and who still has to sign', seen.open.openCards.some((c) => c.includes('Engagement letter Bakker.pdf') && c.includes(L.zeroOf2) && c.includes(L.stillSign))
  && seen.open.openCards.some((c) => c.includes('Payroll August 2026.pdf') && c.includes(L.oneOf2) && c.includes(day(agoDays(3)))), JSON.stringify(seen.open.openCards));
ok('open requests: Klaar holds the finished one, dated', seen.open.klaar === '1' && seen.open.klaarRows.length === 1
  && seen.open.klaarRows[0].includes('Annual accounts 2025.pdf') && seen.open.klaarRows[0].includes(L.signedOn + day(agoDays(19))), JSON.stringify(seen.open.klaarRows));
ok('open requests: no document is printed twice on one screen', !seen.open.openCards.some((c) => c.includes('Annual accounts 2025.pdf')), '');
ok('open requests: no plan line while there is nothing to do with the plan', seen.open.plan === '', seen.open.plan);

// 2. Finished only.
ok('finished only: Open is 0 and Klaar lists all three', seen.recent.open === '0' && seen.recent.klaar === '3' && seen.recent.klaarRows.length === 3, JSON.stringify(seen.recent.klaarRows));
ok('finished only: a withdrawn request says so', seen.recent.klaarRows.some((r) => r.includes('Old quote.pdf') && r.includes(L.cancelled)), JSON.stringify(seen.recent.klaarRows));

// 3. A new account: one card with the first step, and the plan it starts on.
ok('a new account: one card takes the place of the tabs', seen.empty.empty && !seen.empty.seg && L.nothingYet.test(seen.empty.text), '');
ok('a new account: the card offers the first step', seen.empty.emptyLink === L.firstStep, seen.empty.emptyLink);
ok('a new account: the plan line names what Community holds, from the API', seen.empty.plan === L.planFree, seen.empty.plan);

// 4. Every list down: a sentence, a way to try again, no invented empty state.
ok('every list down: the reader gets a sentence, not a status code', L.notLoading.test(seen.down.text) && !/error|failed|500/i.test(seen.down.text), seen.down.text.slice(0, 200));
ok('every list down: it is not shown as an empty account', !seen.down.empty, '');

// 5. Documents waiting for the READER come first, and say what can be done.
ok('waiting for you: they count as open work, before the account own requests', seen.inbox.open === '4' && seen.inbox.openCards[0].includes('Shareholder agreement.pdf') && seen.inbox.openCards[1].includes('Supplier terms 2026.pdf'), JSON.stringify(seen.inbox.openCards.slice(0, 2)));
ok('waiting for you: named by sender and by when signing closes', seen.inbox.openCards[0].includes(L.from) && seen.inbox.openCards[0].includes(L.closes + day(inDays(3))) && seen.inbox.openCards[0].includes(L.waitingYou), seen.inbox.openCards[0]);
ok('waiting for you: every card offers the one thing this page can do', seen.inbox.inboxActs.length === 2 && seen.inbox.inboxActs.every((t) => t === L.resendLabel), JSON.stringify(seen.inbox.inboxActs));
ok('waiting for you: that button is a real tap target on a phone', seen.inbox.actHeight >= 40, `${seen.inbox.actHeight}px`);
ok('waiting for you: the card promises no way in that it does not have', L.inviteNote.test(seen.inbox.openCards[0]), seen.inbox.openCards[0]);

// 6. Pressing the button: one request, and the honest answer. The mail that
// opens the document is built in the sender's browser, so the sender is asked.
resendCalls = 0;
{
  const page = await openDash(L.at, { documents:documentsNone, overview:overviewCommunity, billing:billingCommunity, inbox:inboxWaiting,
    resend:{ status:200, body:{ ok:true } } });
  await page.locator('[data-pa-action="inbox-resend"]').first().click();
  await page.waitForFunction((re) => new RegExp(re).test(document.querySelector('[data-pa-action="inbox-resend"]').textContent), L.asked.source);
  ok('send me the link again: one press, one request, and it says what happened', resendCalls === 1, `${resendCalls} calls`);
  await page.close();
}
{
  resendCalls = 0;
  const page = await openDash(L.at, { documents:documentsNone, overview:overviewCommunity, billing:billingCommunity, inbox:inboxWaiting,
    resend:{ status:429, body:{ error:'rate_limited' } } });
  await page.locator('[data-pa-action="inbox-resend"]').first().click();
  await page.waitForFunction((re) => new RegExp(re).test(document.querySelector('[data-pa-action="inbox-resend"]').textContent), L.capped.source);
  const m = await measure(page);
  ok('send me the link again: a capped resend is a sentence, not a status code', !/429|rate_limited|error/i.test(m.text), (m.text.match(/429|rate_limited|error/i) || [''])[0]);
  await page.close();
}
}

// The homepage itself no longer draws any of this: a signed-in visitor lands here.
{
  const page = await browser.newPage({ viewport:{ width:390, height:844 } });
  // Playwright tries the newest route first, so the catch-all goes on first.
  await page.route('**/api/user/**', (r) => r.fulfill({ status:200, contentType:'application/json', body:'{}' }));
  await page.route('**/api/user/session/verify', (r) => r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify({ authenticated:true }) }));
  await page.goto(ORIGIN + '/en', { waitUntil:'domcontentloaded' });
  await page.waitForURL(/\/en\/dashboard$/, { waitUntil:'commit' });
  okAll('[en] the homepage sends a signed-in visitor to the one overview', true);
  await page.close();
}

await browser.close();
server.close();

const failed = checks.filter((c) => !c.pass);
for (const c of checks) console.log(`${c.pass ? 'ok  ' : 'FAIL'}  ${c.name}${c.detail ? `  -- ${c.detail}` : ''}`);
console.log(`\n${checks.length - failed.length}/${checks.length} passed`);
if (failed.length) process.exit(1);
