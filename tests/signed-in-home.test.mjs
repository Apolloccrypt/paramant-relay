// The signed-in homepage has to be a workbench, not a menu.
//
// WHAT WENT WRONG
//
// Mick opened paramant.app on his iPhone on 4 September 2026, signed in, and
// got: the band, "Your documents, mickbr.", one paragraph, three buttons, and
// then an empty screen down to the footer. His two readings of it, in order:
// "this is overly simple", and then "I see ONLY 3 buttons, as if it were a test
// page. This never passed commerce or marketing."
//
// The yardstick he set is BeerWeer (weer.mickbeer.com): one big reading at the
// top with a small drawn object beside it, then the rest laid out quietly in
// cards. So this file measures the three things that turn the hero back into a
// menu if they slip:
//
//   1. THE FIGURE IS REAL. The number on screen is the number in the mocked
//      API, in all three states. A big number that is decoration rather than
//      data is worse than no number.
//   2. NO STATE IS THREE BUTTONS OVER A HOLE. Including the empty account and
//      the state where every route is down. Measured as the gap between the
//      last thing drawn in <main> and the top of the footer.
//   3. THE WORDS ARE THE READER'S. No hashes, no envelopes, no endpoints, no
//      plan IDs. The buyer review of 5 September scored the signing flow down
//      for exactly this and the homepage must not import it.
//
// The API is mocked the way tests/navigation-shell.test.mjs mocks it: route
// interception over a static file server, no relay, no Redis. The shapes are
// copied from the real ones -- relay/envelope.js listAccountEnvelopes for the
// documents, admin/server.js:2600 for the overview, admin/server.js:3167 for
// billing -- so a change in those shapes shows up here as a red test rather
// than as an empty card in production.
//
// PARAMANT_HOME_IN_SCREENSHOT_DIR=<dir> writes one screenshot per state into that
// directory. Off by default; the assertions do not need it.
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
const aliases = { '/':'/index.html', '/dashboard':'/dashboard.html', '/sign':'/sign.html', '/parashare':'/parashare.html', '/pricing':'/pricing.html' };

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
function ok(name, condition, detail='') { checks.push({ name, pass:!!condition, detail:String(detail) }); }

// The one notation the site shows a reader, rebuilt here rather than imported,
// so a bug in js/format-date.js cannot make this test agree with it.
const MONTHS = ['January','February','March','April','May','June','July','August','September','October','November','December'];
const day = (v) => { const d = new Date(v); return `${d.getUTCDate()} ${MONTHS[d.getUTCMonth()]} ${d.getUTCFullYear()}`; };
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

// How many resends the page asked for, and what the last answer was. Kept out
// here so the interaction case below can read it after the page is gone.
let resendCalls = 0;

async function openHome({ documents, overview, billing, inbox = inboxNone, down = false, resend = null }) {
  const page = await browser.newPage({ viewport:{ width:390, height:844 } });
  await page.route('**/api/user/session/verify', (r) => r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify({ authenticated:true, email:'mickbr@example.com' }) }));
  const answer = (payload) => (r) => (down
    ? r.fulfill({ status:500, contentType:'application/json', body:'{"error":"unavailable"}' })
    : r.fulfill({ status:200, contentType:'application/json', body:JSON.stringify(payload) }));
  // The resend goes on FIRST, because Playwright tries handlers newest-first
  // and '**/api/user/parasign/inbox/*/resend' would otherwise never be reached
  // if a broader pattern were registered after it.
  if (resend) {
    await page.route('**/api/user/parasign/inbox/*/resend', (r) => {
      resendCalls++;
      return r.fulfill({ status:resend.status, contentType:'application/json', body:JSON.stringify(resend.body) });
    });
  }
  await page.route('**/api/user/parasign/inbox', answer(inbox));
  await page.route('**/api/user/documents', answer(documents));
  await page.route('**/api/user/dashboard/overview', answer(overview));
  await page.route('**/api/user/billing/status', answer(billing));
  await page.goto(ORIGIN + '/', { waitUntil:'domcontentloaded' });
  await page.locator('[data-home="in"]:not([hidden])').waitFor();
  // The workbench is filled by four fetches that resolve after the swap, so
  // wait for the state each case is actually about rather than for a timer.
  await page.waitForFunction(() => {
    const fig = document.querySelector('[data-hw-read]');
    const quiet = document.querySelector('[data-hw-quiet]');
    return (fig && !fig.hidden) || (quiet && !quiet.hidden);
  });
  return page;
}

// What is drawn, where, and what the reader can read. One evaluate per state.
async function measure(page) {
  return page.evaluate(() => {
    const vis = (el) => el && !el.hidden && getComputedStyle(el).display !== 'none';
    const inn = document.querySelector('[data-home="in"]');
    const main = document.querySelector('main');
    const footer = document.querySelector('footer');
    // The lowest thing main actually draws. Text nodes only: an empty wrapper
    // that happens to stretch is exactly the hole this is looking for.
    let lowest = main.getBoundingClientRect().top;
    for (const node of main.querySelectorAll('*')) {
      if (!vis(node)) continue;
      const style = getComputedStyle(node);
      if (style.visibility === 'hidden') continue;
      const box = node.getBoundingClientRect();
      if (box.width < 1 || box.height < 1) continue;
      const paints = (node.childNodes.length && Array.from(node.childNodes).some((c) => c.nodeType === 3 && c.textContent.trim()))
        || node.tagName === 'SVG' || node.tagName === 'svg' || node.tagName === 'IMG'
        || style.borderBottomWidth !== '0px' || style.backgroundImage !== 'none';
      if (paints && box.bottom > lowest) lowest = box.bottom;
    }
    return {
      num: (document.querySelector('[data-hw-num]') || {}).textContent || '',
      of: vis(document.querySelector('[data-hw-of]')) ? document.querySelector('[data-hw-of]').textContent : '',
      cap: vis(document.querySelector('[data-hw-cap]')) ? document.querySelector('[data-hw-cap]').textContent : '',
      sub: vis(document.querySelector('[data-hw-sub]')) ? document.querySelector('[data-hw-sub]').textContent : '',
      quiet: vis(document.querySelector('[data-hw-quiet]')),
      strip: vis(document.querySelector('[data-hw-strip]')) ? document.querySelector('[data-hw-strip]').innerText.replace(/\s+/g, ' ').trim() : '',
      inbox: vis(document.querySelector('[data-hw-inbox]')),
      inboxRows: Array.from(document.querySelectorAll('[data-hw-inbox-list] .hw-row')).map((r) => r.innerText.replace(/\s+/g, ' ').trim()),
      inboxActs: Array.from(document.querySelectorAll('[data-hw-inbox-list] [data-hw-resend]')).map((b) => b.textContent.trim()),
      // The tap target on the one control this page has. A phone reader who
      // cannot hit it has no way to get the mail back.
      actHeight: (() => {
        const b = document.querySelector('[data-hw-inbox-list] [data-hw-resend]');
        return b ? Math.round(b.getBoundingClientRect().height) : 0;
      })(),
      waiting: vis(document.querySelector('[data-hw-waiting]')),
      waitingRows: Array.from(document.querySelectorAll('[data-hw-waiting-list] .hw-row')).map((r) => r.innerText.replace(/\s+/g, ' ').trim()),
      recent: vis(document.querySelector('[data-hw-recent]')),
      recentRows: Array.from(document.querySelectorAll('[data-hw-recent-list] .hw-row')).map((r) => r.innerText.replace(/\s+/g, ' ').trim()),
      empty: vis(document.querySelector('[data-hw-empty]')),
      plan: vis(document.querySelector('[data-hw-plan]')) ? document.querySelector('[data-hw-plan]').innerText.replace(/\s+/g, ' ').trim() : '',
      renew: vis(document.querySelector('[data-hw-renew]')),
      actions: Array.from(document.querySelectorAll('[data-home="in"] .home-actions a')).map((a) => a.getAttribute('href')),
      buttons: Array.from(document.querySelectorAll('[data-home="in"] a.hp-btn')).filter((a) => a.offsetParent !== null).map((a) => a.getAttribute('href')),
      text: inn.innerText,
      gap: Math.round(footer.getBoundingClientRect().top - lowest),
      cards: Array.from(document.querySelectorAll('[data-home="in"] .hw-card')).filter(vis).length,
    };
  });
}

// The vocabulary a bookkeeper in Apeldoorn does not have to learn to read his
// own homepage. Every one of these is a real string from somewhere in this
// codebase, which is why it is worth pinning that none of them arrive here.
const JARGON = /\benvelope|env_|pgp_|pst_|sha3|ml-dsa|ml-kem|merkle|recipe_version|api key|endpoint|payload|http \d|\bjson\b|redis|quota\b|caps\b|parasign_|paid_until|current_plan/i;

const states = [
  { key:'open',   title:'open requests',        args:{ documents:documentsOpen, overview:overviewCommunity, billing:billingCommunity } },
  { key:'recent', title:'recent documents only', args:{ documents:documentsDone, overview:overviewPro, billing:billingPro } },
  { key:'empty',  title:'a new account',        args:{ documents:documentsNone, overview:overviewCommunity, billing:billingCommunity } },
  { key:'down',   title:'every route down',     args:{ documents:documentsOpen, overview:overviewCommunity, billing:billingCommunity, down:true } },
  { key:'inbox',  title:'documents waiting for you', args:{ documents:documentsOpen, overview:overviewCommunity, billing:billingCommunity, inbox:inboxWaiting } },
];

const seen = {};
for (const state of states) {
  const page = await openHome(state.args);
  const m = await measure(page);
  seen[state.key] = m;
  if (SHOTS) {
    fs.mkdirSync(SHOTS, { recursive:true });
    await stableScreenshot(page, { path:path.join(SHOTS, `home-in-${state.key}-390.png`), fullPage:true });
  }
  ok(`${state.title}: the reader is never left with three buttons over a hole`, m.gap <= 120, `gap ${m.gap}px, cards ${m.cards}`);
  ok(`${state.title}: the words are the reader's, not the relay's`, !JARGON.test(m.text), (m.text.match(JARGON) || [''])[0]);
  ok(`${state.title}: the three actions stay, and stay in order`, JSON.stringify(m.actions) === JSON.stringify(['/dashboard','/sign','/parashare']), JSON.stringify(m.actions));
  await page.close();
}

// 1. Open requests. Two of the three mocked documents are open, so the figure
// is 2, both of them are listed, and the oldest one is named by date.
ok('open requests: the figure is the number of open requests in the API', seen.open.num === '2' && seen.open.of === '', `${seen.open.num} ${seen.open.of}`);
ok('open requests: the line under the figure says what the 2 are', /requests are waiting on a signature/.test(seen.open.cap), seen.open.cap);
ok('open requests: the oldest one is dated in the one notation', seen.open.sub === `The oldest went out on ${day(OPEN_OLDEST)}.`, seen.open.sub);
ok('open requests: both open documents are listed with who they wait on', seen.open.waiting && seen.open.waitingRows.length === 2
  && seen.open.waitingRows[0].includes('Engagement letter Bakker.pdf')
  && seen.open.waitingRows[0].includes('Waiting on Anna Bakker and Joris de Wit')
  && seen.open.waitingRows[0].includes('0 of 2')
  && seen.open.waitingRows[1].includes('Waiting on Joris de Wit')
  && seen.open.waitingRows[1].includes('1 of 2'), JSON.stringify(seen.open.waitingRows));
// Recent shows what is NOT already in the card above it. Three mocked
// documents, two of them open and listed as open, leaves exactly the finished
// one here. A homepage that printed the same file name twice on one screen
// would be repeating the fault the buyer review found on /account, where the
// end of the term was announced three times in three tones.
ok('open requests: recent lists what the waiting card does not, with a state and a date', seen.open.recent
  && seen.open.recentRows.length === 1
  && seen.open.recentRows[0].includes('Annual accounts 2025.pdf')
  && seen.open.recentRows[0].includes('Completed'), JSON.stringify(seen.open.recentRows));
ok('open requests: no document is printed twice on one screen', new Set(
  [...seen.open.waitingRows, ...seen.open.recentRows].map((r) => r.split('\n')[0])).size
  === seen.open.waitingRows.length + seen.open.recentRows.length, JSON.stringify([seen.open.waitingRows, seen.open.recentRows]));
ok('open requests: the month balance is still readable, in the strip', /SIGNATURES LEFT 2 of 2/i.test(seen.open.strip), seen.open.strip);
ok('open requests: a free account is told the plan is free and is not sold to', seen.open.plan === 'Community, free for good.' && !seen.open.renew, seen.open.plan);
ok('open requests: nothing is empty, so no empty card', !seen.open.empty, String(seen.open.empty));

// 2. Nothing open. The figure falls back to the month's signature balance,
// which is the number the buyer review of 5 September found nowhere on the site
// while /api/user/dashboard/overview already had it.
ok('recent only: the figure is the signatures left this month, from the API', seen.recent.num === '97' && seen.recent.of === 'of 100', `${seen.recent.num} ${seen.recent.of}`);
ok('recent only: the figure is named in plain words', seen.recent.cap === 'signatures left this month', seen.recent.cap);
ok('recent only: the reader is told when the count starts again', /^The count resets on \d+ [A-Z][a-z]+ \d{4}\.$/.test(seen.recent.sub), seen.recent.sub);
ok('recent only: nothing is open, so the waiting card is not drawn', !seen.recent.waiting && seen.recent.recent && seen.recent.recentRows.length === 3, JSON.stringify(seen.recent.recentRows));
// "Firm", not "ParaSign Firm": the stored tier is per product because the
// entitlement layer is, but the plan that grants it is one payment for both
// products, so a product prefix would name a plan that is not sold and would
// tell a Firm customer that half of what he bought runs out by itself.
// ParaSign Business, which IS sold on its own, keeps its prefix.
ok('recent only: a paid term names its end and says nothing renews', seen.recent.plan === `Firm, ends on ${day(PRO_ENDS)}, nothing renews automatically.`, seen.recent.plan);
ok('recent only: a term 29 days out does not shout Renew yet', !seen.recent.renew, String(seen.recent.renew));

// 3. A new account. Not a hole: one card, its own object, two ways out, and the
// month balance above it, so the first screen is full and deliberate.
ok('a new account: the figure is the full monthly allowance', seen.empty.num === '2' && seen.empty.of === 'of 2', `${seen.empty.num} ${seen.empty.of}`);
ok('a new account: one friendly card takes the place of the two lists', seen.empty.empty && !seen.empty.waiting && !seen.empty.recent, JSON.stringify([seen.empty.empty, seen.empty.waiting, seen.empty.recent]));
ok('a new account: no strip of zeros where a reading would go', seen.empty.strip === '', seen.empty.strip);
ok('a new account: the card says both first steps and how long they take', /Nothing here yet\./.test(seen.empty.text) && /both take under a minute/.test(seen.empty.text), '');
// The card carries Start signing and Send securely. Drawing the same two again
// eight lines lower is the page-of-buttons this change exists to end, so the
// row underneath is taken away in this one state and Documents stays in the
// nav's user menu.
ok('a new account: the two first steps are offered once, not twice', seen.empty.buttons.length === 2
  && JSON.stringify(seen.empty.buttons) === JSON.stringify(['/sign','/parashare']), JSON.stringify(seen.empty.buttons));
ok('every other state keeps the three actions on screen', seen.open.buttons.length === 3 && seen.recent.buttons.length === 3 && seen.down.buttons.length === 3,
  JSON.stringify([seen.open.buttons, seen.recent.buttons, seen.down.buttons]));

// 4. Every route down. A calm line, no number invented, no raw error, and the
// page keeps its shape.
ok('every route down: no figure is invented', seen.down.quiet && seen.down.cap === '' && seen.down.of === '', JSON.stringify([seen.down.quiet, seen.down.cap]));
ok('every route down: the reader gets a sentence, not a status code', /not loading right now/.test(seen.down.text) && !/error|failed|500/i.test(seen.down.text), '');
ok('every route down: no half-filled cards are left behind', !seen.down.waiting && !seen.down.recent && !seen.down.empty && !seen.down.inbox && seen.down.plan === '', JSON.stringify([seen.down.waiting, seen.down.recent, seen.down.empty, seen.down.inbox, seen.down.plan]));

// 5. Documents waiting for the READER. Until the party index existed this page
// could count only what the account had SENT, and said so in its own header
// comment. Two documents are waiting on this reader and two of the account's
// own requests are waiting on somebody else; the figure has to be the first
// number, because it is the only one the reader can act on.
ok('waiting for you: the figure counts what waits on the reader, not what the account sent', seen.inbox.num === '2' && seen.inbox.of === '', `${seen.inbox.num} ${seen.inbox.of}`);
ok('waiting for you: the line says whose signature it is waiting for', seen.inbox.cap === 'documents are waiting for your signature', seen.inbox.cap);
ok('waiting for you: the first one is dated in the one notation', seen.inbox.sub === `The first one arrived on ${day(INBOX_FIRST)}.`, seen.inbox.sub);
ok('waiting for you: both are listed, each named by its sender and its date', seen.inbox.inbox
  && seen.inbox.inboxRows.length === 2
  && seen.inbox.inboxRows[0].includes('Shareholder agreement.pdf')
  && seen.inbox.inboxRows[0].includes('From notary@example.com')
  && seen.inbox.inboxRows[0].includes(`sent ${day(INBOX_FIRST)}`)
  && seen.inbox.inboxRows[1].includes('Supplier terms 2026.pdf'), JSON.stringify(seen.inbox.inboxRows));
ok('waiting for you: every row offers the one thing this page can do', seen.inbox.inboxActs.length === 2
  && seen.inbox.inboxActs.every((t) => t === 'Send me the link again'), JSON.stringify(seen.inbox.inboxActs));
ok('waiting for you: that button is a real tap target on a phone', seen.inbox.actHeight >= 44, `${seen.inbox.actHeight}px`);
// The account's own open requests do not disappear; they stop being the
// headline. Two big numbers arguing on one screen is the fault this ordering
// exists to avoid.
ok('waiting for you: the account own open requests move into the strip, not away', /YOUR OPEN REQUESTS 2/i.test(seen.inbox.strip) && seen.inbox.waiting, seen.inbox.strip);
// The card can say a document is waiting. It cannot open one: the route hands
// back no invite token, so a link here would be a promise the page cannot keep.
ok('waiting for you: the card promises no way in that it does not have', /opens from the personal link in its invitation email/.test(seen.inbox.text)
  && seen.inbox.inboxRows.every((r) => !/open|view|sign now/i.test(r)), JSON.stringify(seen.inbox.inboxRows));

// And the paragraph that used to sit above the buttons is gone in every state.
// It described the three buttons in prose, one line above the three buttons.
ok('the hero no longer explains its own buttons in a paragraph', !/Pick up an open request/.test(seen.open.text + seen.empty.text), '');

// 6. Pressing the button. One request, and the answer stays on the button and
// names the address the mail went to, which is the reader's own and the only
// one it could have gone to.
{
  const page = await openHome({
    documents:documentsNone, overview:overviewCommunity, billing:billingCommunity, inbox:inboxWaiting,
    resend:{ status:200, body:{ ok:true, sent_to:'mickbr@example.com' } },
  });
  await page.locator('[data-hw-inbox-list] [data-hw-resend]').first().click();
  await page.waitForFunction(() => /Sent/.test(document.querySelector('[data-hw-inbox-list] [data-hw-resend]').textContent));
  const label = await page.locator('[data-hw-inbox-list] [data-hw-resend]').first().textContent();
  ok('send me the link again: one press, one request, and it says where it went',
    resendCalls === 1 && label.trim() === 'Sent to mickbr@example.com', `${resendCalls} calls, "${label}"`);
  await page.close();
}

// And a second press inside the hour. The server caps a resend at one per
// document per hour, so the reader has to be told which of the two things
// happened rather than left pressing a button that looks unchanged.
{
  resendCalls = 0;
  const page = await openHome({
    documents:documentsNone, overview:overviewCommunity, billing:billingCommunity, inbox:inboxWaiting,
    resend:{ status:429, body:{ error:'rate_limited' } },
  });
  await page.locator('[data-hw-inbox-list] [data-hw-resend]').first().click();
  await page.waitForFunction(() => /again in an hour/.test(document.querySelector('[data-hw-inbox-list] [data-hw-resend]').textContent));
  const m = await measure(page);
  ok('send me the link again: a capped resend is a sentence, not a status code',
    !/429|rate_limited|error/i.test(m.text), (m.text.match(/429|rate_limited|error/i) || [''])[0]);
  await page.close();
}

await browser.close();
server.close();

const failed = checks.filter((c) => !c.pass);
for (const c of checks) console.log(`${c.pass ? 'ok  ' : 'FAIL'}  ${c.name}${c.detail ? `  -- ${c.detail}` : ''}`);
console.log(`\n${checks.length - failed.length}/${checks.length} passed`);
if (failed.length) process.exit(1);
