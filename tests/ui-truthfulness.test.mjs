import assert from 'node:assert/strict';
import fs from 'node:fs';

function read(file) { return fs.readFileSync(new URL('../' + file, import.meta.url), 'utf8'); }

const account = read('frontend/account.html');
const accountJs = read('frontend/js/account.inline1.js');
const adminHtml = read('admin/public/index.html') + read('frontend/admin.html');
const adminJs = read('admin/public/app.js') + read('frontend/js/admin.page.js');
const email = read('admin/lib/email-templates.js');

assert.doesNotMatch(account + accountJs + adminHtml + adminJs, /Delete account permanently|Account deleted|permanent, cannot undo/i);
assert.match(account, /makes its API key unusable/i);
assert.match(account, /sessions and TOTP setup are removed/i);
assert.match(account, /account record is retained/i);
assert.doesNotMatch(account, /Stub mode|No real payments are charged|Mollie integration pending/i);
assert.match(adminHtml, /blocks the account key and removes active sessions and TOTP/i);
assert.match(adminHtml, /Type DEACTIVATE to confirm/);
assert.match(adminJs, /Account deactivated/);
// Deletion now erases the personal data itself, so the mail has to say so.
// It used to promise the opposite, because deletion only revoked the key and
// left the address in users.json (audit finding 5 of 2026-07-21). A mail that
// undersells an erasure is as untrue as one that oversells it, which is what
// this file exists to catch.
assert.match(email, /Personal data removed from our systems/);
assert.match(email, /Billing records kept for as long as tax law requires/);
assert.doesNotMatch(email, /Account record and audit entries retained/);
assert.doesNotMatch(email, /sign up again|Files already relayed are not affected/i);

// The wording moved when the assurance rung was renamed from the eIDAS word
// 'substantial' to 'mrz-unverified'. What the page must keep saying is the
// same thing: the check digits add up and nothing about the document itself
// was verified. Matched on the claim, not on one exact sentence.

console.log('ui-truthfulness: deactivation and MRZ scope are stated honestly');


// ── The signing page now that /sign is served to everyone ────────────────────
// Two things must stay true, and both cost trust if they slip.
const signHtml = read('frontend/sign.html');
const signJs = read('frontend/sign-flow.js');
// What a visitor actually reads. Comments explain the code to us and routinely
// quote the very phrasing they exist to forbid ("no verified signer"), so a
// no-overclaim check that scans the raw file fails on its own explanation.
const signVisible = signHtml.replace(/<!--[\s\S]*?-->/g, '');

// 1. An open-mode signature must never be presented as a verified signer.
// Recipe version 4 binds the signer's PUBLIC KEY into the signed message, so
// the proof commits to "key K signed slot i of document D" and to nothing about
// who holds K. This is the same overclaim that renamed the ParaID assurance
// rung from 'substantial' to 'mrz-unverified'.
assert.match(signHtml, /Signer not verified/i,
  'sign.html must state that an open-mode signer is not verified');
assert.match(signHtml, /does not\s+show who holds that key/i,
  'sign.html must say the proof does not identify the holder of the key');
assert.doesNotMatch(signVisible, /identity verified|verified signer|signer verified|legally binding/i,
  'sign.html must not claim a verified identity or legal effect it cannot deliver');

// The scope notice is driven by what the SERVER reported, never by the mode the
// visitor picked in the UI. A label that guesses is worse than no label: it
// would read as a verdict on evidence nobody checked.
assert.match(signJs, /function showProofScope/,
  'sign-flow.js must have the proof-scope control');
assert.doesNotMatch(signJs, /showProofScope\([^)]*signingMode/,
  'the proof scope must not be derived from the UI signing mode');

// 2. A visitor without a session is told what signing needs BEFORE picking a
// file, not after. The page used to be behind an nginx auth_request; moving the
// dead end to the last step would be worse than the redirect it replaced.
assert.match(signHtml, /Signing a document needs an account/i,
  'sign.html must state the account requirement up front');
assert.match(signHtml, /open a signing request someone sent you/i,
  'sign.html must say what an invited signer can still do without an account');
assert.match(signJs, /function showSessionRequirement/,
  'sign-flow.js must have the session-requirement control');


// ── The auth and account screens ─────────────────────────────────────────────
// docs/brand/messaging.md section 8: an auth screen exists to get the right
// person back into their account with the least text possible. One sentence
// saying what the screen does and what happens next, one action, and no promise.
// These assertions pin the sentence each screen now opens with, so a rewrite
// that quietly drops the explanation fails here instead of in production.
const authFirstSentence = {
  'frontend/auth/login.html': /No password to type: sign in with your passkey/i,
  'frontend/auth/setup.html': /Pick one now and add the other later/i,
  'frontend/auth/backup.html': /each code works\s+once and gets you in without your authenticator app/i,
  'frontend/auth/request-reset.html': /if it matches an account, we send a link/i,
  'frontend/auth/reset-confirm.html': /You get two emails, one after the other/i,
  'frontend/signup/verified.html': /Paramant has no passwords/i,
};
for (const [file, rx] of Object.entries(authFirstSentence)) {
  assert.match(read(file), rx, `${file} must open by saying what this screen does`);
}

// An auth screen that sells is an auth screen that lost someone's password
// reset. No prices, no tier names, no founder block on these six.
const authVisible = Object.keys(authFirstSentence)
  .map((file) => read(file).replace(/<!--[\s\S]*?-->/g, ''))
  .join('\n');
assert.doesNotMatch(authVisible, /EUR\s?\d|€|per month|Community tier|Mick Beer/i,
  'auth screens must not carry pricing, tier names or the founder block');

// A ParaSign signature is a Simple Electronic Signature (/about pins that
// wording). The setup flow used to end on "Add your legally-binding signature
// to a PDF", which promises a legal effect the product does not deliver and
// which tests/ui-truthfulness already forbids on /sign. Same rule, same surface.
assert.doesNotMatch(authVisible,
  /legally.binding|identity verified|verified signer|signer verified/i,
  'the auth screens must not claim a legal effect or a verified identity');

console.log('ui-truthfulness: the auth screens say what they do and sell nothing');


// ── What the review of the auth screens caught, pinned so it cannot come back ─
// Scope note: /account and /download are deliberately absent here. The account
// screen is being rewritten in the dashboard PR and /download is not an auth
// screen; both were taken back out of this branch.
// 1. /auth/request-reset and /auth/reset-confirm used <main class="page-main">,
//    a class no stylesheet in frontend/ defines, so at 390px the heading and the
//    primary button sat flush against both screen edges. They now use the same
//    container as /auth/login and /auth/backup.
const styled = ['frontend/design-system.css', 'frontend/nav.css']
  .map(read).join('\n');
for (const file of ['frontend/auth/request-reset.html', 'frontend/auth/reset-confirm.html']) {
  const main = read(file).match(/<main class="([^"]+)"/);
  assert.ok(main, `${file} must have a <main> with a class`);
  for (const cls of main[1].split(/\s+/)) {
    assert.ok(styled.includes(`.${cls}`),
      `${file}: <main class="${cls}"> has no rule in any stylesheet, so the page has no side margin`);
  }
}

// 2. The reset confirmation token is written with { EX: 3600 } (admin/server.js).
//    The page claimed 15 minutes and justified it as a safety property, which
//    made a wrong number sound deliberate.
const resetConfirm = read('frontend/auth/reset-confirm.html');
assert.match(resetConfirm, /Confirmation links last 60 minutes/i,
  'reset-confirm must state the TTL the code actually sets (EX: 3600)');
assert.doesNotMatch(resetConfirm, /arrives within a minute|within a minute/i,
  'no delivery-time promise: the reset mail is sent fire-and-forget');

// 3. Clicking through from a mail to "confirm" and then being told a second mail
//    follows reads as phishing unless the page says why it is split in two.
assert.match(resetConfirm, /someone who briefly had your mailbox open/i,
  'reset-confirm must say why the reset takes two emails');

// 4. The sign-in rate limit is per IP (5/900s) AND per email address (10/900s),
//    admin/server.js. The email counter is account-wide, so "this device" points
//    the reader at the wrong cause.
const loginJs = read('frontend/js/auth-login.js');
assert.doesNotMatch(loginJs, /attempts from this device/i,
  'the 429 text must not blame the device: the limit is also per account');
assert.match(loginJs, /counted per account and per internet connection/i,
  'the 429 text must name both counters, because either one can be the cause');

// 4b. POST /api/user/auth/request-totp-reset sends a CONFIRMATION mail whose
//     token is { EX: 3600 } (admin/server.js:1890). The 14 day setup token is
//     only written after /auth/reset-confirm succeeds (admin/server.js:1935),
//     so the success message on request-reset may not promise a setup link that
//     lasts 14 days: at that point no setup link exists yet. Both numbers have
//     to appear, attached to the right mail.
const requestResetJs = read('frontend/js/auth-request-reset.js');
assert.match(requestResetJs, /a confirmation email is on its way/i,
  'request-reset must say the first mail confirms the request, not that it carries the setup link');
assert.match(requestResetJs, /valid for 60 minutes/i,
  'the confirmation token is EX 3600, so the success message must say 60 minutes');
assert.match(requestResetJs, /that one works for 14 days/i,
  'the 14 days belong to the second mail, the one with the setup link');
assert.doesNotMatch(requestResetJs, /a setup link is on its way/i,
  'no setup link exists until the confirmation is opened');

//     And the success message has to be visible when it fires: #success sat
//     inside #reset-form, which auth-request-reset.js hides on success, so the
//     confirmation was hidden with its parent and the screen went blank.
const requestResetHtml = read('frontend/auth/request-reset.html');
const resetFormBlock = requestResetHtml.slice(requestResetHtml.indexOf('<form id="reset-form"'),
                                              requestResetHtml.indexOf('</form>'));
assert.doesNotMatch(resetFormBlock, /id="success"/,
  'the success message must sit outside #reset-form: the handler hides that form on success');
assert.match(requestResetHtml, /id="success"/,
  'request-reset still needs a success container, just not inside the form');

//     The same endpoint answers 429 with retry_after 86400 (admin/server.js:1875)
//     off a 5-per-address-per-24h and 10-per-connection-per-hour limit. A shared
//     "try again" branch tells someone who is locked out for a day to retry now.
assert.match(requestResetJs, /res\.status === 429/,
  'request-reset must handle 429 separately: retrying does not help for up to a day');
assert.match(requestResetJs, /up to 24 hours to clear/i,
  'the 429 text must state the wait the server actually imposes (retry_after 86400)');

// 5. Every one of these screens must name the party behind the product and the
//    country it sits in. The stamped legal-strip carries the documents, not the
//    company, and apply-nav.py owns that strip.
for (const file of Object.keys(authFirstSentence)) {
  assert.match(read(file), /Paramantis Solutions B\.V\./,
    `${file} must name the company behind the product`);
  assert.match(read(file), /Harderwijk,\s+the Netherlands/,
    `${file} must name the country the company sits in`);
}

// 6. /signup/verified made a lawyer choose between seven authenticator apps and
//    told them a SHA-256 app is "stronger" without saying what that means.
const verified = read('frontend/signup/verified.html');
assert.doesNotMatch(verified, /SHA-256 app is stronger|Raivo|Aegis|2FAS|Ente Auth/i,
  'verified must not ask the reader to rank authenticator apps; link the help page');
assert.match(verified, /help\/authenticator-apps/,
  'verified must link the help page that does compare the apps');
assert.doesNotMatch(verified, /class="next-num"/,
  'no step badge numbered 2 on a page that has no step 1');
// Same rule as reset-confirm: the setup mail is dispatched fire-and-forget and
// nothing in the code knows what the receiving provider will do with it.
assert.doesNotMatch(verified, /can take up to 60 seconds|arrives within a minute/i,
  'no delivery-time promise on verified either: the rule holds on every screen');


// 7. .lede carries no top margin and h1 carries no bottom margin, so on
//    /auth/setup, /auth/backup and /auth/request-reset the heading and the lead
//    paragraph touched at 390px (measured 0px, against 8px on login and 16px on
//    verified). The .mt-3 utility (16px) restores the gap without changing .lede
//    for the eleven other pages that use it.
for (const file of ['frontend/auth/setup.html', 'frontend/auth/backup.html',
                    'frontend/auth/request-reset.html']) {
  const html = read(file);
  const afterH1 = html.slice(html.indexOf('</h1>'));
  assert.match(afterH1.slice(0, 200), /<p class="lede mt-3">/,
    `${file}: the lead paragraph under the h1 needs a top margin or the two touch at 390px`);
}

console.log('ui-truthfulness: the review findings on PR #337 stay fixed');
// ── The homepage now that it sells instead of describes ──────────────────────
// It states two things a page can be wrong about at real cost: what a signature
// is worth, and what it costs. Both are pinned here, because the homepage is
// the one page that repeats claims owned by another file.
const home = read('frontend/index.html').replace(/<!--[\s\S]*?-->/g, '');

// 1. Same overclaim rule as sign.html. An open-mode signature commits to "key K
// signed slot i of document D" and to nothing about who holds K, so the page
// that sells it may not promise identity or legal effect either.
assert.doesNotMatch(home, /identity verified|verified signer|signer verified|legally binding/i,
  'index.html must not claim a verified identity or legal effect ParaSign cannot deliver');

// 2. "No account" is true only for someone opening an invitation. Signing a
// document you started yourself needs an account (sign.html says so up front,
// and the relay gates POST /v2/envelopes on an API key while leaving
// POST /v2/envelopes/:id/sign public). A homepage that drops the scope turns a
// true sentence into a false one at the first click.
for (const m of home.matchAll(/[^.<>]*\bno account\b[^.<>]*/gi)) {
  assert.match(m[0], /invite|invitation|sent you|the link/i,
    `index.html scopes "no account" to the invited signer, not to signing in general: "${m[0].trim()}"`);
}

// 3. Every price the homepage names must also stand on the pricing page. Two
// pages quoting money is two places to be wrong; this makes the second one
// follow the first instead of drifting away from it.
const pricing = read('frontend/pricing.html');
// Matched on the WHOLE amount, not on a substring: an earlier version tested
// pricing.includes('&euro;15'), which stayed green on a pricing page that only
// ever said &euro;150. The digits must be followed by something that is not
// another digit or a decimal separator.
const homePrices = [...new Set([...home.matchAll(/&euro;([\d.,]+)/g)].map((m) => m[1]))];
assert.ok(homePrices.length >= 6, `expected the homepage to quote its tiers, found ${homePrices.length} prices`);
const priceOnPricingPage = (amount) => new RegExp(`&euro;${amount.replace(/[.]/g, '\\.')}(?![\\d.,])`).test(pricing);
const drifted = homePrices.filter((p) => !priceOnPricingPage(p));
assert.deepEqual(drifted, [],
  `these prices are on the homepage but not on /pricing: ${drifted.join(', ')}`);

// ── The dashboard, which is the homepage for anyone who signed up ────────────
// Mick's phone showed a badge reading "COMMUNITY PLAN" over a Start card, while
// /pricing sells Free, Pro, Business and Enterprise and never once says
// Community. The badge was the raw relay plan ID leaking into the interface, so
// the one number a customer wants to check (which plan am I on, what does the
// next one cost) could not be looked up on the page that sells it.
const dashboardJs = read('frontend/js/dashboard.js');
const planMap = (dashboardJs.match(/var PLAN_NAMES = \{[\s\S]*?\};/) || [''])[0];
const planEntries = [...planMap.matchAll(/^\s*([a-z_]+):\s*'([^']+)',?$/gm)].map((m) => [m[1], m[2]]);
const planIds = planEntries.map(([id]) => id);
const planNames = planEntries.map(([, name]) => name);

// relay/lib/tiers.js is the declared single source of truth for plans, so the
// gate reads ITS rows and ITS aliases rather than a second copy kept here.
// TIER_LIMITS holds the canonical plans; normalisePlan folds every other ID
// (free, dev, licensed) onto one of them. dashboard.js must name every
// canonical plan and must fold every alias the same way, or an account holding
// that ID renders a raw machine string in the badge, which is what 'licensed'
// did before this gate existed.
const tiersSrc = read('relay/lib/tiers.js');
const tierBlock = (tiersSrc.match(/TIER_LIMITS\s*=\s*Object\.freeze\(\{[\s\S]*?\n\}\);/) || [''])[0];
const canonicalPlans = [...tierBlock.matchAll(/^\s{2}([a-z]+):\s*Object\.freeze/gm)].map((m) => m[1]);
assert.ok(canonicalPlans.length >= 4,
  `expected the canonical plan rows in relay/lib/tiers.js, found ${canonicalPlans.length}`);

const normBlock = (tiersSrc.match(/function normalisePlan\([\s\S]*?\n\}/) || [''])[0];
// One line can declare several aliases at once
// ("if (plan === 'free' || plan === 'dev') return 'community';"), so collect
// every ID named in the condition, not just the first.
const tierAliases = [];
for (const line of normBlock.split('\n')) {
  const to = /return\s+'([a-z]+)'/.exec(line);
  if (!to) continue;
  for (const m of line.matchAll(/plan === '([a-z]+)'/g)) {
    if (m[1] !== to[1]) tierAliases.push([m[1], to[1]]);
  }
}
assert.ok(tierAliases.length >= 3,
  `expected normalisePlan to declare its aliases, found ${tierAliases.length}`);

const unnamed = canonicalPlans.filter((id) => !planIds.includes(id));
assert.deepEqual(unnamed, [],
  `relay/lib/tiers.js has these canonical plans but dashboard.js has no display name: ${unnamed.join(', ')}`);

const dashAliasBlock = (dashboardJs.match(/var PLAN_ALIASES = \{[^}]*\}/) || [''])[0];
const wrongAlias = tierAliases.filter(([from, to]) => !new RegExp(`${from}:\\s*'${to}'`).test(dashAliasBlock));
assert.deepEqual(wrongAlias.map(([f, t]) => `${f}->${t}`), [],
  'dashboard.js must fold the same plan aliases normalisePlan does');

const unsold = [...new Set(planNames)].filter((name) => !new RegExp(`>\\s*${name}\\s*<`).test(pricing));
assert.deepEqual(unsold, [],
  `the dashboard shows these plan names, but /pricing does not sell them: ${unsold.join(', ')}`);

// Every ParaRule must carry a way to check it, because the homepage says so:
// "The ParaRules come with a verify link each". Measured before this gate:
// nine rules, zero links, one mailto in the footer.
const pararules = read('frontend/pararules.html');
const guarantees = pararules.slice(pararules.indexOf('<h2>What we guarantee</h2>'), pararules.indexOf('<h2>How we build it</h2>'));
const ruleCount = (guarantees.match(/<h3>\d+\s*&middot;/g) || []).length;
const verifyCount = (guarantees.match(/class="rule-verify"/g) || []).length;
assert.equal(verifyCount, ruleCount,
  `pararules.html has ${ruleCount} rules but ${verifyCount} verify links; the homepage promises one each`);
assert.ok(ruleCount >= 9, `expected at least nine ParaRules, found ${ruleCount}`);

// The signed-in address is in the nav. A second copy in the hero was the first
// thing under the H1 on a phone, above both product actions.
const dashboard = read('frontend/dashboard.html').replace(/<!--[\s\S]*?-->/g, '');
const hero = (dashboard.match(/<header class="dh-hero"[\s\S]*?<\/header>/) || [''])[0];
assert.doesNotMatch(hero, /data-dh="email"/,
  'the dashboard hero must not repeat the email address the nav already shows');

// 4. The free plan is called Community everywhere, because that is the selling
// point and not an internal ID: admin/server.js has always named the plan
// Community, and /pricing, the homepage and the dashboard badge now agree.
// An earlier version of this file pinned the opposite (a bridge sentence
// explaining that Community "is the tier named Free"); that bridge existed only
// because the pricing page disagreed, and the fix was to rename the tier rather
// than to keep explaining it away.
assert.ok(/<div class="tier-name">Community<\/div>/.test(pricing),
  '/pricing must name its free tiers Community');
assert.doesNotMatch(pricing, /<div class="tier-name">Free<\/div>/,
  '/pricing must not have a tier named Free any more');
for (const [label, html] of [
  ['index.html', home],
  ['dashboard.html', read('frontend/dashboard.html')],
  ['parasign.html', read('frontend/parasign.html')],
]) {
  assert.doesNotMatch(html, /tier named <strong>Free<\/strong>|tier is called Free|the free plan\b/i,
    `${label} must not call the Community plan Free`);
}

// Nothing on the site may use Free as the NAME of our free plan. It is called
// Community, and the review found it surviving in seven places the first sweep
// missed: a feature list ("Everything in Free"), an FAQ answer ("Free covers 2
// signatures a month"), an API reference table ("Free (pgp_)", "Free/community
// -> 403"), the signing page ("Free accounts sign 2 documents a month") and the
// terms twice ("one hour on Free", "falls back to Free"). Each of those reads
// as a plan a visitor can go look for, and none of them exist under that name.
//
// Matched on shapes that can only be a plan name, so "Free to start", "Free on
// the Community plan" and BUSL's "Free to use" are untouched. Two pages are
// exempt and say why.
const TIER_NAME_SHAPES = [
  /Everything in Free\b/,
  /\bFree covers\b/,
  /\bFree accounts?\b/,
  /\bFree \(pgp_\)/,
  /\bFree\/community\b/,
  /\bfalls back to Free\b/,
  /\bon Free,/,
  /tier named <strong>Free<\/strong>/,
  /\bthe Free tier\b/,
  /<div class="tier-name">Free<\/div>/,
];
// vs.html describes COMPETITORS' pricing (WeTransfer has a tier it calls Free);
// paramant-ot-brief.html prices its own tier, named Evaluation, at "Free".
const TIER_NAME_EXEMPT = new Set(['vs', 'docs/paramant-ot-brief']);
const frontendPages = (dir = 'frontend', prefix = '') =>
  fs.readdirSync(new URL('../' + dir, import.meta.url), { withFileTypes: true }).flatMap((e) => {
    if (e.isDirectory()) return ['node_modules', 'vendor'].includes(e.name) ? [] : frontendPages(`${dir}/${e.name}`, `${prefix}${e.name}/`);
    return e.isFile() && e.name.endsWith('.html') ? [`${prefix}${e.name.slice(0, -5)}`] : [];
  });

const tierNameHits = [];
for (const slug of frontendPages()) {
  if (TIER_NAME_EXEMPT.has(slug)) continue;
  // Comments explain the rename and quote the very wording they forbid.
  const visible = read(`frontend/${slug}.html`).replace(/<!--[\s\S]*?-->/g, ' ');
  for (const rx of TIER_NAME_SHAPES) {
    const m = rx.exec(visible);
    if (m) tierNameHits.push(`${slug}: "${m[0]}"`);
  }
}
assert.deepEqual(tierNameHits, [],
  `these use Free as the name of a plan; it is called Community:\n  ${tierNameHits.join('\n  ')}\n`);

// The ParaRules grid on the homepage shows a SELECTION. It used to print the
// numbers 01, 03, 04 and 06, which reads as two rules gone missing rather than
// as four chosen. Either the numbers go or they run consecutively.
const ruleNumbers = [...home.matchAll(/<span class="r-n">(\d+)<\/span>/g)].map((m) => Number(m[1]));
if (ruleNumbers.length) {
  const consecutive = ruleNumbers.every((n, i) => i === 0 || n === ruleNumbers[i - 1] + 1);
  assert.ok(consecutive,
    `the homepage rules grid prints ${ruleNumbers.join(', ')}: show consecutive numbers or none at all`);
}

// 5. The founder line. The earlier version of this check had the shape
// "if (page says X) assert (/about says X)", which a rewrite walks straight
// past: swapping "privacy and security researcher" for "award winning
// cryptographer" deletes the very string the check looks for and it stays
// green. Pinned in BOTH directions now.
const about = read('frontend/about.html');
const flatten = (html) => html
  .replace(/<!--[\s\S]*?-->/g, ' ')
  .replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1>/gi, ' ')
  .replace(/<[^>]+>/g, ' ')
  .replace(/&amp;/g, '&').replace(/&nbsp;/g, ' ')
  .replace(/\s+/g, ' ');
const aboutText = flatten(about);

// The sanctioned name and title, exactly as /about states them.
const SANCTIONED_TITLE = 'privacy and security researcher';
assert.ok(aboutText.includes(`Mick Beer, ${SANCTIONED_TITLE}`),
  '/about is the source for the founder line and must carry the name and the title');

// Direction one: a page that sells on the founder must carry that exact title,
// so it cannot be quietly upgraded to something better-sounding.
// Direction two: the qualifier that follows his name must use only words
// /about itself uses, so no new credential can be smuggled in beside it.
const ABOUT_WORDS = new Set(aboutText.toLowerCase().match(/[a-z]+/g) || []);
for (const slug of ['index', 'pricing', 'parasign']) {
  const text = flatten(read(`frontend/${slug}.html`));
  if (!text.includes('Mick Beer')) continue;
  assert.ok(text.includes(`Mick Beer , ${SANCTIONED_TITLE}`) || text.includes(`Mick Beer, ${SANCTIONED_TITLE}`),
    `${slug}.html names the founder, so it must use the title /about gives him: "${SANCTIONED_TITLE}"`);
  // Everything between his name and the end of the qualifying clause.
  const after = text.slice(text.indexOf('Mick Beer') + 'Mick Beer'.length);
  const clause = after.split(/(?:\.\s|,\s+and\s+the\b|\(see\b)/)[0];
  const foreign = [...new Set((clause.toLowerCase().match(/[a-z]+/g) || []))]
    .filter((w) => w.length > 2 && !ABOUT_WORDS.has(w));
  assert.deepEqual(foreign, [],
    `${slug}.html describes Mick Beer with words /about does not use: ${foreign.join(', ')}`);
}
assert.ok(!/\bMick Beer\b/.test(home) || /KvK 42115132/.test(home),
  'if the homepage names the founder it must also name the accountable company registration');

console.log('ui-truthfulness: the homepage does not overclaim signatures and quotes the real prices');
console.log('ui-truthfulness: the free plan is Community everywhere and the founder line matches /about');
console.log('ui-truthfulness: the dashboard names the plans /pricing actually sells');
