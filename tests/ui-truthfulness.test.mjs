import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createRequire } from 'node:module';

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

// ── Billing stopped being a stub, so the copy has to stop saying it is ───────
// Payments run through Mollie for real (relay/lib/mollie.js, called
// unconditionally by POST /v2/billing/checkout), the webhook grants only on a
// re-fetched paid status (relay/lib/billing.js), and it issues a numbered
// document by itself: relay/lib/invoice.js (PS-YYYY-NNNN) or
// relay/lib/credit-note.js (CN-YYYY-NNNN) when money goes back. Nobody is
// invoiced by hand, nothing waits on an integration, and no figure on the
// billing tab is a fixture.
//
// admin/test/admin-ui-coupons.test.js guards admin/public/app.js, the screen
// that is served. This guards the two copies that test does not read: the
// unrouted second admin screen, which carried the same banner and is exactly
// how a corrected line gets copied back in, and the customer email, where the
// claim actually reached a customer.
// Both admin screens carry a block comment explaining which sentence used to
// stand there and why it was false, so they quote the very wording this check
// forbids. Same problem, same answer as signVisible below: read what a person
// sees, not what the file says about itself.
const adminJsVisible = adminJs.replace(/\/\*[\s\S]*?\*\//g, '');
const emailVisible = email.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
const billingLies = /Beta billing|beta note|payment processing is (in beta|not yet live)|manually invoiced|invoiced by hand|stub only|Mollie[^.]{0,40}(is in integration|goes live)|Formal invoicing follows/i;
assert.doesNotMatch(adminJsVisible, billingLies,
  'no admin screen may call billing a beta or a stub: Mollie payments are live');
assert.doesNotMatch(emailVisible, billingLies,
  'no customer email may promise invoicing that already happens');
// And the mail has to say what IS true of an admin-set plan: it was not paid
// for, so it has no document, while a plan that IS paid for gets one.
assert.match(email, /Nothing was charged for[\s\S]{0,4}it, so this change has no invoice/,
  'the plan-change mail must say an admin-set plan was not charged for');
assert.match(email, /numbered invoice or payment receipt/,
  'the plan-change mail must say what a real payment does get');

console.log('ui-truthfulness: deactivation, MRZ scope and billing are stated honestly');


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
// Scope note: /account was deliberately absent here while the dashboard PR
// rewrote it; the section further down now covers it. /download was absent for
// the same reason and has its own section at the foot of this file.
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

// 4. The sign-in 429 is now per IP and ONLY per IP (5 per 900s,
//    admin/lib/login-ratelimit.js). The per-email counter that used to share
//    that status code counted attempts rather than failures, so a stranger
//    naming your address could put you on 429 for fifteen minutes; it counts
//    failures now, clears on a success, and asks for a proof-of-work instead of
//    refusing. The page has to point at the cause that exists, and must not keep
//    telling people their account can be rate-limited shut.
const loginJs = read('frontend/js/auth-login.js');
assert.doesNotMatch(loginJs, /attempts from this device/i,
  'the 429 text must not blame the device: the limit is per internet connection');
assert.doesNotMatch(loginJs, /counted per account and per internet connection/i,
  'there is no per-account refusal any more, so the 429 text must not claim one');
assert.match(loginJs, /counts the connection, not your account/i,
  'the 429 text must name the counter that can actually cause it');
assert.match(loginJs, /nobody can trigger it by guessing at your email address/i,
  'and must say the thing that changed, because it is what a locked-out reader is looking for');

// 4a. The 428 is the priced attempt, not a refusal, and the page handles it by
//     solving the challenge and posting again. The message is only for the case
//     where that fails, so it may not read as a lockout either.
assert.match(loginJs, /res\.status === 428/,
  'the login page must handle the proof-of-work request rather than showing the user a dead end');
assert.match(loginJs, /ParamantCaptcha\.getCaptchaProof/,
  'and it must solve it with the proof-of-work helper the page loads');
assert.match(loginJs, /extra verification this sign-in needs/i,
  'and when the challenge itself fails, the message must be about the verification, not about being blocked');
assert.ok(read('frontend/auth/login.html').includes('/js/pow-captcha.js'),
  'the login page must actually load the proof-of-work helper it calls');

// 4b. A 503 means the TOTP single-use guard could not reach Redis and verification
//     failed closed. Nothing is wrong with the code or the account, and the page
//     has to say so rather than leaving the reader to conclude their code is bad.
assert.match(loginJs, /res\.status === 503/,
  'the login page must handle the fail-closed 503 separately from a wrong code');
assert.match(loginJs, /Nothing is wrong with your account or your code/i,
  'the 503 text must say the outage is ours, not theirs');

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
// Five: the three tier prices (0, 29, 299) and the two incl.-btw figures under
// them. It was six while the Firm line also quoted a EUR 0.40 per-signature
// rate; that rate was never charged and the line is gone, so the floor moved
// down with it rather than the check being weakened for something else.
assert.ok(homePrices.length >= 5, `expected the homepage to quote its tiers, found ${homePrices.length} prices`);
const priceOnPricingPage = (amount) => new RegExp(`&euro;${amount.replace(/[.]/g, '\\.')}(?![\\d.,])`).test(pricing);
const drifted = homePrices.filter((p) => !priceOnPricingPage(p));
assert.deepEqual(drifted, [],
  `these prices are on the homepage but not on /pricing: ${drifted.join(', ')}`);

// ── The dashboard, which is the homepage for anyone who signed up ────────────
// Mick's phone showed a badge reading "COMMUNITY PLAN" over a Start card, and
// the word was the raw relay plan ID leaking through. The fix is not to hide
// the word: Community is what relay/lib/tiers.js calls the free row, what /sla
// calls the plan, what the account mail calls it, and it is the one thing
// Paramant sells on. What was actually broken is that /pricing labels the same
// tier Free, so a customer who read COMMUNITY on the dashboard could not find
// it on the page that sells it. So the dashboard says Community AND names the
// pricing tier, and every OTHER name it shows has to exist on /pricing.
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

// Every rule must carry a way to check it, because the homepage says so:
// "Our rules come with a verify link each". Measured before this gate:
// nine rules, zero links, one mailto in the footer.
// The page was /pararules until the two-product-names round; the nine rules and
// their verify links moved across word for word, only the name went.
const rulesPage = read('frontend/rules.html');
const guarantees = rulesPage.slice(rulesPage.indexOf('<h2>What we guarantee</h2>'), rulesPage.indexOf('<h2>How we build it</h2>'));
const ruleCount = (guarantees.match(/<h3>\d+\s*&middot;/g) || []).length;
const verifyCount = (guarantees.match(/class="rule-verify"/g) || []).length;
assert.equal(verifyCount, ruleCount,
  `rules.html has ${ruleCount} rules but ${verifyCount} verify links; the homepage promises one each`);
assert.ok(ruleCount >= 9, `expected at least nine rules, found ${ruleCount}`);

// ── The same answer on the account page ──────────────────────────────────────
// A customer who wants to know what he pays goes to /account, not /dashboard,
// so account.inline1.js resolves plans too. It has to obey the same source of
// truth: name every canonical row, fold every alias the same way. Two maps that
// drift apart is how 'standard' reached a customer's screen in the first place.
const accountJsPlans = read('frontend/js/account.inline1.js');
const acctIds = [...((accountJsPlans.match(/var PLAN_NAMES = \{[\s\S]*?\};/) || [''])[0])
  .matchAll(/^\s*([a-z_]+):\s*'([^']+)',?$/gm)].map((m) => m[1]);
const acctUnnamed = canonicalPlans.filter((id) => !acctIds.includes(id));
assert.deepEqual(acctUnnamed, [],
  `relay/lib/tiers.js has these canonical plans but account.inline1.js has no display name: ${acctUnnamed.join(', ')}`);

const acctAliasBlock = (accountJsPlans.match(/var PLAN_ALIASES = \{[^}]*\}/) || [''])[0];
const acctWrongAlias = tierAliases.filter(([from, to]) => !new RegExp(`${from}:\\s*'${to}'`).test(acctAliasBlock));
assert.deepEqual(acctWrongAlias.map(([f, t]) => `${f}->${t}`), [],
  'account.inline1.js must fold the same plan aliases normalisePlan does');

// ── Both signed-in surfaces, on the message itself ───────────────────────────
const dashboardHtml = read('frontend/dashboard.html');
const accountHtml = read('frontend/account.html');

// A paying customer is not a lead. The band a paid plan sees says what was
// bought and stops there; it may not carry a link to the pricing page.
for (const [file, html] of [['dashboard.html', dashboardHtml], ['account.html', accountHtml]]) {
  const paid = (html.match(/id="(dh-plan-paid|billing-paid)"[\s\S]*?<\/(aside|div)>/) || [''])[0];
  assert.ok(paid, `${file} must carry the paid-plan band`);
  assert.doesNotMatch(paid, /href="\/pricing"/,
    `${file} must not sell a higher tier to someone who already pays`);
}

// The free band is the one upgrade path, so it gets exactly one link to
// /pricing. Two was the old bridge sentence explaining that Community was
// called Free over there; /pricing says Community now and the sentence is gone.
// The cut is the band's OWN closing tag. It used to be "the first block close
// followed by another block", which is not a boundary at all: on dashboard.html
// that ran 4224 characters past the band and swallowed three sections that have
// nothing to do with the upgrade path, so any link added anywhere below the
// free band failed this check. Naming the tag per band bounds it to the element
// the rule is about.
for (const [file, html, id, close] of [['dashboard.html', dashboardHtml, 'dh-community', 'aside'], ['account.html', accountHtml, 'billing-community', 'div']]) {
  const band = (html.match(new RegExp(`id="${id}"[\\s\\S]*?<\\/${close}>`)) || [''])[0];
  assert.ok(band, `${file} must carry the free-plan band`);
  assert.equal((band.match(/href="\/pricing"/g) || []).length, 1,
    `${file} must offer exactly one upgrade link in the free band`);
  assert.doesNotMatch(band, /called Free|tier is called|Same name on/i,
    `${file} must not still explain a Free/Community mismatch that no longer exists`);
}

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
  // "ParaSign Free" and "ParaSend Free" name a product tier and nothing else,
  // so they cannot be a false positive. They were missing from this list, and
  // security.html carried both through a full review because the only check
  // that forbade them was scoped to /about.
  /\bPara(Sign|Send) Free\b/,
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

// The rules grid on the homepage shows a SELECTION. It used to print the
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
// Mick, 4 September: one note is enough. The name and the title left every page
// but /about; on the homepage exactly one place keeps them, the signature under
// the letter, which is checked as a block further down. So index is the only
// page still required to name him, and no other page may be forced to.
const FOUNDER_REQUIRED = ['index'];
// Pages that MAY name him. If they do, the same rules apply.
const FOUNDER_OPTIONAL = ['pricing', 'parasign', 'dashboard', 'account'];
for (const slug of [...FOUNDER_REQUIRED, ...FOUNDER_OPTIONAL]) {
  const text = flatten(read(`frontend/${slug}.html`));
  if (FOUNDER_REQUIRED.includes(slug)) {
    assert.ok(text.includes('Mick Beer'),
      `${slug}.html sells on the founder, so it must name him; the line may not quietly disappear`);
  } else if (!text.includes('Mick Beer')) {
    continue;
  }
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
// The signature under the founder's letter must carry the registration itself,
// not lean on the footer or a card elsewhere on the page: the reader who stops
// at the signature has to see who is accountable.
{
  const letterSign = home.match(/<div class="letter-sign">[\s\S]*?<\/div>/);
  assert.ok(letterSign, 'the homepage letter has a signature block (.letter-sign)');
  assert.ok(/Mick Beer, privacy and security researcher/.test(letterSign[0]) && /KvK 42115132/.test(letterSign[0]),
    'the letter signature names Mick Beer, privacy and security researcher, and KvK 42115132 in the same block');
}

// 6. What /pricing promises, and in what order. relay/test/pricing-page.test.js
// checks the numbers against the catalog; tests/pricing-fold.test.mjs measures
// where they land on a phone. This checks the sentences themselves.
//
// Body only, and it matters. The same sentences sit in the meta description,
// the og: and twitter: descriptions and the JSON-LD, all of which stand before
// every element in the body, so an ordering check run over the whole file
// passes even when the visible page has lost the sentence entirely. Verified by
// replacing only the hero paragraph: the head copies kept an earlier version of
// this file green.
const pricingVisible = pricing.slice(pricing.indexOf('<body')).replace(/<!--[\s\S]*?-->/g, '');

// What the page sells, before what it costs. A visitor who lands here from a
// search engine has seen no other page, so "Pricing" plus a table says nothing.
// It may not open with the free plan's ceiling either. "vanish after one read"
// was false for everybody who pays; "vanish after one read on Community" was
// true and led the price page with the limit of the plan nobody pays for. The
// sentence now names no count, which is what makes it true on 1, 10, 25 and
// 100 reads and on expiry. Block 37 of site-claims.test.mjs holds the counts
// where they belong, in the cards and the prose.
assert.match(pricingVisible, /Sign documents and send files that delete themselves after reading\./,
  'pricing.html must say what the product does above the prices');

// The promise carries its own number. "Free forever" on its own reads as
// generous until the table says two signatures a month, and a buyer who finds
// that out one screen later has been sold to rather than told.
//
// The numbers come out of tiers.js rather than being typed here, so the sentence
// cannot drift away from the table that enforces it. It used to pin the literal
// "10 transfers a month, 5 MB per file": correct at the time, but it meant the
// sentence and the tier row could only ever be changed together by someone who
// knew this line existed, and the file ceiling in particular sat wrong for
// months partly because moving it broke tests that read like copy checks.
const _tiersSrc = read('relay/lib/tiers.js');
const _community = _tiersSrc.slice(_tiersSrc.indexOf('community:'), _tiersSrc.indexOf('pro:'));
const _dim = (name) => Number(new RegExp(`${name}:\\s*([\\d_]+)`).exec(_community)[1].replace(/_/g, ''));
assert.match(pricingVisible, /Community is &euro;0 a month, forever:<\/strong>[^<]*no card\./,
  'the free promise on pricing.html must carry the limits it actually means');
for (const [dim, phrase] of [['signs_month', `${_dim('signs_month')} signatures a month`],
                             ['transfers_month', `${_dim('transfers_month')} transfers a month`],
                             ['file_mb', `${_dim('file_mb')} MB`]]) {
  assert.ok(pricingVisible.includes(phrase),
    `the free promise on pricing.html must state ${dim} as tiers.js declares it: "${phrase}"`);
}
// And they must be the limits the relay enforces, not the per-IP rate on the
// deprecated anonymous endpoint. relay/test/pricing-page.test.js reads the
// numbers out of relay/lib/tiers.js; this keeps the phrase off the page.
assert.doesNotMatch(pricingVisible, /uploads per hour/,
  'pricing.html must not sell the anonymous per-IP rate as an account limit');
assert.ok(
  pricingVisible.indexOf('Sign documents and send files that delete themselves after reading.') <
  pricingVisible.indexOf('Community is &euro;0 a month, forever:'),
  'the product line must stand above the free/paid split',
);
assert.ok(
  pricingVisible.indexOf('Community is &euro;0 a month, forever:') <
  pricingVisible.indexOf('class="tier-card"'),
  'the free/paid split must stand above the first tier card, not under the tables',
);

// The words a lawyer cannot read, kept out of the lead paragraph. They are not
// banned from the page: the same facts stand under the tables, where a reader
// has asked for the detail.
const heroEnd = pricingVisible.indexOf('id="plans"');
assert.ok(heroEnd > 0, 'pricing.html must still have the plans section the hero links to');
const heroText = pricingVisible.slice(0, heroEnd);
for (const rx of [/post-quantum signatures/, /public proof log/, /dedicated relay/, /a connection to their own software/, /\ban API\b/]) {
  assert.doesNotMatch(heroText, rx,
    `the first screen of pricing.html must not open on ${rx.source}`);
}

// The lead names two amounts, and they buy two different products: &euro;15 is
// ParaSend Pro (sending) and &euro;49 is ParaSign Pro (signing). Named as one
// figure, "from &euro;15 a month" anchors an office that came here to sign, and
// the table then asks &euro;49. Both are read off the Pro cards themselves
// rather than typed in here, and relay/test/pricing-page.test.js binds those
// cards to relay/lib/billing-catalog.js, so the chain runs lead -> card ->
// catalog and no link in it can move on its own.
//
// SINCE 6 SEPTEMBER 2026 the split is gone at the source. Firm is one plan for
// both products at one price, so a lead that names two figures would be the
// untruth now. What survives is the rule that made the split necessary: the
// figure in the lead is read off the card the buyer will click, not typed here,
// and the card stands in BOTH product sections with the SAME price, so no
// visitor is anchored on a number the table then contradicts.
const firmCardPrice = (heading) => {
  const start = pricingVisible.indexOf(heading);
  assert.ok(start > 0, `pricing.html must still have the "${heading}" section`);
  const section = pricingVisible.slice(start, pricingVisible.indexOf('</section>', start));
  const m = /<div class="tier-name">Firm<\/div>\s*<div class="tier-price">&euro;([\d.,]+)/.exec(section);
  assert.ok(m, `the "${heading}" section must still have a Firm card with a price`);
  return m[1];
};
const sending = firmCardPrice('ParaSend · Send a file that disappears');
const signing = firmCardPrice('ParaSign · Get a document signed');
assert.equal(sending, signing,
  'Firm is one plan over both products; its card must show the same price in both sections');
assert.match(heroText, new RegExp(`<strong>&euro;${signing} a month</strong> for signing and sending together on Firm`),
  `the lead must name the Firm price (&euro;${signing}) as the price of BOTH products`);
// And it must not go back to two figures for what is now one purchase.
assert.doesNotMatch(heroText, /for sending, from/,
  'the lead must not price the two products apart again');

// One term for the free limit, on both pages a buyer reads in the same minute.
// /pricing said "2 signatures a month" and /signup said "sign 2 documents a
// month", which reads as two different products.
const signupVisible = read('frontend/signup.html').replace(/<!--[\s\S]*?-->/g, '');
for (const [label, html] of [['pricing.html', pricingVisible], ['signup.html', signupVisible]]) {
  assert.match(html, /2 signatures a month/,
    `${label} must name the free limit in the site's one term: "2 signatures a month"`);
  assert.doesNotMatch(html, /\d+ documents a month/,
    `${label} uses "documents a month" for the signature limit; the term is "2 signatures a month"`);
}
assert.doesNotMatch(signupVisible, /class="tier-card"|privacy and security researcher/,
  'signup.html must not carry tier tables or a founder block; it has already made the sale');

// One legal class for a ParaSign signature, site-wide. /about pins the wording;
// the pricing FAQ used to promise a higher class (AES), which is the single
// claim a law firm checks first, and it sat on the page where they pay.
assert.match(pricingVisible, /A ParaSign signature is a Simple Electronic Signature \(SES\) under eIDAS, not an advanced \(AES\) or a qualified \(QES\) signature\./,
  'pricing.html must state the same signature class as /about');
assert.doesNotMatch(pricingVisible, /Signatures are advanced \(AES\)/,
  'pricing.html must not claim a higher signature class than /about gives');
assert.match(about, /a Simple Electronic Signature \(SES\)/,
  'about.html must keep the SES wording the pricing FAQ is aligned to');

// Compliance is the customer's, not the tool's. The page said "all tiers meet
// NIS2 and GDPR requirements by design" a few hundred pixels above "Paramant
// itself holds no third-party certification for those frameworks".
assert.doesNotMatch(pricingVisible, /meet NIS2 and GDPR requirements by design/,
  'pricing.html must not promise compliance as a property of the product');
assert.match(pricingVisible, /The architecture is built to support your NIS2 and GDPR work\. Paramant itself holds no third-party certification for those frameworks\./,
  'pricing.html must say what the architecture does and what Paramant does not hold');

// Who is behind it, on the page where a buyer decides to upload client files.
// Mick, 4 September: the name and the title left this page. What has to stay is
// the party that is accountable, with the registration beside it;
// pricing-fold.test.mjs measures where that lands on a phone.
assert.match(pricingVisible, /Built in Harderwijk by <strong[^>]*>Paramantis Solutions B\.V\.<\/strong> \(KvK 42115132\)/,
  'pricing.html must name the company that is accountable, with its registration');
assert.doesNotMatch(pricingVisible, /Mick Beer/,
  'pricing.html must not name the founder in its body copy; /about and the homepage letter carry that');

// The free cards send a visitor to /signup. They used to send them to
// /dashboard, a page nobody without an account can open.
const freeCardCtas = [...pricingVisible.matchAll(/<div class="tier-name">Community<\/div>[\s\S]*?<a href="([^"]+)"[^>]*class="btn btn-primary"/g)].map((m) => m[1]);
assert.ok(freeCardCtas.length >= 2, 'pricing.html must still have Community cards with a primary action');
assert.deepEqual([...new Set(freeCardCtas)], ['/signup'],
  `the Community cards must send a visitor to /signup, not to a page they cannot open: ${freeCardCtas.join(', ')}`);

console.log('ui-truthfulness: /pricing says what it sells, with the number, above the tables');

console.log('ui-truthfulness: the homepage does not overclaim signatures and quotes the real prices');
console.log('ui-truthfulness: the free plan is Community everywhere and the founder line matches /about');
console.log('ui-truthfulness: the dashboard names the plans /pricing actually sells');
console.log('ui-truthfulness: the account page resolves plans from the same source and never upsells a customer');

// ── /docs and /help now answer a buyer, and quote pages instead of paraphrasing ─
// The messaging guide (docs/brand/messaging.md, section 10) allows a sentence on
// the site only when it already ships somewhere and a test fails when it stops
// shipping. These three answers were copied onto /help from /sign, /pricing and
// / (the rules grid). A copy drifts silently: the source page can be reworded
// and the copy keeps promising the old thing. So each assertion is a pair, the
// quote and the page it was quoted from, and the pair fails together.
//
// Every quote is matched inside the markup a visitor actually sees. An earlier
// version of this block asserted the docs buyer line against the whole file, and
// deleting the visible paragraph left the test green: the same words also sit in
// four meta tags. A pin that a meta description can satisfy pins nothing.
const docsHtml = read('frontend/docs.html');
const helpHtml = read('frontend/help/index.html');
const securityHtml = read('frontend/security.html');
const developerHtml = read('frontend/developer.html');
const homeGrid = read('frontend/index.html');
// Everything below </head>: the page a visitor reads, meta tags excluded. The
// sales-voice and key-location gates below run against this, not against the
// three answers alone, so a slogan cannot slip back in through the lede, an
// article card or the footer.
const helpBody = helpHtml.slice(helpHtml.indexOf('</head>'));
// The three answers on /help, without their surrounding page.
const helpAnswers = [...helpHtml.matchAll(/<p class="buyer-qa-a">([\s\S]*?)<\/p>/g)].map((m) => m[1]).join('\n');
assert.equal(helpAnswers.split('\n').length, 3,
  'help/index.html must keep the three buyer answers in the "Asked most often" block');

// /docs is where an evaluating buyer sends their IT, and it must say so before
// it starts talking about pip install. It absorbed traffic that belonged on
// /pricing, so it also has to name the price boundary of the API once, and it
// gives the buyer a button of the same weight as the developer's Quick start.
assert.match(docsHtml, /<p class="docs-buyer">Evaluating Paramant\? Your IT can check everything here\./,
  'docs.html must open with the visible line that tells a buyer what this page is for');
assert.match(docsHtml, /<p class="lede">[^<]*The ParaSign API is available from Firm/,
  'docs.html must state in the visible lede which plan the ParaSign API needs');
const docsActions = (docsHtml.match(/<div class="docs-hero-actions">[\s\S]*?<\/div>/) || [''])[0];
assert.match(docsActions, /<a href="#quickstart" class="docs-hero-btn docs-hero-btn-primary">/,
  'the developer keeps the primary button on /docs: Quick start');
assert.match(docsActions, /<a href="\/pricing" class="docs-hero-btn docs-hero-btn-secondary">/,
  'the buyer gets a real button to /pricing beside it, not only a text link');
assert.match(developerHtml, /<p class="lede">[^<]*(?:<a[^>]*>[^<]*<\/a>[^<]*)*API access is included from Firm/,
  'developer.html must state in its visible lede which plan the ParaSign API needs');
// /developer is noindex and only reachable once signed in, so it addresses the
// developer reading it, never the buyer who sent them.
assert.doesNotMatch(developerHtml, /your IT can check/i,
  'developer.html talks to the developer on the screen, not to their buyer');
// Both plan lines are only true while /pricing sells API access on Firm.
assert.match(pricing, /<li>API access<\/li>/,
  'pricing.html must still list API access on the Firm tier');

// Answer 1: signing without an account. Quoted from /sign, which is pinned above.
assert.match(helpAnswers, /Signing a document needs an account/i,
  'help/index.html must answer whether an account is required');
assert.match(helpAnswers, /open a signing request someone sent you/i,
  'help/index.html must say what an invited signer can do without an account');

// Answer 2: cost. A support page that will not name a number sends someone back
// to the search box, so /help names the free allowance and the first paid price
// exactly as /pricing prints them, and both halves are pinned to that page.
// Scoped to the ParaSign grid: /help names "ParaSign Community" and quotes its
// allowance, and pricing.html carries a second Community card for ParaSend. A
// bare match on the tier name stays green while the ParaSign one is renamed.
const parasignGrid = pricing.slice(pricing.indexOf('<!-- TIER CARDS: PARASIGN -->'));
assert.ok(parasignGrid.length > 0 && parasignGrid.length < pricing.length,
  'pricing.html must keep the ParaSign tier grid this block reads from');
assert.match(parasignGrid, /<div class="tier-name">Community<\/div>[\s\S]{0,400}?<li>2 signatures a month<\/li>/,
  'pricing.html is the source of the ParaSign Community allowance quoted on /help');
assert.match(pricing, /&euro;29<span/,
  'pricing.html is the source of the Firm price quoted on /help');
assert.match(pricing, /charged &euro;35\.09\/mo incl\. 21% btw/,
  'pricing.html is the source of the incl. btw figure quoted on /help');
assert.match(helpAnswers, /ParaSign Community is free, forever, and no card is required\. It covers 2 signatures a month\./,
  'help/index.html must name the free allowance, not just promise that free exists');
assert.match(helpAnswers, /Firm at &euro;29 a month excl\. btw \(&euro;35\.09 incl\.\)/,
  'help/index.html must name the first paid price the way /pricing prints it');
// Proof 3 of the messaging guide, quoted from /pricing. The slogan that follows
// it there ("Pay for volume, never for security") stays on the page that sells;
// /help is support voice and an unverifiable sales line is the last thing
// someone stuck on this page needs.
assert.match(pricing, /Every plan gets the same encryption, the same post-quantum signatures and the same public proof log\. Pay for volume, never for security\./,
  'pricing.html must keep the sentence the free-versus-paid split rests on');
assert.match(helpAnswers, /Every plan gets the same encryption, the same post-quantum signatures and the same public proof log\./,
  'help/index.html must quote the same-crypto fact, not paraphrase it');
assert.doesNotMatch(helpBody, /Pay for volume, never for security/,
  'help/index.html must not carry the sales line anywhere in the body; it is a support page');

// Answer 3: where the data lives. Three sentences a person can read, not the
// Jurisdiction and privacy table flattened into prose. The claim is scoped to
// the data path and names the Resend exception in the same breath, exactly as
// proof 1 of the messaging guide requires. The unqualified "no US company" row
// on /security is an open contradiction (guide section 9) and is deliberately
// not repeated here.
assert.match(securityHtml, /Hetzner Nuremberg, Germany/,
  'security.html must keep the server location row /help quotes');
assert.match(homeGrid, /No US provider in the data path\. Email goes out via Resend, as <a href="\/privacy">\/privacy<\/a> sets out\./,
  'index.html is the source of the data-path wording and its Resend exception');
assert.match(helpAnswers, /Your documents live on servers at Hetzner Nuremberg, Germany, and they sit there as ciphertext\./,
  'help/index.html must answer where the documents live, and say they are ciphertext there');
assert.match(helpAnswers, /no US provider is in the data path/,
  'help/index.html must scope the claim to the data path');
assert.match(helpAnswers, /Email goes out via Resend, as <a class="buyer-qa-inline" href="\/privacy">\/privacy<\/a> sets out\./,
  'help/index.html must name the Resend exception in the same breath, with the /privacy link');
assert.doesNotMatch(helpAnswers, /no US company/i,
  'help/index.html must not repeat the unqualified no-US-company row from /security');

// A private key never reaches a server, and the whole site says so: "Generated
// on your device, never sent" (index.html), "relay holds only ciphertext, never
// keys" and "No plaintext, no keys" (security.html), "we never hold decryption
// keys, anywhere" (trust.html), "The relay never sees plaintext and never holds
// a private key" (docs.html). An answer that puts keys in a rack in Nuremberg
// contradicts all five at once, and it is the sentence a security reviewer
// would quote back. So /help may name a key only in the negative: any sentence
// that mentions a key and a piece of infrastructure must be saying the key is
// not there.
assert.match(homeGrid, /Generated on your device, never sent/,
  'index.html is the source of the promise that a key never reaches a server');
assert.match(securityHtml, /relay holds only ciphertext, never keys/,
  'security.html is the source of the promise that the relay holds no keys');
assert.match(docsHtml, /The relay never sees plaintext and never holds a private key\./,
  'docs.html is the source of the sentence /help quotes about plaintext and keys');
assert.match(helpAnswers, /The relay never sees plaintext and never holds a private key\./,
  'help/index.html must say where the keys are not, in the words docs.html uses');
for (const sentence of helpBody.replace(/<[^>]+>/g, ' ').split(/(?<=[.!?])\s+/)) {
  if (!/\bkeys?\b/i.test(sentence)) continue;
  if (!/\b(server|servers|relay|Hetzner|Nuremberg|hosted|infrastructure|data centre|data center)\b/i.test(sentence)) continue;
  assert.match(sentence, /\bnever\b|\bno\b|\bnot\b/i,
    `help/index.html puts a key on infrastructure without denying it: "${sentence.trim()}"`);
  assert.doesNotMatch(sentence, /\bkeys?\b[^.]{0,60}?\b(?:live|sit|reside|are stored|are kept|are held|stay)\b/i,
    `help/index.html must not say a key lives on a server: "${sentence.trim()}"`);
  assert.doesNotMatch(sentence, /\b(?:live|sit|reside|stored|kept|held)\b[^.]{0,60}?\bkeys?\b/i,
    `help/index.html must not say a server holds a key: "${sentence.trim()}"`);
}

// No sales voice on a support page. Someone here has already signed up.
assert.doesNotMatch(helpBody, /revolutionary|seamless|cutting-edge|enterprise-grade|military-grade|trusted by|world-class/i,
  'help/index.html must stay in support voice');

// The tone rule is site-wide, but these two articles kept em-dashes in the H1
// and the tab title after an earlier pass cleaned only their ledes.
for (const slug of ['index', 'api-key-vs-totp', 'lost-authenticator']) {
  const html = read(`frontend/help/${slug}.html`);
  assert.doesNotMatch(html, /\u2014|&mdash;|\u2013|&ndash;/,
    `help/${slug}.html must carry no em-dash or en-dash, in the H1, the title or anywhere else`);
}
assert.doesNotMatch(docsHtml, /\u2014|&mdash;|\u2013|&ndash;/,
  'docs.html must carry no em-dash or en-dash');

console.log('ui-truthfulness: /docs and /help answer a buyer with sentences that ship elsewhere');

// ── The messaging guide, pinned ──────────────────────────────────────────────
// docs/brand/messaging.md (PR #331) settles what the commercial pages promise
// and in what order. Section 10 of that guide is the rule this block enforces:
// a sentence may only go on the site if it is already true on the site or in
// the code, and there is a test that fails when it stops being true. Every
// string below is quoted from a page that ships, and the guide names each of
// them as work to pin. Where the guide flagged a claim as disputed (rule 04's
// "no US provider in the chain", section 9) the claim is NOT asserted
// here and does not appear on the product pages; only the /security row it
// rests on is.
// A claim is what a visitor reads, not how the markup happens to be wrapped.
// The same sentence sits on one line in parasign.html and across three lines
// with a <strong> in the middle in pricing.html, so comparing raw HTML would
// pin the formatting instead of the promise. Comments, style and script are
// dropped for the same reason ui-truthfulness already drops them on sign.html:
// a comment routinely quotes the very wording it exists to forbid.
function visible0(html) {
  return html
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<(style|script)\b[\s\S]*?<\/\1>/gi, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/&middot;/g, '\u00b7').replace(/&euro;/g, '\u20ac')
    .replace(/&amp;/g, '&').replace(/&nbsp;/g, ' ').replace(/&rarr;/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}
const visible = (file) => visible0(read(file));
// The plan limits are read from the code that enforces them, not from another
// page. tiers.js is the single source; relay.js turns its rows into a 402 and a
// 413. Comparing two pages only proves they agree, and both were wrong together.
const { default: tiers } = await import('../relay/lib/tiers.js');
const parasign = visible('frontend/parasign.html');
const parasend = visible('frontend/parasend.html');
const aboutVisible = visible('frontend/about.html');
// pricingVisible above is the same page as markup; this is its plain text.
const pricingText = visible('frontend/pricing.html');
const security = visible('frontend/security.html');
const signVisibleText = visible('frontend/sign.html');

// Proof 1. The EU claim is about the data path, not the whole chain, and the
// Resend exception travels with it. A page may shorten the long form on
// /rules to this one; it may never drop the second half.
const EU_CLAIM = 'Hetzner Germany, Bunny DNS (Slovenia). No US provider in the data path.';
const EU_EXCEPTION = 'Email goes out via Resend';
const homeVisible = visible('frontend/index.html');
for (const [name, text] of [['index', homeVisible], ['parasign', parasign], ['parasend', parasend]]) {
  assert.ok(text.includes(EU_CLAIM), `${name}.html lost the data-path wording of the EU claim`);
  assert.ok(text.includes(EU_EXCEPTION), `${name}.html states the EU claim without naming the Resend exception`);
}
// And it may not be offered against a source that does not carry it. The
// Jurisdiction and privacy table on /security lists Hetzner Nuremberg, the legal
// jurisdiction, the CLOUD Act row, retention, IP logging and analytics. Bunny is
// not in it, and DNS is not a row. A page that names Bunny and then sends the
// reader to that table has offered a checkpoint that fails when checked.
const securityJurisdiction = (read('frontend/security.html')
  .match(/<h2[^>]*>Jurisdiction[\s\S]*?<\/table>/) || [''])[0];
assert.ok(securityJurisdiction, 'security.html must keep its Jurisdiction and privacy table');
assert.ok(!/Bunny/i.test(securityJurisdiction),
  'the /security jurisdiction table now names Bunny; the product pages may point at it again');
for (const [name, text] of [['parasign', parasign], ['parasend', parasend]]) {
  assert.doesNotMatch(text, /Bunny DNS[^.]*\.[^.]*\.[^.]*\.[^.]*jurisdiction table is on the/,
    `${name}.html sends the reader to the /security jurisdiction table for a claim that table does not carry`);
}
// The broader claim is the one section 9 of the guide holds open. It may stay
// on /security, where the table qualifies it, and nowhere near a product hero.
for (const [name, text] of [['parasign', parasign], ['parasend', parasend]]) {
  assert.doesNotMatch(text, /no US (company|provider) in the chain|no US company\b/i,
    `${name}.html claims more than the data path, which /privacy does not support`);
}
// The row used to read "Not applicable: no US infrastructure, no US company",
// and this assertion pinned it, because /security was the one page where the
// table qualified the broader claim. Section 9.2 of the guide names that row
// as the one that has to move to the data-path wording in its own PR with its
// own test. This is that PR. What proof 1 is measured against on /security is
// now the same sentence / and /rules carry, with its Resend exception; the
// window check that keeps the two together lives further down this file.
assert.ok(!/no US company/i.test(security),
  'security.html must no longer claim "no US company", which is broader than /privacy supports');
assert.ok(security.includes('No US provider in the data path'),
  'security.html must carry proof 1 in the data-path wording the guide fixes');

// ── "Why Dutch matters", 5 September ────────────────────────────────────────
// Mick: "the pride in being Dutch is missing, it is too well behaved". The
// homepage now argues the ownership case instead of only stating it, and this
// block is the pin on the three claims that carry it. Each one is checkable:
// the KvK number and the governing-law clause are in this repository, the
// acquisitions are external and carry their sources on the page itself, and the
// data-path line is proof 1 in its own words with the Resend exception beside
// it. The row in docs/site-claims.md records the external half as UNCOVERED,
// which is the same footing the competitor facts on /vs stand on.
// 5 September, Mick: the band now carries a Dutch tile instead of the English
// ownership line. The proverb is the eye-catcher and claims nothing; the line
// under it is the checkable half and is the same server location /privacy,
// /security and the DPA name. One Dutch sentence on an English page is his
// choice, not a slip, and this is not a translation round: no other page moved.
const bandSay = (read('frontend/index.html').match(/<span class="hp-band-say">([\s\S]*?)<\/span>/) || [, ''])[1];
const bandSub = (read('frontend/index.html').match(/<span class="hp-band-sub">([\s\S]*?)<\/span>/) || [, ''])[1];
assert.equal(bandSay, 'Beter een goede buur dan een verre vriend.',
  'index.html: the band tile is the one line above the fold that carries the tone; change it deliberately, and update tests/first-screen with it');
assert.equal(bandSub, 'Onze servers staan in Neurenberg.',
  'index.html: the line under the tile is the checkable half and must keep naming the city /privacy and the DPA name');
const whyNl = visible0((read('frontend/index.html').match(/<section class="hp-sec why-nl-sec"[\s\S]*?<\/section>/) || [''])[0]);
assert.ok(whyNl, 'index.html must keep the "Why Dutch matters" section');
for (const claim of [
  // The ownership facts. Sourced on the page, not in the code, so the wording is
  // pinned here and the sources line is required to travel with it.
  'The parent of WeTransfer has been Bending Spoons in Milan since July 2024.',
  'Zivver has been part of Kiteworks in California since June 2025.',
  'Signhost went to Entrust in 2022, SignRequest to Box in 2021, and QuoVadis is on the Dutch trust list today as DigiCert Europe Netherlands.',
  // Who owns Paramant. The number is the one every other page carries.
  'Paramantis Solutions B.V., Harderwijk, KvK 42115132, with no parent company anywhere else.',
  'Dutch law governs the terms you agree to, and a Dutch court hears the dispute.',
  // Proof 1, in this section\u2019s own words, with the exception in the same breath.
  'No US provider is in the data path.',
  'The one exception is transactional email, which goes out through Resend, an American company: it receives the address and the invite link, never the document.',
  // The sentence that carries the pride. It claims nothing a reader cannot check.
  'We are Dutch, and we would rather say so than hide behind a Delaware address.',
]) {
  assert.ok(whyNl.includes(claim), `index.html: "Why Dutch matters" lost the line: ${claim}`);
}
assert.ok(/Ownership sources: .*Checked 3 September 2026\./.test(whyNl),
  'index.html: the ownership facts are external, so the sources line and its check date must stay with them');
// terms.html \u00a713 is what "Dutch law governs the terms" points at.
assert.match(read('frontend/terms.html'), /<h2 id="law">/,
  'terms.html must keep the #law anchor the homepage sends the reader to');
assert.match(read('frontend/terms.html'), /Dutch law applies\. Disputes go to the competent court in the district where Paramantis Solutions B\.V\. is established/,
  'terms.html must keep the governing-law sentence the homepage summarises');
// /security carries the same claim once, above the table where it is checked.
// It deliberately avoids the exact "No US provider in the data path" wording, so
// the window check above still measures the two occurrences it was written for.
assert.match(read('frontend/security.html'), /A Dutch company owns this: Paramantis Solutions B\.V\. in Harderwijk, KvK 42115132\./,
  'security.html must name the owner above the jurisdiction table');
// /pricing: who takes the money is part of the same answer. Mollie B.V. is the
// Netherlands row in the /dpa sub-processor table, so this is not a new claim.
const pricingPay = read('frontend/pricing.html');
assert.match(pricingPay, /You pay a Dutch company, in euros, through a Dutch payment provider \(Mollie\)\./,
  'pricing.html must say who is paid and where they sit, in the payment paragraph');
assert.match(read('frontend/dpa.html'), /<td>Mollie B\.V\.<\/td><td>Netherlands \(EU\)<\/td>/,
  'the /pricing line rests on the /dpa row that puts Mollie B.V. in the Netherlands');
console.log('ui-truthfulness: the homepage argues the Dutch case with facts it can source');

// Proof 2. The three /about sentences the signing claim rests on.
for (const claim of [
  'ML-DSA-65 (FIPS 204), generated in your browser. The private key never reaches the relay.',
  'Every signature is entered into a public, append-only log.',
  'A signed document verifies without contacting us.',
]) {
  assert.ok(aboutVisible.includes(claim), `about.html lost the signing claim: ${claim}`);
  assert.ok(parasign.includes(claim), `parasign.html lost the signing claim: ${claim}`);
}

// Proof 3. The sentence the whole free-versus-paid split rests on. If the
// pricing model ever gates cryptography behind a tier, this is what fails first.
const SPLIT = 'Every plan gets the same encryption, the same post-quantum signatures and the same public proof log. Pay for volume, never for security. And pay per organisation, not per user.';
for (const [name, text] of [['pricing', pricingText], ['parasign', parasign], ['parasend', parasend]]) {
  assert.ok(text.includes(SPLIT), `${name}.html lost the pay-for-volume sentence`);
}
// The other half of the split: the free plan is permanent, it is called
// Community, and the reason it stays free is named in the same sentence.
const FREE_FOREVER = 'not to unlock features, and that is what keeps the Community plan free';
for (const [name, text] of [['pricing', pricingText], ['parasign', parasign], ['parasend', parasend]]) {
  assert.ok(text.includes(FREE_FOREVER), `${name}.html lost the Community-plan promise`);
}
// /sign carries the same split in one line, next to the account requirement,
// and it names the plan the way /pricing names it.
assert.match(signVisibleText, /Community accounts sign 2 documents a month/,
  'sign.html must keep the free-tier line, under the plan name /pricing uses');
assert.doesNotMatch(signVisibleText, /\bFree accounts\b|tier named Free|the tier is called Free/,
  'sign.html must not call the Community plan Free; one name across the site');

// The founder, with the exact title and nothing added to it. No award, no year
// count, no prior employer, no certification: none of that is on the site.
// Mick, 4 September: one note is enough, so /about is the only page that still
// carries the line. The product pages name the company instead.
const FOUNDER = 'Mick Beer, privacy and security researcher';
assert.ok(aboutVisible.includes(FOUNDER), 'about.html must name the founder with his exact title');
for (const [name, text] of [['parasign', parasign], ['parasend', parasend]]) {
  assert.ok(!text.includes('Mick Beer'),
    `${name}.html must not name the founder in its body copy; /about carries that line`);
  assert.ok(text.includes('Paramantis Solutions B.V.'),
    `${name}.html must still name the company that is accountable`);
}

// Sentence three of the founder paragraph. It was the one claim on these pages
// with no source on main; #332 put it on /about, so it is now quoted rather
// than composed, and it is pinned to both ends of the quote.
const GIVE_BACK = 'The Community plan is his way of giving something back to society; the business plans pay for it.';
assert.ok(aboutVisible.includes(GIVE_BACK), 'about.html lost the give-back sentence the product pages quote');
// Mick, 4 September: parasend states the same promise without the person, since
// "his" has nothing to point at once the name is gone.
assert.ok(parasend.includes('The Community plan is free and stays free; the business plans pay for the servers and keep it that way.'),
  'parasend.html must keep the promise that the free plan stays free and say what pays for it');

// The limits, stated in the same voice as the promises. Both already shipped
// before the product pages existed and neither may be softened or moved into
// small print.
const SES = 'A ParaSign signature is a Simple Electronic Signature (SES): an ML-DSA-65 cryptographic attestation produced in your browser. It is not a notarised legal signature under eIDAS or any qualified-trust regime (QES).';
assert.ok(aboutVisible.includes(SES), 'about.html lost the SES scope note');
assert.ok(parasign.includes(SES), 'parasign.html must carry the SES scope note, not a softer version');
// Where it sits is part of the claim. The note has to land in the hero section,
// before the first band of the page, or it is a footnote with a test on it.
const parasignHero = read('frontend/parasign.html').split('<section class="ps-band"')[0];
assert.ok(visible0(parasignHero).includes(SES),
  'the SES scope note must sit in the first screen of /parasign, not below the tiers');
assert.ok(visible0(parasignHero).includes('legal, finance and healthcare practices in the EU'),
  '/parasign must name who it is for in the first screen');
assert.ok(visible0(parasignHero).includes(`${tiers.tierLimit('community', 'signs_month')} signatures a month`),
  'the free promise in the /parasign hero must carry the number tiers.js enforces');
const parasendHero = read('frontend/parasend.html').split('<section class="ps-band"')[0];
const communityHeroFacts = [
  `${tiers.tierLimit('community', 'transfers_month')} transfers a month`,
  `${tiers.tierLimit('community', 'file_mb')} MB a file`,
  `links that last an hour`,
  `gone after one read`,
];
for (const fact of communityHeroFacts) {
  assert.ok(visible0(parasendHero).includes(fact),
    `the free promise in the /parasend hero must carry the limit tiers.js enforces: ${fact}`);
}
assert.ok(tiers.tierLimit('community', 'view_ttl_ms') === 3_600_000 && tiers.tierLimit('community', 'max_views') === 1,
  'the one-hour, one-read wording in the /parasend hero no longer matches tiers.js');
assert.doesNotMatch(visible0(parasendHero), /uploads (per|an) hour/i,
  'the /parasend hero states the deprecated anon-endpoint rate as if it were a plan limit');
assert.ok(visible0(parasendHero).includes('For offices that email client documents'),
  '/parasend must name who it is for in the first screen');

const NO_CERT = 'Paramant does not hold third-party certification for these frameworks.';
assert.ok(pricing.includes(NO_CERT), 'pricing.html lost the certification limit');
assert.ok(parasend.includes(NO_CERT), 'parasend.html quotes the compliance documentation, so it must carry its limit');

// A product page must not claim the identity or legal effect that /sign is
// already forbidden from claiming. Same overclaim, wider surface.
for (const [name, text] of [['parasign', parasign], ['parasend', parasend]]) {
  assert.doesNotMatch(text, /identity verified|verified signer|signer verified|legally binding/i,
    `${name}.html must not claim a verified identity or legal effect it cannot deliver`);
}

// ── A claim may not be contradicted by the page it cites ─────────────────────
//
// /parasend promised "ML-DSA-65 signed receipts" for ParaShare and linked to the
// algorithm register in the same sentence. That register lists ParaShare
// (webapp) with SIG n/a on the pre-v1 hybrid wire, migrating to v1; ML-DSA-65 is
// the SDK rows. The register is the source, so it is read here and the page is
// held to what it says.
const registerRow = (label) => {
  const rows = read('frontend/crypto-agility.html').match(/<tr>[\s\S]*?<\/tr>/g) || [];
  const row = rows.find((r) => r.includes(label));
  return row ? [...row.matchAll(/<td[^>]*>([\s\S]*?)<\/td>/g)].map((m) => m[1].replace(/<[^>]+>/g, '').trim()) : null;
};
const shareRow = registerRow('ParaShare (webapp)');
assert.ok(shareRow && shareRow.length >= 4, 'crypto-agility.html no longer registers ParaShare (webapp)');
const [, shareKem, shareSig, shareWire] = shareRow;
assert.equal(shareKem, 'ML-KEM-768 + ECDH P-256', 'the ParaShare KEM in the register changed; /parasend quotes it');

// These used to sit inside `if (shareSig === 'n/a')`, which made the register
// the only thing under test: move the webapp to ML-DSA-65 in the register and
// the guard simply stopped running, so /parasend and /pricing could go on
// saying "signature n/a" and "no default signature algorithm" with nothing red.
// The check now runs on whatever the SIG column holds and works in both
// directions: the register's value has to be what the pages say, and a value
// this test has no wording for fails loudly instead of passing quietly.
// In its own scope: two parallel PRs each adding a top-level const under one
// name is what stopped this file parsing on main, so nothing here reaches it.
(function registerSignatureWording() {
  const SIG_ON_PAGE = {
    'n/a': { parasend: 'signature n/a', pricing: 'no default signature algorithm' },
    'ML-DSA-65': { parasend: 'signature ML-DSA-65', pricing: 'ML-DSA-65 as its default signature algorithm' },
  };
  const wanted = SIG_ON_PAGE[shareSig];
  assert.ok(wanted,
    `crypto-agility.html now gives ParaShare (webapp) SIG "${shareSig}". /parasend and /pricing both ` +
    `describe that column in words, and this test has no wording for the new value, so update both ` +
    `pages and SIG_ON_PAGE together.`);
  assert.ok(parasend.includes(wanted.parasend),
    `the register gives ParaShare (webapp) SIG "${shareSig}", so /parasend must say "${wanted.parasend}"`);
  assert.ok(pricing.includes(wanted.pricing),
    `the register gives ParaShare (webapp) SIG "${shareSig}", so /pricing must say "${wanted.pricing}"`);
  // The other direction: no page may carry the wording for a SIG the register
  // does not give the webapp.
  for (const [sig, wording] of Object.entries(SIG_ON_PAGE)) {
    if (sig === shareSig) continue;
    assert.ok(!parasend.includes(wording.parasend),
      `/parasend describes ParaShare as "${wording.parasend}" while the register says "${shareSig}"`);
    assert.ok(!pricing.includes(wording.pricing),
      `/pricing describes ParaShare as "${wording.pricing}" while the register says "${shareSig}"`);
  }
})();
assert.ok(parasend.includes(`the webapp on the ${shareWire} wire`),
  '/parasend must state the wire format the register gives the webapp, not a better one');
if (shareSig !== 'ML-DSA-65') {
  assert.doesNotMatch(parasend, /ParaShare[^.]*ML-DSA-65 signed receipts/,
    'the register gives ParaShare no signature, so /parasend may not sell it ML-DSA-65 signed receipts');
}
assert.doesNotMatch(parasend, /proof that the file came from you/,
  '/parasend may not promise sender proof on a path the register gives no signature');

// Tone, section 6 of the guide. We have no testimonials, no customer logos and
// no user counts, so no page may imply them, and the marketing vocabulary the
// guide bans stays banned by test rather than by good intentions. One word
// from that list is absent here on purpose: "unlock" appears in the /pricing
// sentence these pages quote ("not to unlock features"), so banning it would
// fail on shipped copy the guide itself pins.
const BANNED = /revolutionary|seamless|cutting-edge|enterprise-grade|military-grade|trusted by|world-class|effortless|next-generation|empower|journey/i;
for (const [name, text] of [['parasign', parasign], ['parasend', parasend]]) {
  assert.doesNotMatch(text, BANNED, `${name}.html uses vocabulary the messaging guide bans`);
}

console.log('ui-truthfulness: the messaging guide claims are pinned to the pages that make them true');

// Everything below runs inside its own scope. Four PRs merged into this file
// in parallel on 2 September and two of them collided on a top-level const
// (tiers, pricingVisible), which is a SyntaxError: not one assertion in the
// file runs, on any branch. A block that declares nothing at module level
// cannot do that to the next branch.
{
  // ── The pages that carry the promise: /about, /security, /trust ─────────────
  // The messaging guide (docs/brand/messaging.md) allows a sentence on the site
  // only if it already ships and a test fails when it stops shipping. These are
  // the sentences the buyer-facing copy on /about and /security now rests on.
  // Every one of them was already on a page before this file pinned it; nothing
  // here was written for marketing.
  const securityRaw = read('frontend/security.html');
  const trustRaw = read('frontend/trust.html');

  // The founder. Name and title are the only ones the site can support, so they
  // are pinned as one string: no award, no year count, no prior employer.
  assert.match(about, /Mick Beer/,
    'about.html must name the founder');
  assert.match(about, /Privacy and security researcher, founder of Paramantis Solutions B\.V\./i,
    'about.html must carry the exact founder title, and no other qualification');
  assert.match(about, /founded by Mick Beer, privacy and security researcher/,
    'about.html must keep the founder sentence it has shipped with');
  assert.match(about, /Paramantis Solutions B\.V\. is the contracting and responsible party/,
    'about.html must keep saying the company, not the person, is the responsible party');

  // Proof 2 of the guide: the key stays with the signer and the proof outlives
  // us. These three sentences are what /security now points at as evidence.
  assert.match(about, /ML-DSA-65 \(FIPS 204\), generated in your browser\. The private key never reaches the relay\./,
    'about.html must keep the private-key sentence');
  assert.match(about, /Every signature is entered into a public, append-only log\./,
    'about.html must keep the transparency-log sentence');
  assert.match(about, /A signed document verifies without contacting us\./,
    'about.html must keep the offline-verification sentence');

  // The eIDAS limit. It is the sentence a lawyer reads to decide whether the rest
  // of the page is measured, so it may never be softened or moved to a footnote.
  // It is pinned on /about only. /about calls a ParaSign signature a Simple
  // Electronic Signature, the /pricing FAQ calls it advanced (AES), and those are
  // different levels under eIDAS. Until that is settled in its own round, the
  // wording stays on the one page that has always carried it and is not copied
  // onto a second one.
  assert.match(about, /Simple Electronic Signature \(SES\)/,
    'about.html must state that a ParaSign signature is a Simple Electronic Signature');
  assert.match(about, /not a notarised legal signature under eIDAS or any qualified-trust regime \(QES\)/,
    'about.html must state what the signature is not');
  assert.doesNotMatch(securityRaw, /Simple Electronic Signature|advanced \(AES\)/,
    'security.html must not carry a second, competing eIDAS level while /about and /pricing disagree');
  assert.doesNotMatch(about + securityRaw, /qualified electronic signature|legally binding|eIDAS-certified/i,
    '/about and /security must not claim a qualified signature or legal effect');

  // Proof 3: the same cryptography on every plan. This is the sentence the whole
  // free-versus-paid split rests on. If cryptography is ever gated behind a tier,
  // this is the assertion that must fail first.
  const SAME_CRYPTO = /Every plan gets the same encryption, the same post-quantum signatures and the same public proof log\. Pay for volume, never for security\. And pay per organisation, not per user\./;
  assert.match(pricing, SAME_CRYPTO, 'pricing.html must keep the same-crypto-every-plan sentence');
  assert.match(securityRaw, SAME_CRYPTO, 'security.html must keep the same-crypto-every-plan sentence');

  // Proof 1: EU jurisdiction. /security is where the buyer checks it, so the row
  // and the claim above it have to agree.
  assert.match(securityRaw, /Hetzner Nuremberg, Germany/,
    'security.html must name the server location');
  // The old row read "Not applicable: no US infrastructure, no US company",
  // which is broader than /privacy allows: transactional email goes out through
  // Resend, a US provider. The guide (section 9.2) says that row is the one that
  // has to move to the data-path wording, and it may never be written without
  // its one exception in the same breath.
  assert.match(securityRaw, /No US provider in the data path/,
    'security.html must state the jurisdiction claim about the data path, not about the whole chain');
  assert.doesNotMatch(securityRaw, /no US company\b(?![^<]*Resend)/,
    'security.html must not claim "no US company" without naming the Resend exception beside it');
  // "In the same breath" is the whole point of the wording, so it is measured
  // as a window and not as "somewhere on the page": an earlier version of this
  // check let a card drop Resend entirely, because the jurisdiction table lower
  // down still carried the word.
  const WINDOW = 420;
  for (const [label, html] of [['security.html', securityRaw]]) {
    let at = -1, seen = 0;
    while ((at = html.indexOf('No US provider in the data path', at + 1)) !== -1) {
      seen += 1;
      assert.match(html.slice(at, at + WINDOW), /Resend/,
        `${label} states the data-path claim without naming the Resend exception within ${WINDOW} characters of it`);
    }
    assert.ok(seen >= 2,
      `${label} must carry the data-path wording in both the card and the jurisdiction row, found ${seen}`);
  }

  // The certification limit, stated in the same voice as the proofs.
  assert.match(securityRaw, /Paramant does not hold third-party certification for these frameworks\./,
    'security.html must state that the compliance material is not a certification');
  assert.match(pricing, /Paramant does not hold third-party certification for these frameworks\./,
    'pricing.html must keep the certification limit it has shipped with');

  // House style on the commercial pages, from the messaging guide: no marketing
  // words we cannot back, no invented social proof, no em-dashes.
  const commercial = about + securityRaw + trustRaw;
  assert.doesNotMatch(commercial, /revolutionary|seamless|cutting-edge|military-grade|enterprise-grade|world-class|next-generation|effortless|trusted by \d/i,
    'the commercial pages must not use the banned marketing vocabulary');
  assert.doesNotMatch(commercial, /\u2014/,
    'the commercial pages must not use em-dashes (U+2014)');

  console.log('ui-truthfulness: /about, /security and /trust say only what the site can back');


  // The first screen of each page. The complaint that sent this work back was
  // that a buyer reaches the bottom of a phone screen without knowing what is
  // sold, who sells it, or what to do next. These assert that the answers are in
  // the markup before the first section heading, not a screen and a half down.
  const aboveFold = (html) => html.slice(0, html.indexOf('<!-- WHAT PARAMANT IS -->') + 1 || html.length);
  const aboutHero = aboveFold(about);
  assert.match(aboutHero, /Sign and send documents so that only you and the person you send them to can read them/,
    'about.html must open in plain language, before the word post-quantum');
  assert.match(aboutHero, /For small offices that sign and send confidential papers/,
    'about.html must say who it is for in the hero');
  assert.match(aboutHero, /Mick Beer/, 'about.html must name the founder in the hero');
  assert.match(aboutHero, /Privacy and security researcher, founder of Paramantis Solutions B\.V\./,
    'about.html must carry the founder title in the hero');
  assert.match(aboutHero, /href="\/pricing" class="btn btn-primary"/,
    'about.html must offer a next step in the hero');
  // Nobody can promise ten years. The lede used to end on "the cryptography is
  // post-quantum, which is the proof that it still holds up in ten years", which
  // is not a proof and not checkable, on the page whose whole argument is that
  // everything on it is checkable.
  assert.doesNotMatch(about, /holds up in ten years|proof that it still holds/i,
    'about.html must not promise how long the cryptography holds; nothing on the site backs it');
  // The give-back sentence, in the exact words the messaging guide fixes for it
  // (section 5, sentence three of the founder paragraph). It is the split the
  // whole site is built on, and it is quoted, not paraphrased.
  assert.match(about, /The Community plan is his way of giving something back to society; the business plans pay for it\./,
    'about.html must carry the give-back sentence in the words docs/brand/messaging.md fixes');
  // The earlier draft explained the free plan with a jurisdiction claim ("should
  // not depend on a US subscription"). The guide forbids that beside his name:
  // the jurisdiction claim is proof 1 and needs its Resend exception with it.
  assert.doesNotMatch(about, /US subscription/i,
    'about.html must not hang the jurisdiction claim off the founder paragraph');

  // The section number must not land under the H1 on a phone, where it reads as
  // a stray "00".
  assert.match(about, /#main-content \.sec-head \.num\{display:none\}/,
    'about.html must hide the section number in the mobile hero override');

  // /security: the first screen. The buttons used to sit at roughly y=11400 on a
  // 390px phone, fourteen screens down, and the page never said who was behind
  // it. Sliced at the first <main>, so a next step that drifts below the hero
  // fails here.
  const heroOf = (html) => html.slice(html.indexOf('<section class="page-hero'), html.indexOf('<main'));
  const securityHero = heroOf(securityRaw);
  assert.match(securityHero, /href="\/pricing" class="btn btn-primary"/,
    'security.html must offer a next step in the first screen, not only at the foot of the page');
  assert.match(securityHero, /href="\/verify" class="btn btn-secondary"/,
    'security.html must offer the verify step in the first screen');
  // Mick, 4 September: the founder line left this page. Who is accountable is
  // the company, where it sits and its registration, and that has to stay.
  assert.match(securityHero, /Paramantis Solutions B\.V\. in Harderwijk, the Netherlands, KvK 42115132/,
    'security.html says "why you can trust us", so it must name who that is, under the lede');

  // The hero promise is bounded where the code is bounded. It used to read "Even
  // if our own server is broken into, nobody can read your documents" flat out,
  // while ten screens lower the page says the Chromium and Outlook extensions
  // take a server-side encryption path. For an extension user the flat version
  // is untrue today, so the exception travels with the promise.
  assert.match(securityHero, /That holds for the ParaSend web app and the official SDKs\./,
    'security.html must scope the zero-knowledge promise in the hero');
  assert.match(securityHero, /The Chromium and Outlook extensions still encrypt on our server/,
    'security.html must name the extension exception in the same breath as the promise');
  // And say what that costs the reader. "Treat those uploads as relay-side" is
  // the internal word for it, and it tells someone who does not already know
  // what a relay is precisely nothing.
  assert.match(securityHero, /which means we can read what you upload through them until that is changed/,
    'security.html must say in plain words what the extension exception means: we can read those uploads');
  // The claim this round makes about itself: relay does not appear above the
  // fold undefined. Asserted rather than asserted-in-the-PR-text. The same word
  // is fine lower down, where the page defines it.
  assert.doesNotMatch(securityHero, /\brelay\b/i,
    'security.html must not use "relay" in the first screen; it is undefined there');

  assert.doesNotMatch(securityHero, /nobody can read your documents: they are encrypted on your device before they leave it, and the key never reaches us\. This page shows/,
    'the unqualified version of the promise must not come back');

  // /security promises "who audited it" in the hero and the meta description says
  // "independent audit". Both have to resolve on the page itself: /architecture
  // points back here for the audit material, so a pointer there is a loop.
  assert.match(securityRaw, /Three external security audits in April 2026 reviewed the relay code/,
    'security.html must state the audits its hero promises');
  // The previous round asserted "The audit reports themselves are not
  // published." That was false: docs/security-audit-2026-04.md is the full
  // Smart Cyber Solutions writeup and it ships in the site tree as
  // frontend/docs/security-audit-2026-04.md. Only the raw pentest output is
  // missing, which is what that document itself calls the "Raw report". These
  // pin what /docs#audits actually says: three audits, forty findings, four
  // critical, all resolved.
  assert.match(securityRaw, /Together they produced 40 findings, 4 of them critical\./,
    'security.html must quote the finding counts the /docs#audits table adds up to');
  assert.match(securityRaw, /the raw pentest output behind it is not published|What is not published is the raw pentest output/,
    'security.html must name what is actually unpublished: the raw pentest output, not the reports');
  assert.doesNotMatch(securityRaw + trustRaw, /The audit reports themselves are not published/,
    'the April 2026 report IS published at /docs/security-audit-2026-04.md; that sentence was untrue');
  assert.match(securityRaw, /href="\/docs\/security-audit-2026-04\.md"/,
    'security.html must link the published audit report it points at');
  // The auditor names were pinned on /trust only, so replacing them on
  // /security with "an independent firm" left the suite green. Pinned on both.
  assert.match(securityRaw, /two by R\. Zwarts, one by Ryan Williams of Smart Cyber Solutions/,
    'security.html must name the auditors it credits');
  assert.match(securityRaw, /href="\/docs#audits"/,
    'security.html must link the audit table that carries the counts');
  assert.doesNotMatch(securityRaw, /full audit history[^<]*<a href="\/architecture"/,
    'security.html must not send the reader to /architecture for audit material it sends back');

  // /trust: tab title and H1 say the same thing, and the audit claim names its
  // auditors and where the outcome is.
  // The literal head strings belong to #334 and tests/seo-contract.test.mjs
  // pins them there. What this file guards is that the H1 and the head agree;
  // see the structural check further down.
  assert.match(trustRaw, /<h1>Trust &amp; Verification<\/h1>/, 'trust.html H1 names the page');
  assert.match(trustRaw, /two by R\. Zwarts, one by Ryan Williams of Smart Cyber Solutions/,
    'trust.html must name the auditors it credits');
  assert.match(trustRaw, /Together they produced 40 findings, 4 of them critical\./,
    'trust.html must quote the same finding counts /docs#audits adds up to');
  assert.match(trustRaw, /href="\/docs\/security-audit-2026-04\.md"/,
    'trust.html must link the published audit report');
  const trustHero = heroOf(trustRaw);
  assert.match(trustHero, /For organisations that run Paramant on their own server/,
    'trust.html must name its audience in the hero, not a screen below it');
  assert.doesNotMatch(trustHero, /\brelay\b/i,
    'trust.html must not use "relay" in the first screen; it is undefined there');

  // One name for one page. The H1 and the <title> said "Trust & Verification"
  // while the social card and the structured data still said "Trust &
  // Transparency", and no test in tests/ compares a title with its og:title.
  // #334 owns the head wording and tests/seo-contract.test.mjs pins the literal
  // strings, so this checks the RELATION instead: the four places that name the
  // page must name it the same, and that name must be the one the H1 uses.
  // Punctuation and case are not the point; "Transparency" versus
  // "Verification" was.
  const pageName = (re, label) => {
    const m = re.exec(trustRaw);
    assert.ok(m, `trust.html must carry ${label}`);
    return m[1].replace(/&amp;|&/g, 'and').replace(/&middot;|\u00b7/g, '').replace(/[^a-z]+/gi, ' ').trim().toLowerCase();
  };
  const trustNames = {
    title: pageName(/<title>([^<]*)<\/title>/, 'a title'),
    og: pageName(/<meta property="og:title" content="([^"]*)"/, 'an og:title'),
    twitter: pageName(/<meta name="twitter:title" content="([^"]*)"/, 'a twitter:title'),
    jsonld: pageName(/"name": "([^"]*Paramant[^"]*)"/, 'a JSON-LD WebPage name'),
  };
  for (const [where, name] of Object.entries(trustNames)) {
    assert.equal(name, trustNames.title,
      `trust.html ${where} calls the page "${name}", the title calls it "${trustNames.title}"`);
  }
  const trustH1 = /<h1>([^<]*)<\/h1>/.exec(trustRaw)[1].replace(/&amp;|&/g, 'and').replace(/[^a-z]+/gi, ' ').trim().toLowerCase();
  for (const word of trustH1.split(' ')) {
    assert.ok(trustNames.title.includes(word),
      `the /trust H1 says "${trustH1}" but the title says "${trustNames.title}"; the word "${word}" is missing`);
  }
  assert.doesNotMatch(trustRaw, /Trust &(amp;)? Transparency|Trust and transparency/i,
    'trust.html must not keep the old page name anywhere');

  // The hero addresses "anyone who has to check a supplier". That reader used to
  // get one text link in the middle of a paragraph as the only way onward.
  assert.match(trustHero, /href="\/security" class="btn btn-primary"/,
    'trust.html must give the reviewer a real next step in the hero');
  assert.match(trustHero, /href="\/pricing" class="btn btn-secondary"/,
    'trust.html must offer pricing from the hero as well');

  // "the operator who runs the relay" was the first sentence under the hero, and
  // relay is not a word a supplier reviewer knows.
  const trustFirstScreen = trustRaw.slice(0, trustRaw.indexOf('<h3>How to read this page</h3>'));
  assert.doesNotMatch(trustFirstScreen, /the operator who runs the relay/,
    'trust.html must not open on undefined jargon; say which server is meant');

  // /pricing sells four ParaSign tiers. "Businesses pay for Pro or Enterprise"
  // silently dropped Business, and the sentence sat on the page that exists to
  // be checkable.
  for (const name of ['ParaSign Community', 'ParaSend Community', 'Firm, ParaSign Business and Enterprise']) {
    assert.ok(trustRaw.includes(name), `trust.html must name the plans as /pricing names them: "${name}"`);
  }
  assert.doesNotMatch(trustRaw, /Businesses pay for Pro or Enterprise/,
    'trust.html must not name two of the three paid ParaSign tiers as if they were all of them');

  console.log('ui-truthfulness: the trust pages answer who, what and what next above the fold');
}
// ── /download: the desktop app, and what the artifacts actually are ─────────
//
// Two reviewers rejected the previous version of this page on 2026-09-02. It
// opened with "THE DESKTOP APP IS OUT OF DATE. USE THE WEB APP." and then ran
// a full product page with four download buttons underneath it, so the page
// argued with itself. It also made a signing claim the artifacts do not
// support, and it counted "21 protections" the web app has over the native
// build, a number no test in this repo could check.
//
// The page now carries one message: the desktop app is not maintained, use the
// browser. The installers stay, collapsed, as an archive with the measurement
// beside them. These assertions pin the parts a future edit could quietly
// soften: the status, the file list, and the signing truth.
//
// Every number below was measured on 2026-09-02 against the files
// https://paramant.app/dl/ serves, which are byte-identical to the release
// artifacts of Apolloccrypt/paramant-app (verified by sha256). The repo is
// private, so the artifacts are the source, not the release notes.

// Wrapped in a named IIFE, the convention #359 settled for this file. It is a
// flat script, so every const in it is a top-level binding and two sections
// arriving from parallel branches collide with "has already been declared".
(function pinDownloadPage() {
  const downloadHtml = read('frontend/download.html');
  const downloadVisible = downloadHtml.replace(/<!--[\s\S]*?-->/g, '');

  // 1. The status sentence. The last release is v0.2.1 of 28 March 2026 and none
  //    has followed it; the repository has no build pipeline that would produce
  //    one. If the app is ever picked up again this assertion is the thing that
  //    fails first, which is the point.
  assert.match(downloadVisible, /The Paramant desktop app is no longer maintained/,
    'download.html must open by saying the desktop app is not maintained');
  assert.match(downloadVisible, /v0\.2\.1/,
    'download.html must name the last release, v0.2.1');
  assert.match(downloadVisible, /28 March 2026/,
    'download.html must date the last release');

  // The old contradiction, in both directions: the page may not recommend the
  // desktop app, and may not sell it as current.
  assert.doesNotMatch(downloadVisible, /\b(?:latest|current|newest)\s+(?:version|build|release)\s+of\s+the\s+desktop\b/i,
    'download.html must not present the archived build as current');
  assert.doesNotMatch(downloadVisible, /\bdownload the (?:desktop |native )?app\b/i,
    'download.html must not invite a download as its call to action');

  // 2. The archive equals what was actually published. Filename, version and
  //    sha256 together: a version bump on the page without a new artifact, or a
  //    fifth installer that no release ever shipped, both fail here.
  const publishedInstallers = {
    'paramant_0.2.1_amd64.deb': {
      version: 'v0.2.1',
      sha256: '62360ad6959be6a9b333de65de67a24b4534f754043c3d88b85908d4703e32bb',
    },
    'PARAMANT-0.2.0-1.x86_64.rpm': {
      version: 'v0.2.0',
      sha256: 'b103dadcd081e886ead442e9128843d5a894b3ec05547b8a2a1ec208d7d541be',
    },
    'PARAMANT_0.2.0_amd64.AppImage': {
      version: 'v0.2.0',
      sha256: '7e0962ace68feb6722a6ddcd60102513c8588c9ac4b3406f91b24721ee9aa728',
    },
    'PARAMANT-0.2.0-windows-signed.exe': {
      version: 'v0.2.0',
      sha256: 'fff0d10c1e0904c5b52cf7c15c1b0fce90e9ab9e48e54d6aab9747e73333f1bc',
    },
  };
  for (const [file, want] of Object.entries(publishedInstallers)) {
    assert.ok(downloadVisible.includes(`/dl/${file}`),
      `download.html must link the archived installer /dl/${file}`);
    assert.ok(downloadVisible.includes(want.sha256),
      `download.html must carry the measured sha256 of ${file}`);
  }
  // No sixth link creeping in, and no Android installer: v0.2.1 shipped an .apk,
  // but on Android the app runs in the system webview, so the "own process, no
  // browser" argument that justifies the desktop archive does not apply there.
  const linkedInstallers = [...downloadVisible.matchAll(/\/dl\/([A-Za-z0-9._-]+)/g)]
    .map((m) => m[1])
    .filter((name) => name !== 'SHA256SUMS');
  assert.deepEqual(
    [...new Set(linkedInstallers)].sort(),
    Object.keys(publishedInstallers).sort(),
    'download.html links installers that are not in the pinned release list, or is missing one');
  // The .apk may be named as a fact (v0.2.1 shipped one), never offered as a
  // link: on Android the app runs in the system webview, so the "own process,
  // no browser" argument that justifies the desktop archive does not apply.
  assert.doesNotMatch(downloadVisible, /href="[^"]*\.apk"/i,
    'download.html must not link the Android build; the web app is current there');

  // 3. The signing truth, measured on the artifacts themselves:
  //      .deb 0.2.1  no _gpgbuilder and no _gpgorigin. Not signed.
  //      .rpm        rpm -qpi reports "Signature : (none)". Not signed.
  //      .AppImage   .sha256_sig and .sig_key exist but are all zeroes.
  //      .exe        Authenticode present, certificate table 1704 bytes, but
  //                  subject and issuer are both CN=Mick Beer, O=PARAMANT, C=NL.
  //
  //    A first pass of this page got the .deb wrong and a reviewer caught it.
  //    It checked only for _gpgorigin, the member debsigs writes, and concluded
  //    the v0.2.0 release notes had overclaimed. They had not. dpkg-sig writes
  //    _gpgbuilder instead, and the v0.2.0 package carries one: a clearsigned
  //    manifest, signer 6EF8E5ACC444949E5A2EAA65CCE2378929A49B97, exactly the
  //    GOODSIG the notes name. The signature disappeared in v0.2.1, which is
  //    the package this page serves. So it is a build regression, not a false
  //    claim, and the yardstick has to name both members or the next reader
  //    repeats the mistake.
  assert.ok(downloadVisible.includes('_gpgbuilder') && downloadVisible.includes('_gpgorigin'),
    'download.html must name both _gpgbuilder (dpkg-sig) and _gpgorigin (debsigs); '
    + 'checking for only one is how the first version of this page got it wrong');

  // A signature may be claimed for v0.2.0, never for the v0.2.1 package on
  // offer. Every sentence that asserts one has to say which release it is about.
  const signingClaims = downloadVisible
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .split(/(?<=\.)\s+/)
    .filter((line) => /\bGPG[- ]?signed\b|\bGOODSIG\b|\bpackage was signed\b/i.test(line));
  assert.ok(signingClaims.length > 0,
    'download.html must still explain that the Debian package used to be signed');
  for (const line of signingClaims) {
    assert.match(line, /v0\.2\.0/,
      `a signing claim on download.html must name the release it holds for: "${line.trim()}"`);
  }
  // The contrast itself, which is the whole point of the paragraph: one release
  // carried the signature, the next did not. Softening either half turns a
  // reported regression back into a vague "not signed" and loses the reason.
  assert.match(downloadVisible, /v0\.2\.0 package was signed/i,
    'download.html must say the v0.2.0 package was signed, because it was');
  assert.match(downloadVisible, /v0\.2\.1 package[\s\S]{0,120}?has no such member/i,
    'download.html must say the v0.2.1 package it serves lost that signature');
  assert.match(downloadVisible, /paramant_0\.2\.1_amd64\.deb[\s\S]{0,400}?Not signed/,
    'the archive entry for the served .deb must say it is not signed');
  assert.match(downloadVisible, /self-signed/i,
    'download.html must say the one signed installer is self-signed');
  assert.doesNotMatch(downloadVisible, /\bsigned and verified\b|\bverified publisher\b|\btrusted publisher\b/i,
    'download.html must not imply a signature a stranger can verify against a trust anchor');

  // 4. No jargon in the first screenful. The rule is docs/brand/messaging.md
  //    section 6: "Cryptography names, standard numbers and RAM-only appear
  //    below the fold, as the reason the top half is true. Never in an H1." And:
  //    at 390px the first screen carries an H1, a sub of at most two sentences,
  //    and two buttons. Nothing enforced that before this page; this is the gate.
  //
  //    "First screenful" is the lead block, from <main> to the end of the
  //    <header class="dl-lead">. That is what a 390px viewport shows, confirmed
  //    by a screenshot at 390x844 in the PR that added this. The class is
  //    page-prefixed on purpose: .hero and .lede already exist in
  //    design-system.css and silently overrode the mobile spacing.
  const heroStart = downloadVisible.indexOf('<main');
  const heroEnd = downloadVisible.indexOf('</header>', heroStart);
  assert.ok(heroStart !== -1 && heroEnd !== -1,
    'download.html must open <main> with a <header class="dl-lead"> block');
  const heroText = downloadVisible
    .slice(heroStart, heroEnd)
    .replace(/<[^>]+>/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  const JARGON = [
    // cryptography and standard numbers
    /ML-KEM/i, /ML-DSA/i, /SPHINCS/i, /\bAES-\d/i, /\bECDH\b/i, /\bHKDF\b/i,
    /\bSHA-?256\b/i, /\bFIPS\b/i, /\bGPG\b/i, /Authenticode/i, /\bratchet/i,
    /\bnonce/i, /\bentropy\b/i, /\bjitter\b/i, /\bpadding\b/i, /post-quantum/i,
    // build and packaging vocabulary
    /\bTauri\b/i, /\bRust\b/i, /\bWebKit\b/i, /AppImage/i, /\.deb\b/i, /\.rpm\b/i,
    /\.exe\b/i, /\bbinary\b/i, /\bAVX2\b/i, /\bRAM\b/i, /\brelay\b/i,
    // header names and other internals a buyer never asked about
    /x-forwarded-for/i, /IndexedDB/i, /getDisplayMedia/i, /\bWS\b/, /\bDOM\b/,
    // the marketing words messaging.md bans outright
    /revolutionary|seamless|cutting-edge|enterprise-grade|military-grade/i,
    /trusted by|world-class|effortless|next-generation|unlock|empower/i,
  ];
  const heroJargon = JARGON.filter((re) => re.test(heroText)).map((re) => String(re));
  assert.deepEqual(heroJargon, [],
    `the first screenful of download.html must say what it is, not how it is built.\n  ` +
    `found: ${heroJargon.join(', ')}\n  in: "${heroText}"\n`);

  // The sub is two sentences and stays near 160 characters, so the hero still
  // fits a 390px screen above the fold.
  const lede = (downloadVisible.slice(heroStart, heroEnd).match(/<p class="dl-sub">([\s\S]*?)<\/p>/) || [])[1] || '';
  const ledeText = lede.replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
  assert.ok(ledeText.length > 0 && ledeText.length <= 200,
    `download.html lede must stay short enough for one mobile screen, is ${ledeText.length} chars`);
  assert.ok((ledeText.match(/\./g) || []).length <= 2,
    `download.html lede must be at most two sentences: "${ledeText}"`);

  // 5. The page is a whole document. The version this replaced was truncated
  //    mid-word ("geen installatie verei") with no </main>, </body> or </html>,
  //    which is why apply-nav.py could not stamp nav.js or nav-auth.js on it and
  //    the hamburger on /download did nothing. Nothing else in the suite reads
  //    HTML for well-formedness, so it is checked here.
  for (const tag of ['</main>', '</body>', '</html>']) {
    assert.ok(downloadHtml.includes(tag),
      `download.html must be a complete document: ${tag} is missing`);
  }
  for (const src of ['/nav.js', '/js/nav-auth.js']) {
    assert.ok(downloadHtml.includes(`src="${src}`),
      `download.html must load ${src}; without a </body> the nav generator skips it`);
  }
})();

console.log('ui-truthfulness: /download says the desktop app is unmaintained, and the archive matches the artifacts');


// ── "Unlimited transfers", banned across the whole site ──────────────────────
//
// relay/lib/tiers.js gives every metered tier a finite transfers_month (10 on
// Community, 500 on Pro, 2,000 on Business) and relay/lib/entitlements.js holds
// even enterprise to ENTERPRISE_MONTHLY_CEILING rather than Infinity, so no
// page and no script may promise transfers without a ceiling. relay/relay.js
// refuses the transfer over the cap with a 402 monthly_transfer_quota_reached
// naming that ceiling: a visitor who read "unlimited" meets the number anyway,
// at the worst possible moment.
//
// relay/test/pricing-page.test.js already forbade the phrase, but only on
// /parasign and /parasend, and only in .html. It sat on three files that check
// could not see: /pricing itself (the ParaSign Pro card), frontend/js/
// quota-upgrade.js (the 402 upgrade card, which is the very screen the relay
// shows when the cap bites) and frontend/js/dashboard.js (the summary a paying
// customer reads). So the ban is scoped to the whole frontend here, scripts and
// served markdown included, which is what "site-wide" has to mean for a claim
// that travels in a template string.
//
// Receiving IS uncapped, and stays sayable: nothing in tiers.js or in any
// entitlement quota meters it (#359 pins that negatively in pricing-page.test).
// Licence capacity is uncapped too (max_keys 'unlimited' really is Infinity in
// relay.js), as is enterprise devices/outbound_per_hour in tiers.js. So this
// bans the word beside "transfers", not the word.
(function noUnlimitedTransfers() {
  const TEXT_EXT = ['.html', '.js', '.mjs', '.md'];
  const SKIP_DIR = ['node_modules', 'vendor', 'assets'];
  const walk = (dir) => fs.readdirSync(new URL('../' + dir, import.meta.url), { withFileTypes: true })
    .flatMap((e) => {
      if (e.isDirectory()) return SKIP_DIR.includes(e.name) ? [] : walk(`${dir}/${e.name}`);
      return TEXT_EXT.some((x) => e.name.endsWith(x)) ? [`${dir}/${e.name}`] : [];
    });
  const files = walk('frontend');
  assert.ok(files.length > 20, `the frontend walk found only ${files.length} text files; the ban would be vacuous`);

  // Comments are stripped: a comment that explains a removed overclaim quotes
  // the wording it exists to forbid, which is exactly how it stays forbidden.
  const strip = (s) => s
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/^[ \t]*\/\/.*$/gm, ' ');

  const hits = [];
  for (const file of files) {
    const m = /unlimited(?:\s|&nbsp;|<[^>]+>)+(?:\w+(?:\s|&nbsp;)+)?transfers/i.exec(strip(read(file)));
    if (m) hits.push(`${file}: "${m[0].replace(/\s+/g, ' ')}"`);
  }
  assert.deepEqual(hits, [],
    'no frontend page or script may promise transfers without a ceiling; tiers.js caps every tier ' +
    'and relay.js answers 402 monthly_transfer_quota_reached with that cap:\n  ' + hits.join('\n  '));

  // Where the word DID name a real ceiling, the number replaced it. These are
  // ParaSend contexts: the plan table a self-hoster reads and the OT brief's own
  // Pro tier, both describing the ParaSend capacity the relay actually enforces.
  const proTransfers = 500; // relay/lib/tiers.js pro.transfers_month, pinned to the module in relay/test/
  for (const [file, rx] of [
    ['frontend/docs/paramant-ot-brief.html', new RegExp(`<li>${proTransfers} transfers a month</li>`)],
    ['frontend/docs/self-hosting.md', new RegExp(`\\| \`pro\` \\| ${proTransfers} \\|`)],
  ]) {
    assert.match(read(file), rx,
      `${file} must state the ParaSend Pro transfers ceiling where it used to say "unlimited"`);
  }
})();

console.log('ui-truthfulness: no page or script promises transfers without a ceiling');


// ── No page may bill for something the kassa cannot collect ─────────────────
//
// For six releases /pricing, /parasign, the homepage, the dashboard and the
// inline sign notice all told a Firm customer that signatures past 100 cost
// EUR 0.40 each "and appear on your next invoice". None of that could happen.
// relay/lib/billing-catalog.js holds fixed monthly and yearly amounts and
// nothing else; no usage line exists in billing.js, invoice.js or
// billing-recurring.js; the metered counter in quota.js had no reader but a
// test. The money was never asked for and there was no second invoice to ask
// on, because a Firm subscription collects its own fixed amount.
//
// Both gates that should have caught it were counting amounts. This one counts
// the PROMISE, which is the part that costs trust: a per-unit rate, or a charge
// deferred to a later bill. Either may only appear on the site once the catalog
// can actually charge it, and the catalog is asked here rather than trusted to
// have stayed the same.
(function noChargeThePriceListCannotMake() {
  const require_ = createRequire(import.meta.url);
  const catalog = require_('../relay/lib/billing-catalog.js');

  const TEXT_EXT = ['.html', '.js', '.mjs'];
  const SKIP_DIR = ['node_modules', 'vendor', 'assets'];
  const walk = (dir) => fs.readdirSync(new URL('../' + dir, import.meta.url), { withFileTypes: true })
    .flatMap((e) => {
      if (e.isDirectory()) return SKIP_DIR.includes(e.name) ? [] : walk(`${dir}/${e.name}`);
      return TEXT_EXT.some((x) => e.name.endsWith(x)) && !e.name.endsWith('.min.js')
        ? [`${dir}/${e.name}`] : [];
    });
  const files = walk('frontend');
  assert.ok(files.length > 20, `the frontend walk found only ${files.length} text files; the ban would be vacuous`);

  // What a person reads. Comments are stripped for the same reason as above:
  // the note explaining a removed promise has to be free to quote it.
  const strip = (s2) => s2
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/\/\*[\s\S]*?\*\//g, ' ')
    .replace(/^[ \t]*\/\/.*$/gm, ' ');

  const CURRENCY = '(?:&euro;|\u20ac|EUR\\s*)';
  const FORBIDDEN = [
    // A charge pushed to a later bill. The only invoice Paramant issues is the
    // one for the payment that was just taken (relay/lib/invoice.js, issued from
    // the webhook), so there is no later bill to put anything on.
    [/next invoice|volgende factuur|on your next bill|added to your invoice/i,
      'a charge deferred to a later invoice; relay/lib/invoice.js only ever documents a payment already taken'],
    // A per-unit rate. Every amount the site prints has to be resolvable by
    // catalog.resolveOrder, and a per-signature rate is not.
    [new RegExp(`${CURRENCY}\\s*[\\d.,]+\\s*(?:each|a piece|per\\s+(?:extra\\s+)?(?:signature|sign|transfer|document|user|seat))`, 'i'),
      'a per-unit rate; relay/lib/billing-catalog.js sells whole plans, so nothing collects it'],
    [/\bovergebruik\b|\boverage\b/i,
      'metered overage; no tier meters and no billing line collects one'],
  ];

  const hits = [];
  for (const file of files) {
    const visible = strip(read(file));
    for (const [rx, why] of FORBIDDEN) {
      const m = rx.exec(visible);
      if (m) hits.push(`${file}: "${m[0].replace(/\s+/g, ' ')}" (${why})`);
    }
  }
  assert.deepEqual(hits, [],
    'no page may promise a charge the price list cannot make:\n  ' + hits.join('\n  '));

  // And the reason it cannot: the catalog holds plan prices, per interval, and
  // has no per-unit line to hang a metered rate on. Asked, not assumed, so the
  // day a usage line is added this check is what points at the rule to revisit.
  for (const { product, plan } of catalog.ON_SALE) {
    for (const interval of catalog.INTERVALS) {
      const order = catalog.resolveOrder({ product, plan, interval });
      assert.ok(!order.error && order.amount,
        `${product}/${plan}/${interval} must resolve to one chargeable amount`);
    }
  }
  assert.strictEqual(catalog.priceOf('parasign', 'pro', 'per_signature'), null,
    'the catalog must have no per-signature interval; add the billing line before the site names a rate');
})();

console.log('ui-truthfulness: no page bills for something billing-catalog.js cannot charge');


// ── A ParaSign surface states no transfers figure at all ────────────────────
//
// The other half of the same correction, and the sharper one. "Unlimited
// transfers" on the ParaSign Pro card was false for everyone, because no tier
// is unbounded. Putting 500 there would have been false for a different reason:
// transfers are a ParaSEND capacity, held on plan_parasend, and the grant that
// sells ParaSign Pro (entitlements.applyProductTier(acct,'parasign','pro'), the
// Mollie webhook and the admin path) writes plan_parasign alone and leaves
// plan_parasend exactly where it was. A ParaSign Pro buyer on a free ParaSend
// tier keeps 10 transfers a month. relay/test/parasign-pro-perks.test.js pins
// that delivery gap; this pins the copy that must not outrun it.
//
// So: ParaSign Pro sells signatures and the API. It does not sell transfers,
// and no ParaSign card, pitch or plan summary may print a transfers number
// while the grant does not move one. The gate ASKS the entitlement layer rather
// than restating its answer, so bundling a ParaSend entitlement into ParaSign
// Pro flips this from "must not state" to "must state" on its own.
(function signingSurfacesStateOnlyDeliveredTransfers() {
  // The relay is CommonJS; this file is ESM. createRequire loads the real
  // modules rather than a copy of their numbers, which is the whole point: the
  // gate has to move when the entitlement layer does.
  const require_ = createRequire(import.meta.url);
  const { applyProductTier, getEntitlements, PARASEND } = require_('../relay/lib/entitlements.js');
  const catalog = require_('../relay/lib/billing-catalog.js');

  // What a signing surface may promise is what the plan it pitches actually
  // hands over. Firm grants both products, so its ParaSend ceiling is real; a
  // bare parasign=pro grant still grants nothing on ParaSend, which is what
  // relay/test/parasign-pro-perks.test.js pins and why this gate exists.
  const afterBuying = (product, plan) => {
    const acct = { key: 'k', account_id: 'k', plan: 'community', plan_parasend: 'community', plan_parasign: 'free' };
    for (const g of catalog.grantsOf(product, plan) || []) applyProductTier(acct, g.product, g.tier);
    return getEntitlements(acct).parasend.quotas.transfers_month;
  };
  const delivered = afterBuying('firm', 'firm');
  assert.equal(delivered, PARASEND.pro.quotas.transfers_month,
    `Firm must deliver the ParaSend Pro ceiling, got ${delivered}`);
  assert.equal(afterBuying('parasign', 'pro'), PARASEND.community.quotas.transfers_month,
    'a bare parasign=pro grant still moves nothing on ParaSend; that is what makes this gate necessary');

  const TRANSFER_FIGURE = /([\d][\d,]*)\s*(?:ParaSend\s+)?transfers/i;
  const pricingHtml = read('frontend/pricing.html');
  const between = (src, a, b) => src.slice(src.indexOf(a), b ? src.indexOf(b) : undefined);
  const dashJs = read('frontend/js/dashboard.js');
  const quotaJs = read('frontend/js/quota-upgrade.js');
  const parasignGridScope = between(pricingHtml, '<!-- TIER CARDS: PARASIGN -->', '<!-- TIER CARDS: PARASEND -->');
  const scopes = [
    ['pricing.html ParaSign grid', parasignGridScope],
    ['parasign.html plan cards', between(read('frontend/parasign.html'), '<h3', '')],
    ['dashboard.js PRODUCT_INCLUDES.parasign', between(dashJs, 'parasign: {', 'parasend: {')],
    ['quota-upgrade.js freeSignHtml', between(quotaJs, 'function freeSignHtml', 'function hardCapHtml')],
  ];
  for (const [name, scope] of scopes) {
    assert.ok(scope.length > 200, `${name}: the scope markers moved; this gate would read nothing`);
  }

  // Any transfers figure on a signing surface has to be the one Firm delivers.
  const wrong = [];
  for (const [name, scope] of scopes) {
    const m = TRANSFER_FIGURE.exec(scope);
    if (!m) continue;
    if (Number(m[1].replace(/,/g, '')) !== delivered) wrong.push(`${name}: "${m[0]}" against ${delivered} delivered`);
  }
  assert.deepEqual(wrong, [],
    'a signing surface prints a transfers figure the plan it pitches does not deliver:\n  ' + wrong.join('\n  '));

  // And the card that SELLS Firm has to say so: the second product is half of
  // what the buyer is paying for, and a card that hides it undersells itself.
  assert.match(parasignGridScope, TRANSFER_FIGURE,
    'the Firm card in the ParaSign grid must state the ParaSend ceiling it grants');
})();

console.log('ui-truthfulness: no ParaSign surface sells a transfers ceiling the ParaSign grant does not deliver');


// ── Two product names, and only two ──────────────────────────────────────────
//
// docs/brand/messaging.md section 6: there are two products, ParaSend and
// ParaSign. ParaShare was never a product, only the label on the send screen,
// and it read as a fifth brand on the perskit, the pricing page and five claims
// on /security. The name is gone from copy. Two things it is NOT gone from, on
// purpose, and neither is a name a buyer reads:
//
//   /parashare        the URL. Every link the Chromium and Thunderbird
//                     extensions ever minted is baked against it
//                     (extensions/shared/paramant-core.js), those links sit in
//                     recipients' mailboxes, and relay.js answers the retired
//                     /v2/anon-inbound with a Link: rel="successor-version"
//                     header pointing at it, which is in the sdk-js 3.x
//                     contract until the 31-12-2026 Sunset. The URL cannot move.
//   the register row  <td>ParaShare (webapp)</td> on /crypto-agility is a
//                     technical key: two other gates read the algorithms out of
//                     that row by that label (this file, above, and
//                     relay/test/pricing-page.test.js).
//
// Everywhere else the name may only appear as a glossed contract term in the
// three legal documents, where dropping a defined term out of live conditions
// is not a search and replace.
(function twoProductNamesOnly() {
  const dir = new URL('../frontend/', import.meta.url);
  const pages = [];
  const walk = (rel) => {
    for (const entry of fs.readdirSync(new URL(rel, dir), { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (entry.name !== 'node_modules' && entry.name !== 'vendor') walk(`${rel}${entry.name}/`);
      } else if (entry.name.endsWith('.html')) {
        pages.push(`${rel}${entry.name}`);
      }
    }
  };
  walk('');
  assert.ok(pages.length > 30, 'the page walk found almost nothing; this gate would read nothing');

  // The legal term, glossed. A gloss on the first mention is what makes the
  // term readable; a bare mention on a page that never defines it is not.
  const LEGAL = new Set(['terms.html', 'privacy.html', 'dpa.html']);
  const REGISTER = 'crypto-agility.html';
  const GLOSS = 'ParaShare (the ParaSend web app)';

  const strays = [];
  for (const page of pages) {
    const html = read('frontend/' + page);
    if (!html.includes('ParaShare')) continue;
    if (LEGAL.has(page)) {
      assert.ok(html.includes(GLOSS),
        `${page} uses ParaShare as a contract term without ever defining it; it must read "${GLOSS}" at least once`);
      continue;
    }
    if (page === REGISTER) {
      assert.ok(/<td>ParaShare \(webapp\)<\/td>/.test(html),
        'crypto-agility.html may carry ParaShare only as the register row two other gates read by that label');
      continue;
    }
    strays.push(page);
  }
  assert.deepEqual(strays, [], `these pages present ParaShare in copy again: ${strays.join(', ')}`);

  // And nowhere, not even on the four pages above, in the three places a
  // reader takes for a product name: the H1, the kicker over it, or the
  // heading on a card. The eyebrow on /parashare said PARASHARE until this
  // round, which is exactly the shape this looks for.
  const shouty = [];
  for (const page of pages) {
    const html = read('frontend/' + page);
    const spots = [
      ...html.matchAll(/<h1[^>]*>([\s\S]*?)<\/h1>/gi),
      ...html.matchAll(/<h3[^>]*>([\s\S]*?)<\/h3>/gi),
      ...html.matchAll(/<span[^>]*class="[^"]*eyebrow[^"]*"[^>]*>([\s\S]*?)<\/span>/gi),
      ...html.matchAll(/<p[^>]*class="[^"]*eyebrow[^"]*"[^>]*>([\s\S]*?)<\/p>/gi),
    ];
    for (const m of spots) {
      if (/parashare|pararules/i.test(m[1])) shouty.push(`${page}: ${m[1].replace(/\s+/g, ' ').trim()}`);
    }
  }
  assert.deepEqual(shouty, [],
    `a heading, card or kicker presents a retired name as a product:\n  ${shouty.join('\n  ')}\n`);
})();

console.log('ui-truthfulness: ParaSend and ParaSign are the only two product names in copy');


// ── The rules page is "Our rules" on /rules ──────────────────────────────────
//
// The nine rules and their verify links (#328) moved word for word; only the
// name went. /pararules is in Google, so it keeps a permanent 301 in both
// server confs the runbook edits, and nothing on the site may point at the old
// path any more: a link that takes a redirect is a link that will rot the day
// someone tidies the redirect away.
(function rulesPageMoved() {
  const rules = read('frontend/rules.html');
  assert.match(rules, /<h1>Our rules<\/h1>/, 'frontend/rules.html must carry the H1 the page is named for');
  assert.match(rules, /<link rel="canonical" href="https:\/\/paramant\.app\/rules">/,
    'rules.html must point its canonical at the new URL, or the 301 sends the signal back and forth');
  assert.ok(!/ParaRule/i.test(rules), 'rules.html carries the retired name again');

  const sitemap = read('frontend/sitemap.xml');
  assert.ok(sitemap.includes('<loc>https://paramant.app/rules</loc>'), '/rules is missing from the sitemap');
  assert.ok(!sitemap.includes('/pararules'), 'the sitemap still lists the retired /pararules URL');

  // No internal link may take the redirect.
  const dir = new URL('../frontend/', import.meta.url);
  const linkers = [];
  const walk = (rel) => {
    for (const entry of fs.readdirSync(new URL(rel, dir), { withFileTypes: true })) {
      if (entry.isDirectory()) {
        if (entry.name !== 'node_modules' && entry.name !== 'vendor') walk(`${rel}${entry.name}/`);
      } else if (entry.name.endsWith('.html') || entry.name.endsWith('.js')) {
        if (read('frontend/' + rel + entry.name).includes('/pararules')) linkers.push(rel + entry.name);
      }
    }
  };
  walk('');
  assert.deepEqual(linkers, [], `these files still link to the retired /pararules: ${linkers.join(', ')}`);

  // The 301 itself, in both confs deploy/deploy-3.1.sh phase 5c names.
  for (const conf of ['deploy/nginx-paramant-public.conf', 'deploy/nginx-paramant-live.conf']) {
    assert.match(read(conf), /location = \/pararules \{ return 301 https:\/\/\$host\/rules; \}/,
      `${conf} has no 301 from /pararules to /rules; every indexed link to the old page would 404`);
  }
})();

console.log('ui-truthfulness: the rules page is Our rules on /rules, with /pararules redirected');

// ── The appearance choice: the key, the values, and the three promises ───────
//
// The inventory of localStorage keys is not here: tests/site-claims.test.mjs
// row 28 reads every key the frontend writes against the list on /privacy and
// fails on either side drifting. One inventory is enough. What this adds is the
// half that gate cannot see: that the key /privacy names is the key this
// feature writes, and that the three sentences beside the switch on /account
// are true of the code underneath them.
(() => {
  const themeJs = read('frontend/js/theme.js');
  assert.match(themeJs, /var KEY = 'paramant\.theme\.v1';/,
    'the appearance key was renamed; /privacy, docs/site-claims.md and tests/app-theme.test.mjs name the old one');
  assert.match(themeJs, /var CHOICES = \['auto', 'light', 'dark'\];/,
    'the three appearance choices are what /account offers and what app-theme measures');

  const privacyPage = read('frontend/privacy.html');
  assert.ok(privacyPage.includes('<code>paramant.theme.v1</code>'),
    '/privacy must name the appearance key in its local-storage list');
  assert.ok(read('docs/site-claims.md').includes('`paramant.theme.v1`'),
    'docs/site-claims.md must record what the appearance key is for');

  // "Kept in this browser only" is a claim about the network, so read the code
  // back: nothing in theme.js may reach off the machine.
  assert.doesNotMatch(themeJs, /fetch\(|XMLHttpRequest|navigator\.sendBeacon/,
    'theme.js must not send the choice anywhere; /account and /privacy both say it stays in the browser');

  assert.match(account, /Dark is the default and it stays dark until you change it here/,
    '/account must say that the night is the default, because app-2026.css makes it so');
  assert.match(account, /kept in this\s+browser only/,
    '/account must say the choice never leaves the browser');
  assert.match(account, /The public pages stay dark\./,
    '/account promises the marketing pages stay on the night; tests/app-theme.test.mjs measures that');
})();

console.log('ui-truthfulness: the appearance switch says only what theme.js and app-2026.css do');

// ── /parashare says up front that this is a live handshake ──────────────────
// A buyer reached step 2 before finding out that the other person has to be at
// their screen right now. The stepper said "2 . Share", the card said "Waiting
// for receiver", and by then he had already picked a file and made a link. That
// is not a copy problem on step 2; it is a fact about the product that belongs
// above step 1, in the words someone would use out loud.
//
// The sentence is pinned to the flow rather than to itself. It claims two
// things: that the receiver has to be online while you send, and that the two
// of you confirm a short code together. Both are properties of
// parashare.page.js, so both are read back from it here. Verified by sabotage:
// drop the sentence, or let confirmFingerprint run without receiverPubs, or
// let createSession reach step-encrypting without going through the waiting
// step, and this block goes red.
(() => {
  const parashare = read('frontend/parashare.html');
  const psJs = read('frontend/js/parashare.page.js');

  assert.match(parashare, /The person you send to has to be online while you send; you confirm a short code together\./,
    '/parashare must say above step 1 that the receiver has to be there; a sender should not discover a live handshake on step 2');

  // The sentence above became a sentence about ONE of two stands the moment
  // /parashare grew "Send a link", so it may only be shown while that stand is
  // chosen. Three things have to hold together or the page starts lying in one
  // direction or the other: the chooser exists and offers both, the live
  // sentence is the DEFAULT (the live stand is the one selected on arrival, so
  // a sender who chooses nothing reads the promise that is true of what he is
  // about to do), and the sentence is really swapped when the other stand is
  // picked rather than left standing over a flow it does not describe.
  // Sabotage: delete either mode card, flip aria-checked to the link card, or
  // take the swap out of setSendMode, and this goes red.
  assert.match(parashare, /id="ps-mode-live"[^>]*aria-checked="true"/,
    'the live stand must be the one selected on arrival: it is the stand the sentence above step 1 describes');
  assert.match(parashare, /id="ps-mode-link"[^>]*aria-checked="false"/,
    'the "Send a link" stand must not be pre-selected while the live sentence stands above step 1');
  assert.match(psJs, /note\.textContent = \(sendMode === 'link'\)/,
    'setSendMode no longer swaps the live-handshake sentence; choosing "Send a link" would leave a promise on screen that that stand does not keep');
  assert.match(psJs, /does not have to be online/,
    'the "Send a link" stand must say the receiver does not have to be online; that is the whole reason it exists');
  // Above step 1 means above it, not somewhere on the page: the sentence has to
  // sit before the step-1 guide inside #step-setup.
  const setupAt = parashare.indexOf('id="step-setup"');
  const noteAt = parashare.indexOf('The person you send to has to be online');
  const guideAt = parashare.indexOf('Step 1 of 5');
  assert.ok(setupAt > 0 && noteAt > setupAt && noteAt < guideAt,
    'the sentence must stand inside #step-setup and above the step-1 guide, which is where a sender reads before choosing a file');

  // Claim 1: sending really does wait for the other person. createSession goes
  // to the waiting step and opens the socket, and nothing else advances.
  assert.match(psJs, /showStep\('step-waiting'\);\s*\n\s*connectWebSocket\(\);/,
    'createSession must hand over to the waiting step: that wait is what the sentence promises');
  assert.equal((psJs.match(/showStep\('step-encrypting'\)/g) || []).length, 1,
    'more than one path now reaches the encrypt step; the promise that the receiver has to be online is only true while confirmFingerprint is the single door');
  const confirm = psJs.slice(psJs.indexOf('async function confirmFingerprint()'));
  const guardAt = confirm.indexOf('if (!receiverPubs) return;');
  const encryptAt = confirm.indexOf('showStep(\'step-encrypting\')');
  assert.ok(guardAt >= 0,
    'confirmFingerprint no longer refuses to run without a receiver; the sentence above step 1 promises the receiver has to be there');
  assert.ok(encryptAt > guardAt,
    'the encrypt step must sit behind the receiverPubs guard, so a sender cannot send to nobody');

  // Claim 2: there really is a short code, and both sides work it out.
  assert.match(psJs, /async function genFingerprint\(/,
    'the short code the sentence promises is genFingerprint; without it the sentence describes nothing');
  assert.match(parashare, /Compare this code together/,
    'the card where the two of you compare must be named after what it asks you to do');
  assert.match(read('frontend/js/ontvang.page.js'), /genFingerprint|fp-display/,
    'the receiver side must compute a code too, otherwise "together" is one-sided');
})();

console.log('ui-truthfulness: /parashare says the receiver has to be online, and the flow really waits for them');

// ── /ct-log names the log it is showing, and describes that one ─────────────
//
// The page prints a live count of log entries. Until 5 September 2026 it printed
// nothing else about them, and a busy count on a page that sells the product
// reads as busy customers. A notice was added that day to correct that, and the
// notice was wrong: it described relay.paramant.app (891 entries, 855 of them
// made by the hourly self-test) and printed it beside the count of
// health.paramant.app (4771 entries, of which the self-test made none). The
// sentence was true of a log the page does not show.
//
// So the rule this block enforces is not "the page must contain sentence X". It
// is: the page must name the host it fetches, and every claim it makes about the
// composition of that log must be backed by code that writes into that same
// host's log. That is the class of error, not the instance.
//
// The public projection at /v2/ct/log deliberately gives no way to tell entry
// kinds apart for a reader who wants to profile traffic: relay.js strips
// device_hash and coarsens the timestamp to the hour. Labelling the self-test
// inside the log would undo exactly that, because every entry left unlabelled
// would then be provably customer traffic. So the disclosure lives on the page.
(() => {
  const ctLogHtml = read('frontend/ct-log.html');
  const ctLogJs = read('frontend/js/ct-log.page.js');
  // Comments are not read by visitors and this page's comment quotes the very
  // sentences being required, so a gate that scanned the raw file would stay
  // green on a page that had lost them. Everything below reads what a person sees.
  // Newlines inside a sentence are the page's line wrapping, not the reader's:
  // a required phrase must match whether or not the source happens to break it.
  const ctLogSeen = ctLogHtml.replace(/<!--[\s\S]*?-->/g, '').replace(/\s+/g, ' ');
  const ctLogJsSeen = ctLogJs.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

  // The trigger: this page shows a count, so it owes the reader its composition.
  assert.match(ctLogSeen, /id="stat-total"/,
    'ct-log no longer shows a live entry count; if the count is gone, retire this block deliberately');

  // 1. Which log. The host the page fetches has to be the host the copy names,
  //    or the reader is being told about one log while looking at another.
  const ctHostM = /const RELAY = 'https:\/\/([a-z0-9.-]+)'/.exec(ctLogJsSeen);
  assert.ok(ctHostM, 'ct-log.page.js no longer declares its relay as a single const RELAY; this gate reads the host from there');
  const ctHost = ctHostM[1];
  assert.ok(ctLogSeen.includes(ctHost),
    `ct-log fetches ${ctHost} and never names it; a visitor cannot tell which of our relays' logs they are reading`);
  // And no other relay host may be named in the copy without the one being shown
  // standing beside it, which is the shape that produced the 5 September error.
  for (const other of [...ctLogSeen.matchAll(/\b([a-z0-9-]+\.paramant\.app)\b/g)].map((m) => m[1])) {
    assert.equal(other, ctHost,
      `ct-log names ${other} in its copy but fetches ${ctHost}; text and number must be about the same log`);
  }

  // 2. Whatever the page blames for the bulk of the entries has to be something
  //    that writes into THIS log.
  //
  //    a. The hourly self-test. It posts to PARAMANT_RELAY_URL in heartbeat.yml,
  //       and that is a different host from the one this page reads today. If the
  //       copy ever blames the self-test again, the two hosts must agree first.
  const heartbeat = read('.github/workflows/heartbeat.yml');
  const hbHostM = /PARAMANT_RELAY_URL:\s*https:\/\/([a-z0-9.-]+)/.exec(heartbeat);
  assert.ok(hbHostM, 'heartbeat.yml no longer names the relay it tests; this gate reads the host from there');
  if (/self-test/i.test(ctLogSeen)) {
    assert.equal(hbHostM[1], ctHost,
      `ct-log blames the hourly self-test for its entries, but the self-test writes to ${hbHostM[1]} and this page reads ${ctHost}`);
    assert.match(heartbeat, /- cron: '\d+ \* \* \* \*'/,
      'ct-log calls the self-test hourly; heartbeat.yml no longer runs hourly');
    assert.match(read('scripts/heartbeat/parasend.mjs'), /\$\{RELAY\}\/v2\/anon-inbound/,
      'the self-test must still send a real transfer, or it makes no log entries to disclose');
  }

  //    b. Relay announcements, which is what this log is actually full of. The
  //       claim only stands while relay.js still writes a CT entry when a relay
  //       announces itself, and while the relays still announce to this host.
  if (/restarts?|announce/i.test(ctLogSeen)) {
    const relaySrc = read('relay/relay.js');
    assert.match(relaySrc, /function registerSelf/,
      'ct-log says our relays announce themselves; relay.js no longer has registerSelf');
    assert.match(relaySrc, /RELAY_PRIMARY_URL/,
      'ct-log says our relays announce themselves to one relay; RELAY_PRIMARY_URL is gone');
    const relayRegRoute = relaySrc.slice(relaySrc.indexOf("path === '/v2/relays/register'"));
    assert.ok(relayRegRoute.length > 0, 'the relay-registration route is gone; ct-log blames it for entries it no longer makes');
    assert.match(relayRegRoute.slice(0, 4000), /ctAppendRelayReg\(/,
      'a relay announcing itself no longer appends to the CT log, so ct-log blames it for nothing');
    const compose = read('docker-compose.yml');
    assert.match(compose, new RegExp(`RELAY_PRIMARY_URL:\\s*"http://relay-${ctHost.split('.')[0]}:`),
      `ct-log reads ${ctHost} and says our relays announce themselves there; docker-compose.yml points them somewhere else`);
    // The page owes the reader a counter for the kind it blames, or the three
    // numbers under the table still do not add up to the total.
    assert.match(ctLogSeen, /id="stat-relayreg"/,
      'ct-log blames relay announcements for most entries and shows no count of them');
    assert.match(ctLogJsSeen, /e\.type === 'relay_reg'/,
      "ct-log.page.js must count relay_reg entries for the counter the page shows");
  }

  // 3. The sentence has to stand before the number it explains, not below it.
  const noticeAt = ctLogSeen.indexOf('id="composition-notice"');
  const statsAt = ctLogSeen.indexOf('id="stat-total"');
  assert.ok(noticeAt > 0 && noticeAt < statsAt,
    'the composition notice must stand above the counters, which is where a visitor reads before the number');

  // 4. No page may sell the volume as demand. These are the shapes that would.
  for (const shape of [
    /(shows?|proves?|reflects?|measures?)[^.<]{0,30}(real |actual |live )?customer (use|usage|traffic|activity|demand)/i,
    /see how (much|often)[^.<]{0,30}is used/i,
    /live customer (activity|traffic)/i,
    /growing (steadily|fast)/i,
  ]) {
    assert.doesNotMatch(ctLogSeen, shape,
      'ct-log must not present the entry count as customer use; most of the entries are not customer traffic');
  }
  assert.match(ctLogSeen, /not a measure of how much the service is used/i,
    'ct-log must say what the count is not, or the number sells activity the service does not have');

  // 5. The count is fetched, never typed, so it cannot age into a lie. Read the
  // notice as a whole rather than a window around the word "entries": the
  // number sits in a span of its own, so any regex that steps over tags misses
  // exactly the paste it is meant to catch. No figure belongs in this notice
  // that /v2/ct/log did not just answer, so no literal number belongs here.
  const ctLogNoticeEnd = ctLogSeen.indexOf('</div> </div>', noticeAt);
  assert.ok(ctLogNoticeEnd > noticeAt, 'the composition notice no longer closes as a notice block');
  const ctLogNotice = ctLogSeen.slice(noticeAt, ctLogNoticeEnd);
  assert.match(ctLogNotice, /id="composition-count"/,
    'the count in the sentence must be a slot the page fills, not text');
  assert.doesNotMatch(ctLogNotice, /\d{2,}/,
    'the entry count in the copy must come from /v2/ct/log, not be typed into the page');
  assert.match(ctLogJsSeen, /getElementById\('composition-count'\)/,
    'ct-log.page.js must fill the count in the sentence; without it the page names no number at all');
  assert.match(ctLogJsSeen, /var logSize = d\.size != null \? d\.size : allEntries\.length;/,
    'the sentence and the counter must name the same number, off the same read of /v2/ct/log');

  // 6. Same rule as block 8 of site-claims.test.mjs, on the page next door: while
  // HEARTBEAT_ENABLED gates the workflow, /sla says the check is switched off
  // until its credentials are in place, and this page may not say otherwise.
  if (/vars\.HEARTBEAT_ENABLED\s*==\s*'true'/.test(heartbeat)) {
    assert.doesNotMatch(ctLogSeen, /self-test (is )?(running|runs) (right )?now|every hour, (all day|around the clock)|around the clock/i,
      'the self-test is gated off, so ct-log must not imply it is running; /sla carries the same caveat');
  }
})();

console.log('ui-truthfulness: /ct-log names the relay whose log it shows, and every claim about the mix is backed by code that writes into that log');
