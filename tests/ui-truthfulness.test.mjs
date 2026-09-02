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
for (const [file, html, id] of [['dashboard.html', dashboardHtml, 'dh-community'], ['account.html', accountHtml, 'billing-community']]) {
  const band = (html.match(new RegExp(`id="${id}"[\\s\\S]*?<\\/(aside|div)>\\s*<\\/?(aside|div|p)`)) || [''])[0];
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
// Pages that SELL on the founder. On these the line is required, not optional:
// an if-includes gate lets the sentence be deleted and stays green, and the
// give-back promise is the one thing the signed-in pages are there to make.
const FOUNDER_REQUIRED = ['index', 'dashboard', 'account'];
// Pages that MAY name him. If they do, the same rules apply.
const FOUNDER_OPTIONAL = ['pricing', 'parasign'];
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
assert.match(docsHtml, /<p class="lede">[^<]*The ParaSign API is available from ParaSign Pro/,
  'docs.html must state in the visible lede which plan the ParaSign API needs');
const docsActions = (docsHtml.match(/<div class="docs-hero-actions">[\s\S]*?<\/div>/) || [''])[0];
assert.match(docsActions, /<a href="#quickstart" class="docs-hero-btn docs-hero-btn-primary">/,
  'the developer keeps the primary button on /docs: Quick start');
assert.match(docsActions, /<a href="\/pricing" class="docs-hero-btn docs-hero-btn-secondary">/,
  'the buyer gets a real button to /pricing beside it, not only a text link');
assert.match(developerHtml, /<p class="lede">[^<]*(?:<a[^>]*>[^<]*<\/a>[^<]*)*API access is included from ParaSign Pro/,
  'developer.html must state in its visible lede which plan the ParaSign API needs');
// /developer is noindex and only reachable once signed in, so it addresses the
// developer reading it, never the buyer who sent them.
assert.doesNotMatch(developerHtml, /your IT can check/i,
  'developer.html talks to the developer on the screen, not to their buyer');
// Both plan lines are only true while /pricing sells API access on ParaSign Pro.
assert.match(pricing, /Unlimited transfers - API access/,
  'pricing.html must still list API access on the ParaSign Pro tier');

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
assert.match(parasignGrid, /<div class="tier-name">Community<\/div>[\s\S]{0,400}?<li>2 signatures per month<\/li>/,
  'pricing.html is the source of the ParaSign Community allowance quoted on /help');
assert.match(pricing, /&euro;49<span/,
  'pricing.html is the source of the ParaSign Pro price quoted on /help');
assert.match(pricing, /charged &euro;59\.29\/mo incl\. 21% btw/,
  'pricing.html is the source of the incl. btw figure quoted on /help');
assert.match(helpAnswers, /ParaSign Community is free, forever, and no card is required\. It covers 2 signatures per month\./,
  'help/index.html must name the free allowance, not just promise that free exists');
assert.match(helpAnswers, /ParaSign Pro at &euro;49 a month excl\. btw \(&euro;59\.29 incl\.\)/,
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
