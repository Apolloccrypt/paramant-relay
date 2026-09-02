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
// /security. A copy drifts silently: the source page can be reworded and the
// copy keeps promising the old thing. So each assertion is a pair, the quote and
// the page it was quoted from, and the pair fails together.
const docsHtml = read('frontend/docs.html');
const helpHtml = read('frontend/help/index.html');
const securityHtml = read('frontend/security.html');
const developerHtml = read('frontend/developer.html');

// /docs is where an evaluating buyer sends their IT, and it must say so before
// it starts talking about pip install. It absorbed traffic that belonged on
// /pricing, so it also has to name the price boundary of the API once.
assert.match(docsHtml, /Your IT can check everything here/,
  'docs.html must open with the line that tells a buyer what this page is for');
assert.match(docsHtml, /The ParaSign API is available from ParaSign Pro/,
  'docs.html must state which plan the ParaSign API needs');
assert.match(developerHtml, /API access is included from ParaSign Pro/,
  'developer.html must state which plan the ParaSign API needs');
// Both of those are only true while /pricing sells API access on ParaSign Pro.
assert.match(pricing, /Unlimited transfers - API access/,
  'pricing.html must still list API access on the ParaSign Pro tier');

// Answer 1: signing without an account. Quoted from /sign, which is pinned above.
assert.match(helpHtml, /Signing a document needs an account/i,
  'help/index.html must answer whether an account is required');
assert.match(helpHtml, /open a signing request someone sent you/i,
  'help/index.html must say what an invited signer can do without an account');
assert.match(signHtml, /Free accounts sign 2 documents a month/i,
  'sign.html is the source of the free signing limit quoted on /help');
assert.match(helpHtml, /free accounts sign 2 documents a month/i,
  'help/index.html must answer what the free tier gives');

// Answer 2: cost. The sentence the whole free-versus-paid split rests on. If the
// pricing model ever gates cryptography behind a tier, this is what fails first.
assert.match(pricing, /Pay for volume, never for security/,
  'pricing.html must keep the sentence the free-versus-paid split rests on');
assert.match(helpHtml, /Pay for volume, never for security/,
  'help/index.html must quote the pricing promise, not paraphrase it');

// Answer 3: where the data lives. Quoted from the Jurisdiction and privacy table
// on /security, word for word, and never broadened past what that table says.
assert.match(securityHtml, /Hetzner Nuremberg, Germany/,
  'security.html must keep the server location row');
assert.match(securityHtml, /Not applicable: no US infrastructure, no US company/,
  'security.html must keep the CLOUD Act row');
assert.match(helpHtml, /Hetzner Nuremberg, Germany/,
  'help/index.html must answer where the data lives');
assert.match(helpHtml, /Not applicable: no US infrastructure, no US company/,
  'help/index.html must quote the CLOUD Act row exactly');

// No sales voice on a support page. Someone here has already signed up.
assert.doesNotMatch(helpHtml, /revolutionary|seamless|cutting-edge|enterprise-grade|military-grade|trusted by|world-class/i,
  'help/index.html must stay in support voice');

console.log('ui-truthfulness: /docs and /help answer a buyer with sentences that ship elsewhere');
